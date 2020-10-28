package mux

import (
	"bytes"
	"crypto/cipher"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// Errors relating to stream or mux shutdown.
var (
	ErrClosedConn       = errors.New("underlying connection was closed")
	ErrClosedStream     = errors.New("stream was gracefully closed")
	ErrPeerClosedStream = errors.New("peer closed stream gracefully")
	ErrPeerClosedConn   = errors.New("peer closed underlying connection")
)

// A Mux multiplexes multiple duplex Streams onto a single net.Conn.
type Mux struct {
	conn     net.Conn
	aead     cipher.AEAD
	settings connSettings

	cond    sync.Cond // guards + synchronizes subsequent fields
	streams map[uint32]*Stream
	nextID  uint32
	err     error // sticky and fatal

	// fields relating to the pending Write
	write struct {
		header   frameHeader
		payload  []byte
		timedOut bool
	}
}

func (m *Mux) setErr(err error) error {
	m.cond.L.Lock()
	defer m.cond.L.Unlock()
	if m.err != nil {
		return m.err
	}

	// try to detect when the peer closed the connection
	if errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.EPROTOTYPE) {
		err = ErrPeerClosedConn
	}

	// set sticky error, close conn, and wake everyone up
	m.err = err
	for _, s := range m.streams {
		s.cond.L.Lock()
		s.err = err
		s.cond.Broadcast()
		s.cond.L.Unlock()
	}
	m.conn.Close()
	m.cond.Broadcast()
	return err
}

func (m *Mux) consumeFrame(h frameHeader, payload []byte, deadline time.Time) error {
	m.cond.L.Lock()
	defer m.cond.L.Unlock()
	m.write.timedOut = false
	if !deadline.IsZero() {
		if !time.Now().Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		timer := time.AfterFunc(time.Until(deadline), func() {
			m.cond.L.Lock()
			m.write.timedOut = true
			m.cond.Broadcast()
			m.cond.L.Unlock()
		})
		defer timer.Stop()
	}

	// wait for current frame to be consumed
	for m.write.header.id != 0 && m.err == nil && !m.write.timedOut {
		m.cond.Wait()
	}
	if m.err != nil {
		return m.err
	} else if m.write.timedOut {
		return os.ErrDeadlineExceeded
	}
	// queue our frame and wake the writeLoop
	//
	// NOTE: it is not necessary to wait for the actual Write call to complete.
	// A successful write() syscall doesn't mean that the peer actually received
	// the data; just that the packets are sitting in a kernel buffer somewhere.
	// Likewise, (*Stream).Write can return as soon as its frames are buffered.
	m.write.header = h
	m.write.payload = payload
	m.cond.Broadcast()
	return nil
}

func (m *Mux) writeLoop() {
	// wake cond whenever a keepalive is due
	//
	// NOTE: we send a keepalive when 75% of the MaxTimeout has elapsed
	keepaliveInterval := m.settings.MaxTimeout - m.settings.MaxTimeout/4
	nextKeepalive := time.Now().Add(keepaliveInterval)
	timer := time.AfterFunc(keepaliveInterval, m.cond.Broadcast) // nice
	defer timer.Stop()

	writeBuf := make([]byte, m.settings.maxFrameSize())
	for {
		// wait for a frame
		m.cond.L.Lock()
		for m.write.header.id == 0 && m.err == nil && time.Now().Before(nextKeepalive) {
			m.cond.Wait()
		}
		if m.err != nil {
			m.cond.L.Unlock()
			return
		}
		// if we have a normal frame, send that; otherwise, send a keepalive
		h, payload := m.write.header, m.write.payload
		if h.id == 0 {
			h, payload = frameHeader{id: idKeepalive}, nil
		}
		frame := encryptFrame(writeBuf, h, payload, m.settings.RequestedPacketSize, m.aead)
		m.cond.L.Unlock()

		// reset keepalive
		timer.Stop()
		timer.Reset(keepaliveInterval)
		nextKeepalive = time.Now().Add(keepaliveInterval)

		// write the frame
		if _, err := m.conn.Write(frame); err != nil {
			m.setErr(err)
			return
		}

		// clear the payload and wake (*Mux).consumeFrame
		m.cond.L.Lock()
		m.write.header = frameHeader{}
		m.write.payload = nil
		m.cond.Broadcast()
		m.cond.L.Unlock()
	}
}

func (m *Mux) readLoop() {
	var curStream *Stream // saves a lock acquisition + map lookup in the common case
	buf := make([]byte, m.settings.maxFrameSize())
	for {
		h, payload, err := readEncryptedFrame(m.conn, buf, m.settings.RequestedPacketSize, m.aead)
		if err != nil {
			m.setErr(err)
			return
		}
		switch h.id {
		case idErrorBadInit, idEstablishEncryption, idUpdateSettings:
			// peer is behaving weirdly; after initialization, we shouldn't
			// receive any of these IDs
			m.setErr(errors.New("peer sent invalid frame ID"))
			return
		case idKeepalive:
			continue // no action required
		default:
			// look for matching Stream
			if curStream == nil || h.id != curStream.id {
				m.cond.L.Lock()
				if curStream = m.streams[h.id]; curStream == nil {
					// no existing stream with this ID; create a new one
					curStream = &Stream{
						m:    m,
						id:   h.id,
						cond: sync.Cond{L: new(sync.Mutex)},
					}
					m.streams[h.id] = curStream
					m.cond.Broadcast() // wake (*Mux).AcceptStream
				}
				m.cond.L.Unlock()
			}
			curStream.consumeFrame(h, payload)
		}
	}
}

// Close closes the underlying net.Conn.
func (m *Mux) Close() error {
	err := m.setErr(ErrClosedConn)
	if err == ErrClosedConn || err == ErrPeerClosedConn {
		err = nil
	}
	return err
}

// AcceptStream waits for and returns the next peer-initiated Stream.
func (m *Mux) AcceptStream() (*Stream, error) {
	m.cond.L.Lock()
	defer m.cond.L.Unlock()
	for {
		if m.err != nil {
			return nil, m.err
		}
		for _, s := range m.streams {
			if !s.accepted {
				s.accepted = true
				return s, nil
			}
		}
		m.cond.Wait()
	}
}

// DialStream creates a new Stream.
func (m *Mux) DialStream() (*Stream, error) {
	m.cond.L.Lock()
	defer m.cond.L.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	s := &Stream{
		m:    m,
		cond: sync.Cond{L: new(sync.Mutex)},
	}
	// loop until we find an unused ID
	//
	// NOTE: this implementation use alternating IDs for the Dialer and Accepter
	// to avoid collisions, but other implementations simply choose the ID at
	// random; thus, we always have to check for collisions.
again:
	m.nextID += 2
	if _, ok := m.streams[m.nextID]; ok {
		goto again
	}
	s.id = m.nextID
	m.streams[s.id] = s
	return s, nil
}

func newMux(conn net.Conn, aead cipher.AEAD, settings connSettings) *Mux {
	m := &Mux{
		conn:     conn,
		aead:     aead,
		settings: settings,
		cond:     sync.Cond{L: new(sync.Mutex)},
		streams:  make(map[uint32]*Stream),
		nextID:   1 << 8, // avoid collisions with reserved IDs
	}
	go m.readLoop()
	go m.writeLoop()
	return m
}

var ourVersion = []byte{1}

var defaultConnSettings = connSettings{
	RequestedPacketSize: 1440, // IPv6 MTU
	MaxFrameSizePackets: 10,
	MaxTimeout:          20 * time.Minute,
}

// Dial initiates the multiplexer protocol handshake on the provided conn.
func Dial(conn net.Conn, theirKey ed25519.PublicKey) (*Mux, error) {
	if err := initiateVersionHandshake(conn); err != nil {
		return nil, fmt.Errorf("version handshake failed: %w", err)
	}
	aead, err := initiateEncryptionHandshake(conn, theirKey)
	if err != nil {
		return nil, fmt.Errorf("encryption handshake failed: %w", err)
	}
	settings, err := initiateSettingsHandshake(conn, defaultConnSettings, aead)
	if err != nil {
		return nil, fmt.Errorf("settings handshake failed: %w", err)
	}
	return newMux(conn, aead, settings), nil
}

// Accept reciprocates a multiplexer protocol handshake on the provided conn.
func Accept(conn net.Conn, ourKey ed25519.PrivateKey) (*Mux, error) {
	if err := acceptVersionHandshake(conn); err != nil {
		return nil, fmt.Errorf("version handshake failed: %w", err)
	}
	aead, err := acceptEncryptionHandshake(conn, ourKey)
	if err != nil {
		return nil, fmt.Errorf("encryption handshake failed: %w", err)
	}
	settings, err := acceptSettingsHandshake(conn, defaultConnSettings, aead)
	if err != nil {
		return nil, fmt.Errorf("settings handshake failed: %w", err)
	}
	m := newMux(conn, aead, settings)
	m.nextID++ // avoid collisions with Dialing peer
	return m, nil
}

// A Stream is a duplex connection multiplexed over a net.Conn. It implements
// the net.Conn interface.
type Stream struct {
	m        *Mux
	id       uint32
	accepted bool

	cond sync.Cond // guards + synchronizes subsequent fields
	read struct {
		payload  []byte
		timedOut bool
	}
	err    error
	rd, wd time.Time // deadlines
}

// LocalAddr returns the underlying connection's LocalAddr.
func (s *Stream) LocalAddr() net.Addr { return s.m.conn.LocalAddr() }

// RemoteAddr returns the underlying connection's RemoteAddr.
func (s *Stream) RemoteAddr() net.Addr { return s.m.conn.RemoteAddr() }

// SetDeadline sets the read and write deadlines associated with the Stream. It
// is equivalent to calling both SetReadDeadline and SetWriteDeadline.
//
// This implementation does not entirely conform to the net.Conn interface.
// Specifically, setting a new deadline does not affect pending Read or Write
// calls, only future calls.
func (s *Stream) SetDeadline(t time.Time) error {
	s.SetReadDeadline(t)
	s.SetWriteDeadline(t)
	return nil
}

// SetReadDeadline sets the read deadline associated with the Stream.
//
// This implementation does not entirely conform to the net.Conn interface.
// Specifically, setting a new deadline does not affect pending Read calls, only
// future calls.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	s.rd = t
	return nil
}

// SetWriteDeadline sets the write deadline associated with the Stream.
//
// This implementation does not entirely conform to the net.Conn interface.
// Specifically, setting a new deadline does not affect pending Write calls,
// only future calls.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	s.wd = t
	return nil
}

func (s *Stream) consumeFrame(h frameHeader, payload []byte) {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	if s.err != nil {
		return
	}
	// handle final/error frame
	if h.flags&flagFinal != 0 {
		err := ErrPeerClosedStream
		if h.flags&flagError != 0 {
			err = errors.New(string(payload))
		}
		s.err = err
		s.cond.Broadcast() // wake (*Stream).Read
		return
	} else if len(payload) == 0 {
		return
	}
	// set payload and wait for it to be consumed
	s.read.payload = payload
	s.cond.Broadcast() // wake (*Stream).Read
	for len(s.read.payload) != 0 && s.err == nil && !s.read.timedOut {
		s.cond.Wait()
	}
}

// Read reads data from the Stream.
func (s *Stream) Read(p []byte) (int, error) {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	s.read.timedOut = false
	if !s.rd.IsZero() {
		if !time.Now().Before(s.rd) {
			return 0, os.ErrDeadlineExceeded
		}
		timer := time.AfterFunc(time.Until(s.rd), func() {
			s.cond.L.Lock()
			s.read.timedOut = true
			s.cond.Broadcast()
			s.cond.L.Unlock()
		})
		defer timer.Stop()
	}

	for len(s.read.payload) == 0 && s.err == nil && !s.read.timedOut {
		s.cond.Wait()
	}
	n := copy(p, s.read.payload)
	s.read.payload = s.read.payload[n:]
	s.cond.Broadcast() // wake (*Stream).consumeFrame
	if s.read.timedOut {
		return n, os.ErrDeadlineExceeded
	}
	return n, s.err
}

// Write writes data to the Stream.
func (s *Stream) Write(p []byte) (int, error) {
	h := frameHeader{id: s.id}
	buf := bytes.NewBuffer(p)
	for buf.Len() > 0 {
		payload := buf.Next(s.m.settings.maxPayloadSize())
		h.length = uint32(len(payload))
		if err := s.m.consumeFrame(h, payload, s.wd); err != nil {
			return len(p) - buf.Len(), err
		}
	}
	return len(p), nil
}

// Close closes the Stream. The underlying connection is not closed.
func (s *Stream) Close() error {
	h := frameHeader{
		id:    s.id,
		flags: flagFinal,
	}
	err := s.m.consumeFrame(h, nil, s.wd)
	if err == ErrPeerClosedStream {
		err = nil
	}

	// cancel outstanding Read/Write calls
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	s.err = ErrClosedStream
	s.cond.Broadcast()
	return err
}

var _ net.Conn = (*Stream)(nil)
