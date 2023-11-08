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

	// all subsequent fields are guarded by mu
	mu      sync.Mutex
	cond    sync.Cond
	streams map[uint32]*Stream
	nextID  uint32
	err     error // sticky and fatal
	write   struct {
		header   frameHeader
		payload  []byte
		timedOut bool
		cond     sync.Cond // separate cond for waking a single bufferFrame
	}
}

// setErr sets the Mux error and wakes up all Mux-related goroutines. If m.err
// is already set, setErr is a no-op.
func (m *Mux) setErr(err error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
	m.write.cond.Broadcast()
	return err
}

// bufferFrame blocks until it can store its frame in the m.write struct. It
// returns early with an error if m.err is set or if the deadline expires.
func (m *Mux) bufferFrame(h frameHeader, payload []byte, deadline time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !deadline.IsZero() {
		if !time.Now().Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		timer := time.AfterFunc(time.Until(deadline), m.write.cond.Broadcast) // nice
		defer timer.Stop()
	}
	// wait for current frame to be consumed
	for m.write.header.id != 0 && m.err == nil && (deadline.IsZero() || time.Now().Before(deadline)) {
		m.write.cond.Wait()
	}
	if m.err != nil {
		return m.err
	} else if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	// queue our frame and wake the writeLoop
	//
	// NOTE: it is not necessary to wait for the writeLoop to flush our frame. A
	// successful write() syscall doesn't mean that the peer actually received
	// the data, just that the packets are sitting in a kernel buffer somewhere.
	m.write.header = h
	m.write.payload = payload
	m.cond.Broadcast()
	return nil
}

// writeLoop handles the actual Writes to the Mux's net.Conn. It waits for a
// bufferFrame call to fill the m.write buffer, then Writes the frame and wakes
// up the next bufferFrame call (if any). It also handles keepalives.
func (m *Mux) writeLoop() {
	// wake cond whenever a keepalive is due
	//
	// NOTE: we send a keepalive when 75% of the MaxTimeout has elapsed
	keepaliveInterval := m.settings.MaxTimeout - m.settings.MaxTimeout/4
	nextKeepalive := time.Now().Add(keepaliveInterval)
	timer := time.AfterFunc(keepaliveInterval, m.cond.Broadcast)
	defer timer.Stop()

	writeBuf := make([]byte, m.settings.maxFrameSize())
	for {
		// wait for a frame
		m.mu.Lock()
		for m.write.header.id == 0 && m.err == nil && time.Now().Before(nextKeepalive) {
			m.cond.Wait()
		}
		if m.err != nil {
			m.mu.Unlock()
			return
		}
		// if we have a normal frame, use that; otherwise, send a keepalive
		//
		// NOTE: even if we were woken by the keepalive timer, there might be a
		// normal frame ready to send, in which case we don't need a keepalive
		h, payload := m.write.header, m.write.payload
		if h.id == 0 {
			h, payload = frameHeader{id: idKeepalive}, nil
		}
		frame := encryptFrame(writeBuf, h, payload, m.settings.RequestedPacketSize, m.aead)
		m.mu.Unlock()

		// reset keepalive timer
		timer.Stop()
		timer.Reset(keepaliveInterval)
		nextKeepalive = time.Now().Add(keepaliveInterval)

		// write the frame
		if _, err := m.conn.Write(frame); err != nil {
			m.setErr(err)
			return
		}

		// clear the payload and wake at most one bufferFrame call
		m.mu.Lock()
		m.write.header = frameHeader{}
		m.write.payload = nil
		m.write.cond.Signal()
		m.mu.Unlock()
	}
}

// readLoop handles the actual Reads from the Mux's net.Conn. It waits for a
// frame to arrive, then routes it to the appropriate Stream, creating a new
// Stream if none exists. It then waits for the frame to be fully consumed by
// the Stream before attempting to Read again.
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
				m.mu.Lock()
				if curStream = m.streams[h.id]; curStream == nil {
					// no existing stream with this ID; create a new one
					curStream = &Stream{
						m:        m,
						id:       h.id,
						accepted: false,
						cond:     sync.Cond{L: new(sync.Mutex)},
					}
					m.streams[h.id] = curStream
					m.cond.Broadcast() // wake (*Mux).AcceptStream
				}
				m.mu.Unlock()
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
	m.mu.Lock()
	defer m.mu.Unlock()
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

// NewStream creates a new Stream. The peer will not be aware of the new Stream
// until Write is called.
func (m *Mux) NewStream() (*Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	s := &Stream{
		m:        m,
		accepted: true,
		cond:     sync.Cond{L: new(sync.Mutex)},
	}
	// loop until we find an unused ID
	//
	// NOTE: this implementation uses alternating IDs for the Dialer and
	// Accepter to avoid collisions, but other implementations simply choose the
	// ID at random; thus, we always have to check for collisions.
	for m.streams[m.nextID] != nil {
		m.nextID += 2
	}
	s.id = m.nextID
	m.nextID += 2
	m.streams[s.id] = s
	return s, nil
}

// newMux initializes a Mux and spawns its readLoop and writeLoop goroutines.
func newMux(conn net.Conn, aead cipher.AEAD, settings connSettings) *Mux {
	m := &Mux{
		conn:     conn,
		aead:     aead,
		settings: settings,
		streams:  make(map[uint32]*Stream),
		nextID:   1 << 8, // avoid collisions with reserved IDs
	}
	// both conds use the same mutex
	m.cond.L = &m.mu
	m.write.cond.L = &m.mu
	go m.readLoop()
	go m.writeLoop()
	return m
}

// Dial initiates a mux protocol handshake on the provided conn.
func Dial(conn net.Conn, theirKey ed25519.PublicKey) (*Mux, error) {
	if err := initiateVersionHandshake(conn); err != nil {
		return nil, fmt.Errorf("version handshake failed: %w", err)
	}
	aead, err := initiateEncryptionHandshake(conn, theirKey)
	if err != nil {
		return nil, fmt.Errorf("encryption handshake failed: %w", err)
	}

	// the siad implementation determines the initial packet size for the handshake
	// based on the connection's IP address instead of hardcoding it.
	ours := defaultConnSettings
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, fmt.Errorf("could not parse remote address: %w", err)
	} else if net.ParseIP(host).To4() != nil {
		ours.RequestedPacketSize = 1460 // IPv4 MTU
	}

	settings, err := initiateSettingsHandshake(conn, ours, aead)
	if err != nil {
		return nil, fmt.Errorf("settings handshake failed: %w", err)
	}
	return newMux(conn, aead, settings), nil
}

// Accept reciprocates a mux protocol handshake on the provided conn.
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

	cond    sync.Cond // guards + synchronizes subsequent fields
	err     error
	readBuf []byte
	rd, wd  time.Time // deadlines

	// SiaMux handles the subscriber handshake asynchronously, it is expected
	// that writes to the peer will continue uninterupted before the handshake
	// is complete. The subscriber must be prependend to the first call to
	// Write(), but the response may not be sent until future calls to Write()
	// have completed. This means the response must be read from the read buffer
	// before other calls to Read() can complete.
	writeMu  sync.Mutex // guards the lazy write buffer
	writeBuf []byte
	// guards calls to Read(). Calls to Read() should take an RLock on the mutex.
	// Calling exclusiveReader() should takes a WLock to prevent other calls
	// to Read() while the exclusive reader is open. A mutex benchmarked better
	// than the channel that the existing siamux uses.
	readMu sync.RWMutex
}

// LocalAddr returns the underlying connection's LocalAddr.
func (s *Stream) LocalAddr() net.Addr { return s.m.conn.LocalAddr() }

// RemoteAddr returns the underlying connection's RemoteAddr.
func (s *Stream) RemoteAddr() net.Addr { return s.m.conn.RemoteAddr() }

// SetDeadline sets the read and write deadlines associated with the Stream. It
// is equivalent to calling both SetReadDeadline and SetWriteDeadline.
//
// This implementation does not entirely conform to the net.Conn interface:
// setting a new deadline does not affect pending Read or Write calls, only
// future calls.
func (s *Stream) SetDeadline(t time.Time) error {
	s.SetReadDeadline(t)
	s.SetWriteDeadline(t)
	return nil
}

// SetReadDeadline sets the read deadline associated with the Stream.
//
// This implementation does not entirely conform to the net.Conn interface:
// setting a new deadline does not affect pending Read calls, only future calls.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	s.rd = t
	return nil
}

// SetWriteDeadline sets the write deadline associated with the Stream.
//
// This implementation does not entirely conform to the net.Conn interface:
// setting a new deadline does not affect pending Write calls, only future
// calls.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	s.wd = t
	return nil
}

// consumeFrame stores a frame in s.read and waits for it to be consumed by
// (*Stream).read calls.
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
		s.cond.Broadcast() // wake Read
		return
	} else if len(payload) == 0 {
		return
	}
	// set payload and wait for it to be consumed
	s.readBuf = payload
	s.cond.Broadcast() // wake Read
	for len(s.readBuf) != 0 && s.err == nil {
		s.cond.Wait()
	}
}

// read reads data from the Stream.
func (s *Stream) read(p []byte) (int, error) {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	if !s.rd.IsZero() {
		if !time.Now().Before(s.rd) {
			return 0, os.ErrDeadlineExceeded
		}
		timer := time.AfterFunc(time.Until(s.rd), s.cond.Broadcast)
		defer timer.Stop()
	}
	for len(s.readBuf) == 0 && s.err == nil && (s.rd.IsZero() || time.Now().Before(s.rd)) {
		s.cond.Wait()
	}
	if s.err != nil {
		return 0, s.err
	} else if !s.rd.IsZero() && !time.Now().Before(s.rd) {
		return 0, os.ErrDeadlineExceeded
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	s.cond.Broadcast() // wake consumeFrame
	return n, s.err
}

// Write writes data to the Stream.
func (s *Stream) write(p []byte) (int, error) {
	buf := bytes.NewBuffer(p)
	for buf.Len() > 0 {
		// check for error
		s.cond.L.Lock()
		err := s.err
		s.cond.L.Unlock()
		if err != nil {
			return len(p) - buf.Len(), err
		}
		// write next frame's worth of data
		payload := buf.Next(s.m.settings.maxPayloadSize())
		h := frameHeader{id: s.id, length: uint32(len(payload))}
		if err := s.m.bufferFrame(h, payload, s.wd); err != nil {
			return len(p) - buf.Len(), err
		}
	}
	return len(p), nil
}

// lazyWrite prepends data to the next frame written to the stream.
func (s *Stream) lazyWrite(p []byte) {
	s.writeMu.Lock()
	s.writeBuf = append(s.writeBuf, p...)
	s.writeMu.Unlock()
}

// Read reads data from the Stream.
func (s *Stream) Read(p []byte) (int, error) {
	s.readMu.RLock()
	defer s.readMu.RUnlock()
	return s.read(p)
}

// Write writes data to the Stream.
func (s *Stream) Write(p []byte) (n int, err error) {
	s.writeMu.Lock()
	var m int
	if len(s.writeBuf) != 0 {
		m = len(s.writeBuf)
		p = append(s.writeBuf, p...)
		s.writeBuf = nil
	}
	s.writeMu.Unlock()
	n, err = s.write(p)
	if n >= m {
		n -= m
	}
	return
}

// exclusiveReader returns a reader with exclusive access to the stream's read
// buffer. Direct reads from the stream are blocked until the returned reader
// is closed.
func (s *Stream) exclusiveReader() io.ReadCloser {
	s.readMu.Lock()
	return &exclusiveReader{s: s}
}

// Close closes the Stream. The underlying connection is not closed.
func (s *Stream) Close() error {
	h := frameHeader{
		id:    s.id,
		flags: flagFinal,
	}
	err := s.m.bufferFrame(h, nil, s.wd)
	if errors.Is(err, ErrPeerClosedStream) {
		err = nil
	}

	// cancel outstanding Read/Write calls
	//
	// NOTE: Read calls will be interrupted immediately, but Write calls will
	// finish sending their current frame before seeing the error. This is ok:
	// the peer will discard any of this Stream's frames that arrive after the
	// flagFinal frame.
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	s.err = ErrClosedStream
	s.cond.Broadcast()
	return err
}

// exclusiveReader is a reader that provides exclusive read access to a stream's
// underlying read buffer. Any other calls to Read() on the underlying stream
// will be blocked until the exclusive reader is closed.
type exclusiveReader struct {
	s      *Stream
	closed bool
}

// Read reads data from the underlying stream. Implements io.Reader.
func (r *exclusiveReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, ErrClosedStream
	}
	return r.s.read(p)
}

// Close closes the reader and unlocks the underlying stream. The underlying
// stream is not closed.
func (r *exclusiveReader) Close() error {
	r.closed = true
	r.s.readMu.Unlock()
	return nil
}

var _ net.Conn = (*Stream)(nil)
