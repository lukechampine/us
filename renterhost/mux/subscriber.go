package mux

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"gitlab.com/NebulousLabs/encoding"
)

type (
	SubscriberHandler func(subscriber string, stream *Stream)

	SubscriberMux struct {
		mux *Mux
	}

	SubscriberRouter struct {
		key   ed25519.PrivateKey
		appID uint64

		mu       sync.RWMutex
		handlers map[string]SubscriberHandler
	}
)

var (
	ErrUnknownSubscriber = errors.New("unknown subscriber")
)

func (sm *SubscriberMux) Close() error {
	return sm.mux.Close()
}

// NewStream creates a new Stream that subscribes to the specified
// handler on the peer.
func (sm *SubscriberMux) NewStream(subscriber string) (*Stream, error) {
	s, err := sm.mux.NewStream()
	if err != nil {
		return nil, fmt.Errorf("failed to create new stream: %w", err)
	}

	// lazy write the subscriber
	var buf = make([]byte, 16+len(subscriber))
	binary.LittleEndian.PutUint64(buf, uint64(8+len(subscriber)))
	binary.LittleEndian.PutUint64(buf[8:], uint64(len(subscriber)))
	copy(buf[16:], subscriber)
	s.lazyWrite(buf)

	// lock the stream to prevent reads until the subscriber handshake is
	// complete. The subscriber handshake must happen asynchronously for
	// compatibility with siad.
	er := s.exclusiveReader()
	go func() {
		defer er.Close()

		// helper to pass a returned error up the stack
		setErr := func(err error) {
			s.cond.L.Lock()
			defer s.cond.L.Unlock()
			if s.err == nil {
				s.err = err
			}
			s.cond.Broadcast()
		}

		// read the response from the exclusive reader. The response is a uint64
		//indicating the response's total length, followed by another uint64
		// indicating the message string length, then the actual message string.
		// For success the response message should be empty.
		lr := io.LimitReader(er, 1024)
		responseLen := make([]byte, 8)
		if _, err := io.ReadFull(lr, responseLen); err != nil {
			setErr(fmt.Errorf("failed to read response length: %w", err))
			return
		}
		n := binary.LittleEndian.Uint64(responseLen)
		if n > 1024 {
			setErr(fmt.Errorf("response message too large: %d", n))
			return
		}
		response := make([]byte, n)
		if _, err := io.ReadFull(lr, response); err != nil {
			setErr(fmt.Errorf("failed to read response: %w", err))
			return
		} else if len(response) != 8 {
			switch s := string(response[8:]); s {
			case "unknown subscriber":
				err = ErrUnknownSubscriber
			default:
				err = errors.New(s)
			}
			setErr(fmt.Errorf("failed to subscribe: %w", err))
			return
		}
	}()

	return s, nil
}

func (r *SubscriberRouter) RegisterSubscriber(subscriber string, fn SubscriberHandler) {
	r.mu.Lock()
	r.handlers[subscriber] = fn
	r.mu.Unlock()
}

func (r *SubscriberRouter) UnregisterSubscriber(subscriber string) {
	r.mu.Lock()
	delete(r.handlers, subscriber)
	r.mu.Unlock()
}

func (r *SubscriberRouter) route(m *Mux) (err error) {
	stream, err := m.AcceptStream()
	if err != nil {
		return fmt.Errorf("failed to accept stream: %w", err)
	}
	defer func() {
		if err != nil {
			stream.Close()
		}
	}()

	// subscriber should be the first bytes read on the stream
	var subscriber string
	if err = encoding.ReadObject(stream, &subscriber, 4096); err != nil {
		return fmt.Errorf("failed to read subscriber: %w", err)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	handler, exists := r.handlers[subscriber]
	if !exists {
		encoding.WriteObject(stream, "unknown subscriber")
		return fmt.Errorf("failed to route stream: %w", ErrUnknownSubscriber)
	}

	// send an empty error response to indicate success
	stream.lazyWrite([]byte{0: 8, 15: 0})

	go func() {
		handler(subscriber, stream)
		stream.Close()
	}()
	return nil
}

// Upgrade the connection to a mux connection and route new streams
// to the proper subscriber.
func (r *SubscriberRouter) Upgrade(conn net.Conn) error {
	// upgrade to a mux connection
	m, err := Accept(conn, r.key)
	if err != nil {
		return fmt.Errorf("failed to upgrade connection: %w", err)
	}

	// first stream handles the app seed handshake
	stream, err := m.AcceptStream()
	if err != nil {
		return fmt.Errorf("failed to accept stream: %w", err)
	}
	defer stream.Close()

	var peerSeed uint64
	if err := encoding.ReadObject(stream, &peerSeed, 4096); err != nil {
		return fmt.Errorf("failed to read peer seed: %w", err)
	}

	if err := encoding.WriteObject(stream, r.appID); err != nil {
		return fmt.Errorf("failed to write app seed: %w", err)
	}

	for {
		err := r.route(m)
		if errors.Is(err, ErrClosedConn) || errors.Is(err, ErrPeerClosedConn) {
			return nil
		}
	}
}

// DialSubscriber iniates the mux and app handshakes on the connection.
func DialSubscriber(conn net.Conn, appSeed uint64, theirKey ed25519.PublicKey) (sm *SubscriberMux, err error) {
	m, err := Dial(conn, theirKey)
	if err != nil {
		return nil, fmt.Errorf("failed to upgrade: %w", err)
	}

	s, err := m.NewStream()
	if err != nil {
		return nil, fmt.Errorf("failed to create app seed stream: %w", err)
	}
	defer s.Close()

	if err := encoding.WriteObject(s, appSeed); err != nil {
		return nil, fmt.Errorf("failed to write app seed: %w", err)
	}

	var peerSeed uint64
	if err := encoding.ReadObject(s, &peerSeed, 4096); err != nil {
		return nil, fmt.Errorf("failed to read peer seed: %w", err)
	}

	return &SubscriberMux{m}, nil
}

func NewSubscriberRouter(appID uint64, key ed25519.PrivateKey) *SubscriberRouter {
	return &SubscriberRouter{
		appID:    appID,
		key:      key,
		handlers: make(map[string]SubscriberHandler),
	}
}
