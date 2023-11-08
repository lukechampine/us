package mux

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"gitlab.com/NebulousLabs/encoding"
	"gitlab.com/NebulousLabs/log"
	"gitlab.com/NebulousLabs/siamux"
	"gitlab.com/NebulousLabs/siamux/mux"
	"lukechampine.com/frand"
)

func startEchoSubscriber(l net.Listener, priv ed25519.PrivateKey) {
	router := NewSubscriberRouter(8000, priv)

	// simple echo handler
	router.RegisterSubscriber("echo", func(subscriber string, stream *Stream) {
		var buf []byte
		if err := encoding.ReadObject(stream, &buf, 1024); err != nil {
			panic(fmt.Errorf("failed to read object from stream: %w", err))
		}

		if err := encoding.WriteObject(stream, buf); err != nil {
			panic(fmt.Errorf("failed to write object to stream: %w", err))
		}
	})

	// spawn a goroutine to accept connections and upgrade them
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				continue
			}

			if err := router.Upgrade(conn); err != nil {
				continue
			}
		}
	}()
}

func TestSubscriberRouter(t *testing.T) {
	serverKey := ed25519.NewKeyFromSeed(frand.Bytes(ed25519.SeedSize))

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal("failed to listen:", err)
	}
	defer listener.Close()
	startEchoSubscriber(listener, serverKey)

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal("failed to dial:", err)
	}
	defer conn.Close()

	m, err := DialSubscriber(conn, 8000, serverKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal("failed to upgrade:", err)
	}
	defer m.Close()

	t.Run("test bad subscriber", func(t *testing.T) {
		// Due to the laziness expected by siad, we cannot detect the unknown
		// subscriber error as part of the handshake. We have to first write
		// to then read from the stream.
		s, err := m.NewStream("bad subscriber")
		if err != nil {
			t.Fatal("failed to initiate stream:", err)
		}
		defer s.Close()

		if err := encoding.WriteObject(s, []byte("hello")); err != nil {
			t.Fatal("failed to write to stream:", err)
		}

		if err := encoding.ReadObject(s, new([]byte), 1024); err == nil {
			t.Fatal("expected subscriber error:", err)
		}
	})

	t.Run("test good subscriber", func(t *testing.T) {
		s, err := m.NewStream("echo")
		if err != nil {
			t.Fatal("failed to create subscriber stream:", err)
		}
		defer s.Close()

		req := frand.Bytes(128)
		if err := encoding.WriteObject(s, req); err != nil {
			t.Fatal("failed to write object to stream:", err)
		}

		var resp []byte
		if err := encoding.ReadObject(s, &resp, 1024); err != nil {
			t.Fatal("failed to read subscriber reply:", err)
		}

		if !bytes.Equal(req, resp) {
			t.Fatalf("unexpected reply: got %v expected %v", resp, req)
		}
	})
}

func TestSubscriberConcurrency(t *testing.T) {
	serverKey := ed25519.NewKeyFromSeed(frand.Bytes(32))

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal("failed to listen:", err)
	}
	defer listener.Close()
	startEchoSubscriber(listener, serverKey)

	var connWG sync.WaitGroup
	concurrentConnections := 10
	concurrentStreams := 500
	errs := make(chan error, concurrentConnections*concurrentStreams)
	connWG.Add(concurrentConnections)

	connect := func(i int) {
		defer connWG.Done()
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			panic(fmt.Errorf("failed to dial %v: %w", i, err))
		}
		defer conn.Close()

		m, err := DialSubscriber(conn, 5751, serverKey.Public().(ed25519.PublicKey))
		if err != nil {
			panic(fmt.Errorf("failed to upgrade %v: %w", i, err))
		}
		defer m.Close()

		var wg sync.WaitGroup
		wg.Add(concurrentStreams)

		for j := 0; j < concurrentStreams; j++ {
			go func(connID, streamID int) {
				defer wg.Done()

				s, err := m.NewStream("echo")
				if err != nil {
					errs <- fmt.Errorf("failed to create subscriber stream %v%v: %w", connID, streamID, err)
					return
				}
				defer s.Close()

				req := frand.Bytes(128)
				if err := encoding.WriteObject(s, req); err != nil {
					errs <- fmt.Errorf("failed to write object to stream %v%v: %w", connID, streamID, err)
					return
				}

				var resp []byte
				if err := encoding.ReadObject(s, &resp, 1024); err != nil {
					errs <- fmt.Errorf("failed to read subscriber reply %v%v: %w", connID, streamID, err)
					return
				}

				if !bytes.Equal(req, resp) {
					errs <- fmt.Errorf("unexpected reply %v%v: got %v expected %v", connID, streamID, resp, req)
				}

				errs <- nil
			}(i, j)
		}
		wg.Wait()
	}

	for i := 0; i < concurrentConnections; i++ {
		go connect(i)
	}

	connWG.Wait()
	close(errs)
	var errored bool
	for err := range errs {
		if err != nil {
			t.Log(err)
			errored = true
		}
	}

	if errored {
		t.FailNow()
	}
}

func TestSubscriberRouterCompat(t *testing.T) {
	dir := t.TempDir()

	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal("failed to create listener:", err)
	}
	defer l.Close()

	serverKey := ed25519.NewKeyFromSeed(frand.Bytes(32))
	startEchoSubscriber(l, serverKey)

	m, err := siamux.New(":0", ":0", log.DiscardLogger, filepath.Join(dir, "siamux"))
	if err != nil {
		t.Fatal("failed to create sia mux:", err)
	}
	defer m.Close()

	var key mux.ED25519PublicKey
	copy(key[:], serverKey.Public().(ed25519.PublicKey)[:])

	t.Run("bad subscriber", func(t *testing.T) {
		s, err := m.NewStream("bad sub", l.Addr().String(), key)
		if err != nil {
			t.Fatal("failed to create subscriber stream:", err)
		}

		if err := encoding.WriteObject(s, []byte("hello")); err != nil {
			t.Fatal("failed to write to stream:", err)
		}

		if err := encoding.ReadObject(s, new([]byte), 1024); err == nil {
			t.Fatal("expected subscriber error:", err)
		}
	})

	t.Run("echo subscriber", func(t *testing.T) {
		s, err := m.NewStream("echo", l.Addr().String(), key)
		if err != nil {
			t.Fatal("failed to create subscriber stream:", err)
		}

		req := frand.Bytes(128)
		if err := encoding.WriteObject(s, req); err != nil {
			t.Fatal("failed to write object to stream:", err)
		}

		var resp []byte
		if err := encoding.ReadObject(s, &resp, 1024); err != nil {
			t.Fatal("failed to read subscriber reply:", err)
		}

		if !bytes.Equal(req, resp) {
			t.Fatalf("unexpected reply: got %v expected %v", resp, req)
		}
	})
}

func TestSubscriberMuxCompat(t *testing.T) {
	dir := t.TempDir()

	serverMux, err := siamux.New(":0", ":0", log.DiscardLogger, filepath.Join(dir, "siamux"))
	if err != nil {
		t.Fatal("failed to create sia mux:", err)
	}
	defer serverMux.Close()

	serverMux.NewListener("echo", func(stream siamux.Stream) {
		var buf []byte
		if err := encoding.ReadObject(stream, &buf, 1024); err != nil {
			panic(fmt.Errorf("failed to read object from stream: %w", err))
		}

		if err := encoding.WriteObject(stream, buf); err != nil {
			panic(fmt.Errorf("failed to write object to stream: %w", err))
		}
	})

	conn, err := net.Dial("tcp", serverMux.Address().String())
	if err != nil {
		t.Fatal("failed to dial sia mux:", err)
	}
	defer conn.Close()

	serverKey := serverMux.PublicKey()
	m, err := DialSubscriber(conn, 5751, serverKey[:])
	if err != nil {
		t.Fatal("failed to dial subscriber mux:", err)
	}

	t.Run("bad subscriber", func(t *testing.T) {
		s, err := m.NewStream("bad sub")
		if err != nil {
			t.Fatal("failed to create subscriber stream:", err)
		}

		if err := encoding.WriteObject(s, []byte("hello")); err != nil {
			t.Fatal("failed to write to stream:", err)
		}

		if err := encoding.ReadObject(s, new([]byte), 1024); err == nil {
			t.Fatal("expected subscriber error:", err)
		}
	})

	t.Run("echo subscriber", func(t *testing.T) {
		s, err := m.NewStream("echo")
		if err != nil {
			t.Fatal("failed to create subscriber stream:", err)
		}

		req := frand.Bytes(128)
		if err := encoding.WriteObject(s, req); err != nil {
			t.Fatal("failed to write object to stream:", err)
		}

		var resp []byte
		if err := encoding.ReadObject(s, &resp, 1024); err != nil {
			t.Fatal("failed to read subscriber reply:", err)
		}

		if !bytes.Equal(req, resp) {
			t.Fatalf("unexpected reply: got %v expected %v", resp, req)
		}
	})

}
