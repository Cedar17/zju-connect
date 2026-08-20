package atrust

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestTLSListener(t *testing.T) net.Listener {
	t.Helper()
	seed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificates := append([]tls.Certificate(nil), seed.TLS.Certificates...)
	seed.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: certificates})
	if err != nil {
		t.Fatalf("tls.Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func TestGetIPContextClosesStalledTLSReadOnCancellation(t *testing.T) {
	listener := newTestTLSListener(t)
	readStarted := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buffer := make([]byte, 1)
		if _, err := conn.Read(buffer); err != nil {
			return
		}
		close(readStarted)
		_, _ = io.Copy(io.Discard, conn)
	}()

	client := NewClient("user", "sid", "device", "")
	client.MajorNodeGroup = "group"
	client.BestNodes = map[string]string{"group": listener.Addr().String()}
	client.underlayDialer = newUnderlayDialer(listener.Addr().String(), "", false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- client.getIPContext(ctx)
	}()

	select {
	case <-readStarted:
	case <-time.After(time.Second):
		t.Fatal("IP request did not reach the TLS server")
	}
	startedAt := time.Now()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("getIPContext() error = %v, want context.Canceled", err)
		}
		if elapsed := time.Since(startedAt); elapsed > time.Second {
			t.Fatalf("stalled read returned after %s, want prompt cancellation", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("stalled TLS read did not stop after cancellation")
	}
}
