package cli

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/mouizahmed/sshstate/internal/control"
)

func TestAwaitDaemonWaitsForAServiceStillStarting(t *testing.T) {
	s := newScripted(t)
	delay := 600 * time.Millisecond
	go func() {
		time.Sleep(delay)
		ln, err := net.Listen("unix", s.Layout.ControlSocket())
		if err != nil {
			return
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{}"))
		})}
		t.Cleanup(func() { srv.Close() })
		srv.Serve(ln)
	}()

	start := time.Now()
	if err := s.Env.awaitDaemon(context.Background(), 5*time.Second); err != nil {
		t.Fatalf("a daemon that answered after %s was reported missing: %v", delay, err)
	}
	if waited := time.Since(start); waited < delay {
		t.Fatalf("returned after %s, before the daemon was listening", waited)
	}
}

func TestAwaitDaemonGivesUpOnADaemonThatNeverStarts(t *testing.T) {
	s := newScripted(t)
	err := s.Env.awaitDaemon(context.Background(), 300*time.Millisecond)
	if !errors.Is(err, control.ErrDaemonUnavailable) {
		t.Fatalf("want ErrDaemonUnavailable, got %v", err)
	}
}
