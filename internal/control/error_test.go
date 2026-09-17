package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPIErrorMatchesOnCodeNotMessage(t *testing.T) {
	locked := &APIError{Code: CodeLocked, Message: "vault is locked"}
	if !errors.Is(locked, ErrLocked) {
		t.Fatal("a locked error did not match ErrLocked")
	}
	if errors.Is(locked, ErrRecoveryUnconfirmed) {
		t.Fatal("a locked error matched an unrelated code")
	}

	differentMessage := &APIError{Code: CodeLocked, Message: "something else entirely"}
	if !errors.Is(differentMessage, ErrLocked) {
		t.Fatal("matching depends on the message, not the code")
	}

	wrapped := fmt.Errorf("unlock: %w", locked)
	if !errors.Is(wrapped, ErrLocked) {
		t.Fatal("a wrapped API error did not match")
	}
	if errors.Is(errors.New("plain"), ErrLocked) {
		t.Fatal("a plain error matched an API error")
	}
}

func TestAnOversizedReplySaysSoInsteadOfFailingToParse(t *testing.T) {
	dir, err := os.MkdirTemp("", "ctl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(append([]byte(`{"vault_id":"`), bytes.Repeat([]byte("a"), MaxRequestBytes)...))
	})}
	go srv.Serve(listener)
	t.Cleanup(func() { srv.Close() })

	_, err = NewClient(socket).Status(context.Background())
	if err == nil {
		t.Fatal("a reply past the limit was accepted")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("a truncated reply was reported as %v", err)
	}
}
