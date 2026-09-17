package cli

import (
	"bytes"
	"os"
	"sync"
	"testing"
	"time"
)

type transcript struct {
	mu   sync.Mutex
	seen []byte
}

func (x *transcript) collect(f *os.File) {
	buf := make([]byte, 256)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			x.mu.Lock()
			x.seen = append(x.seen, buf[:n]...)
			x.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (x *transcript) String() string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return string(x.seen)
}

func (x *transcript) await(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if bytes.Contains([]byte(x.String()), []byte(want)) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("waited for %q, terminal showed %q", want, x.String())
}

func TestAPasswordTypedBeforeThePromptIsNotUsedAsTheAnswer(t *testing.T) {
	master, slave := openPTY(t)
	if _, err := master.WriteString("typed-ahead\n"); err != nil {
		t.Fatal(err)
	}

	shown := &transcript{}
	go shown.collect(master)

	type answer struct {
		secret []byte
		err    error
	}
	done := make(chan answer, 1)
	go func() {
		secret, err := readSecretFrom(slave, "Unlock password: ")
		done <- answer{secret, err}
	}()

	shown.await(t, "Unlock password: ")
	if _, err := master.WriteString("hunter2\n"); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if got.err != nil {
		t.Fatal(got.err)
	}
	if string(got.secret) != "hunter2" {
		t.Fatalf("read %q; a password typed before the prompt was used", got.secret)
	}
	if after := shown.String(); bytes.Contains([]byte(after), []byte("hunter2")) {
		t.Fatalf("the terminal printed the password: %q", after)
	}
}
