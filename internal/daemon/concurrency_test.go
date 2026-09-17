package daemon

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/mouizahmed/sshstate/internal/control"
)

func TestConcurrentLockSignAndStatus(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	if _, err := h.client.Unlock(ctx, testPassword); err != nil {
		t.Fatal(err)
	}
	added, err := h.client.AddKey(ctx, control.AddKeyRequest{PrivateKey: string(testKeyPEM(t, "race"))})
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(added.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	var wg sync.WaitGroup
	data := []byte("exchange hash")

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.Dial("unix", h.layout.AgentSocket())
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			client := agent.NewClient(conn)
			for time.Now().Before(deadline) {
				sig, err := client.Sign(pub, data)
				if err != nil {
					continue
				}
				if err := pub.Verify(data, sig); err != nil {
					t.Errorf("agent returned a signature that does not verify: %v", err)
					return
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for time.Now().Before(deadline) {
			if _, err := h.client.Lock(ctx); err != nil {
				t.Error(err)
				return
			}
			time.Sleep(5 * time.Millisecond)
			if _, err := h.client.Unlock(ctx, testPassword); err != nil {
				t.Error(err)
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				if _, err := h.client.Status(ctx); err != nil {
					t.Errorf("status failed under concurrency: %v", err)
					return
				}
			}
		}()
	}

	wg.Wait()

	if _, err := h.client.Unlock(ctx, testPassword); err != nil {
		t.Fatal(err)
	}
	keys, err := h.client.Keys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].RecordID != added.RecordID {
		t.Fatalf("vault holds %d keys after the race", len(keys))
	}
}
