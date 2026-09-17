package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mouizahmed/sshstate/internal/daemon"
	"github.com/mouizahmed/sshstate/internal/vault"
)

func initUnconfirmed(t *testing.T) (*scripted, string) {
	t.Helper()
	s := newScripted(t)
	kitPath := filepath.Join(t.TempDir(), "kit.txt")
	s.secrets = []string{password, password}
	s.lines = []string{"WRONGVALUE", "STILLWRONG", "NOPENOPE00"}
	if err := s.run(t, "init", "--kit", kitPath); err == nil {
		t.Fatal("init completed without confirming the recovery kit")
	}
	if _, err := os.Stat(s.Layout.Database()); err != nil {
		t.Fatalf("the failed confirmation removed the vault: %v", err)
	}
	return s, kitPath
}

func TestFailedConfirmationPointsAtAWorkingCommand(t *testing.T) {
	s, kitPath := initUnconfirmed(t)
	advice := s.errOut.String()
	if !strings.Contains(advice, "confirm-recovery") {
		t.Fatalf("the failure does not name the recovery command:\n%s", advice)
	}
	if !strings.Contains(advice, kitPath) {
		t.Errorf("the failure does not name the kit path it just wrote:\n%s", advice)
	}
	if strings.Contains(advice, "init --confirm-recovery") {
		t.Error("the failure still advertises a flag that does not exist")
	}
	var named bool
	for _, c := range Commands() {
		if c.Name == "confirm-recovery" {
			named = true
		}
	}
	if !named {
		t.Fatal("confirm-recovery is advertised but not implemented")
	}
}

func TestConfirmRecoveryWithoutDaemon(t *testing.T) {
	s, kitPath := initUnconfirmed(t)
	s.out.Reset()
	s.mustRun(t, "confirm-recovery", "--kit", kitPath)
	if !strings.Contains(s.out.String(), "confirmed") {
		t.Fatalf("confirm-recovery reported nothing:\n%s", s.out)
	}

	s.startDaemon(t)
	s.secrets = []string{password}
	s.mustRun(t, "unlock")
	s.mustRun(t, "add", "prod", "--hostname", "10.0.0.5", "--user", "ubuntu")
	body, err := os.ReadFile(s.Layout.Config())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Host prod") {
		t.Fatal("the confirmed vault did not accept a host")
	}
}

func TestConfirmRecoveryWithRunningDaemon(t *testing.T) {
	s, kitPath := initUnconfirmed(t)
	s.startDaemon(t)

	s.secrets = []string{password}
	s.mustRun(t, "unlock")
	err := s.run(t, "add", "prod", "--hostname", "10.0.0.5")
	if err == nil {
		t.Fatal("an unconfirmed vault accepted a host")
	}
	if !strings.Contains(err.Error(), "confirm-recovery") {
		t.Fatalf("the refusal does not say how to fix it: %v", err)
	}

	s.mustRun(t, "confirm-recovery", "--kit", kitPath)
	s.mustRun(t, "add", "prod", "--hostname", "10.0.0.5", "--user", "ubuntu")
}

func TestConfirmRecoveryRejectsAnotherVaultsKit(t *testing.T) {
	s, _ := initUnconfirmed(t)

	other := newScripted(t)
	otherKit := filepath.Join(t.TempDir(), "other-kit.txt")
	other.secrets = []string{password, password}
	other.answer = func(string) (string, error) {
		body, _ := os.ReadFile(otherKit)
		kit, err := vault.ParseKit(string(body))
		if err != nil {
			return "", err
		}
		return kit.Checksum(), nil
	}
	other.mustRun(t, "init", "--kit", otherKit)

	err := s.run(t, "confirm-recovery", "--kit", otherKit)
	if err == nil {
		t.Fatal("a kit from another vault confirmed this one")
	}
	if !strings.Contains(err.Error(), "does not belong to this vault") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfirmRecoveryRejectsADamagedKit(t *testing.T) {
	s, kitPath := initUnconfirmed(t)
	body, err := os.ReadFile(kitPath)
	if err != nil {
		t.Fatal(err)
	}
	damaged := strings.Replace(string(body), "signing_seed: ", "signing_seed: A", 1)
	damagedPath := filepath.Join(t.TempDir(), "damaged.txt")
	if err := os.WriteFile(damagedPath, []byte(damaged), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.run(t, "confirm-recovery", "--kit", damagedPath); err == nil {
		t.Fatal("a damaged kit was accepted")
	}
}

func TestConfirmRecoveryRefusesAMissingKit(t *testing.T) {
	s, _ := initUnconfirmed(t)
	if err := s.run(t, "confirm-recovery", "--kit", filepath.Join(t.TempDir(), "absent.txt")); err == nil {
		t.Fatal("a missing kit file was accepted")
	}
}

func TestInitExplainsItselfWhenTheKitCannotBeWritten(t *testing.T) {
	s := newScripted(t)
	s.secrets = []string{password, password}
	unwritable := filepath.Join(t.TempDir(), "no-such-dir", "kit.txt")

	err := s.run(t, "init", "--kit", unwritable)
	if err == nil {
		t.Fatal("init succeeded despite failing to write the kit")
	}
	if _, statErr := os.Stat(s.Layout.Database()); statErr != nil {
		t.Skip("no vault was created, so there is nothing to explain")
	}
	advice := s.errOut.String()
	if !strings.Contains(advice, s.Layout.Database()) {
		t.Errorf("the failure does not name the vault it left behind:\n%s", advice)
	}
	if !strings.Contains(advice, "cannot be recovered") {
		t.Errorf("the failure does not say the vault is unrecoverable:\n%s", advice)
	}
	if strings.Contains(advice, "confirm-recovery --kit "+unwritable) {
		t.Error("the failure suggests confirming with a kit that was never written")
	}
}

func TestInitRefusesExistingRecoveryKitPathWithoutChangingIt(t *testing.T) {
	s := newScripted(t)
	s.secrets = []string{password, password}
	kitPath := filepath.Join(t.TempDir(), "existing.txt")
	const original = "keep this file exactly as it is\n"
	if err := os.WriteFile(kitPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(kitPath, 0o644); err != nil {
		t.Fatal(err)
	}

	err := s.run(t, "init", "--kit", kitPath)
	if err == nil {
		t.Fatal("init overwrote an existing recovery-kit path")
	}
	body, readErr := os.ReadFile(kitPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(body) != original {
		t.Fatalf("existing file changed to %q", body)
	}
	fi, statErr := os.Stat(kitPath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := fi.Mode().Perm(); got != 0o644 {
		t.Fatalf("existing file mode changed to %04o", got)
	}
	if !strings.Contains(s.errOut.String(), "cannot be recovered") {
		t.Fatalf("failure did not explain the initialized vault state:\n%s", s.errOut.String())
	}
}

func TestInitExplainsItselfWhenTheConfirmationCannotBeRead(t *testing.T) {
	s := newScripted(t)
	kitPath := filepath.Join(t.TempDir(), "kit.txt")
	s.secrets = []string{password, password}
	s.answer = func(string) (string, error) { return "", io.EOF }

	if err := s.run(t, "init", "--kit", kitPath); err == nil {
		t.Fatal("init succeeded with no answer available")
	}
	advice := s.errOut.String()
	if !strings.Contains(advice, "confirm-recovery --kit "+kitPath) {
		t.Fatalf("the failure does not point at the saved kit:\n%s", advice)
	}
}

func TestConfirmRecoveryRefusesWhileADaemonOwnsTheVault(t *testing.T) {
	s, kitPath := initUnconfirmed(t)

	release, err := daemon.AcquireInstanceLock(s.Layout.DaemonLock())
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	err = s.run(t, "confirm-recovery", "--kit", kitPath)
	if err == nil {
		t.Fatal("the offline path opened a vault another process owns")
	}
	if !strings.Contains(err.Error(), "already running") {
		t.Fatalf("the error does not explain the conflict: %v", err)
	}

	release()
	s.mustRun(t, "confirm-recovery", "--kit", kitPath)
}
