package sshconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mouizahmed/sshstate/internal/paths"
)

func TestReactivatingRestoresExactlyTheBlocksThatWereCommentedOut(t *testing.T) {
	dir := t.TempDir()
	l := paths.Layout{Data: dir, SSH: filepath.Join(dir, "sshstate"), Runtime: dir, UserSSHConfig: filepath.Join(dir, "config")}
	original := "Host keep\n    HostName 10.0.0.9\n\nHost prod\n    HostName 10.0.0.5\n    # the old box\n\n    User ubuntu\n# a note that follows prod\nHost web\n    HostName 10.0.0.6\n"
	if err := os.WriteFile(l.UserSSHConfig, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts, problems := ParseImport(original)
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	var retire []ImportedHost
	for _, h := range hosts {
		if h.Alias != "keep" {
			retire = append(retire, h)
		}
	}
	if _, err := CommentOutBlocks(l, retire); err != nil {
		t.Fatal(err)
	}
	commented, _ := os.ReadFile(l.UserSSHConfig)
	if strings.Contains(string(commented), "\nHost prod") {
		t.Fatalf("prod was not commented out:\n%s", commented)
	}

	res, err := ReactivateBlocks(l)
	if err != nil {
		t.Fatal(err)
	}
	restored, _ := os.ReadFile(l.UserSSHConfig)
	if string(restored) != original {
		t.Fatalf("reactivation did not restore the original config.\nwant:\n%s\ngot:\n%s", original, restored)
	}
	if strings.Join(res.Aliases, ",") != "prod,web" {
		t.Fatalf("reactivated %v, want prod and web", res.Aliases)
	}
	if res.BackupPath == "" {
		t.Fatal("reactivation edited the config without a backup")
	}
	again, err := ReactivateBlocks(l)
	if err != nil || again.Lines != 0 {
		t.Fatalf("a second reactivation changed something: %+v %v", again, err)
	}
}
