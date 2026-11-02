package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRefusesSymlinkAndNonRegular(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.jsonl")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if l, err := Open(link, "s"); err == nil {
		_ = l.Close()
		t.Error("symlinked audit path accepted")
	}
	if _, err := Open(dir, "s"); err == nil {
		t.Error("directory accepted")
	}
	l, err := Open(target, "s")
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
}
