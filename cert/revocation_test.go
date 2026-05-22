package cert_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/firefly-engineering/mosey/cert"
)

func TestLoadRevocationFile_MissingFileReturnsEmpty(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	got, err := cert.LoadRevocationFile(filepath.Join(dir, "missing.txt"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty set, got %d entries", len(got))
	}
}

func TestLoadRevocationFile_ParsesEntries(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "revoked.txt")
	body := "# Workspace foo revocations\n" +
		"serial-001\n" +
		"\n" +
		"serial-002\n" +
		"  serial-003  \n" + // leading/trailing whitespace
		"# comment in the middle\n" +
		"serial-004\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := cert.LoadRevocationFile(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, want := range []string{"serial-001", "serial-002", "serial-003", "serial-004"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %q from revocation set", want)
		}
	}
	if len(got) != 4 {
		t.Errorf("expected 4 entries, got %d: %v", len(got), got)
	}
}

func TestAppendRevocation_CreatesAndAppends(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "revoked.txt")

	if err := cert.AppendRevocation(path, "first"); err != nil {
		t.Fatalf("first append: %v", err)
	}
	if err := cert.AppendRevocation(path, "second"); err != nil {
		t.Fatalf("second append: %v", err)
	}

	got, err := cert.LoadRevocationFile(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := got["first"]; !ok {
		t.Error("first serial not loaded")
	}
	if _, ok := got["second"]; !ok {
		t.Error("second serial not loaded")
	}
}

func TestAppendRevocation_RejectsForbiddenChars(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "revoked.txt")
	for _, bad := range []string{"", "has\nnewline", "#starts-with-hash"} {
		if err := cert.AppendRevocation(path, bad); err == nil {
			t.Errorf("AppendRevocation(%q): expected error, got nil", bad)
		}
	}
}
