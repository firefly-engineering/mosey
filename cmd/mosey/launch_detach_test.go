package main_test

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// moseyBin is the compiled binary path, populated by TestMain.
var moseyBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "mosey-detach-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, "tempdir:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	moseyBin = filepath.Join(dir, "mosey")
	build := exec.Command("go", "build", "-o", moseyBin, ".")
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build:", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// shortSockPath mirrors vterm/unix_integration_test.go: macOS caps
// sun_path at ~104 bytes, and t.TempDir lands deeper than that on
// darwin. /tmp keeps us under the limit.
func shortSockPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ml")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, fmt.Sprintf("%d.sock", time.Now().UnixNano()%1_000_000))
}

// TestLaunchDetach_ParentExitsAfterAddresses asserts the end-to-end
// shape of --detach: parent prints addresses to its stderr and
// exits 0; the detached child stays alive past the parent; pidfile
// and address-file land where the user asked; both files are
// removed when the child eventually exits.
func TestLaunchDetach_ParentExitsAfterAddresses(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "mosey.pid")
	addrPath := filepath.Join(dir, "mosey.addr")
	logPath := filepath.Join(dir, "mosey.log")
	sock := shortSockPath(t)

	// `sleep 60` keeps the child alive long enough that we can poke
	// at its state — far longer than this test's wall clock budget.
	cmd := exec.Command(moseyBin, "launch",
		"--secret=test",
		"--detach",
		"--pidfile="+pidPath,
		"--address-file="+addrPath,
		"--log-file="+logPath,
		"--listen=unix://"+sock,
		"--", "sleep", "60",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("parent run: %v\nstderr: %s", err, stderr.String())
	}
	// Parent exited 0 — by contract its stderr already contains the
	// listening lines.
	if !strings.Contains(stderr.String(), "mosey launch: listening: unix://"+sock) {
		t.Fatalf("parent stderr missing endpoint line; got:\n%s", stderr.String())
	}

	// Child's pidfile + address-file should be populated promptly.
	pid := readPID(t, pidPath, 3*time.Second)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGTERM) })

	addrs := readEventually(t, addrPath, 3*time.Second)
	if !strings.Contains(addrs, "unix://"+sock) {
		t.Fatalf("address-file missing endpoint; got: %q", addrs)
	}

	// Child must still be running after parent exit.
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("child pid=%d not alive after parent exit: %v", pid, err)
	}

	// Ask the child to shut down. SIGTERM is wired through the
	// launch's signal.NotifyContext.
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Fatalf("sigterm child: %v", err)
	}

	// Pidfile + address-file should be cleaned up on graceful exit.
	waitForRemoval(t, pidPath, 5*time.Second)
	waitForRemoval(t, addrPath, 5*time.Second)
}

// TestLaunchDetach_RejectsAuxFlagsWithoutDetach: --pidfile etc.
// without --detach is a config mistake worth catching, not a
// silent no-op.
func TestLaunchDetach_RejectsAuxFlagsWithoutDetach(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		flag string
	}{
		{"pidfile", "--pidfile=" + filepath.Join(dir, "p")},
		{"address-file", "--address-file=" + filepath.Join(dir, "a")},
		{"log-file", "--log-file=" + filepath.Join(dir, "l")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(moseyBin, "launch", "--secret=x", tc.flag, "--", "true")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			if err == nil {
				t.Fatalf("expected non-zero exit, got success; stderr: %s", stderr.String())
			}
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != 2 {
				t.Fatalf("expected exit code 2, got %v; stderr: %s", err, stderr.String())
			}
			if !strings.Contains(stderr.String(), "only meaningful with --detach") {
				t.Fatalf("stderr missing explanation; got: %s", stderr.String())
			}
		})
	}
}

// readPID polls pidPath until it contains a valid integer or the
// deadline expires.
func readPID(t *testing.T, pidPath string, within time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		body, err := os.ReadFile(pidPath)
		if err == nil {
			pid, perr := strconv.Atoi(strings.TrimSpace(string(body)))
			if perr == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("pidfile %s never became readable within %s", pidPath, within)
	return 0
}

// readEventually polls path until it has non-empty contents or the
// deadline expires.
func readEventually(t *testing.T, path string, within time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		body, err := os.ReadFile(path)
		if err == nil && len(body) > 0 {
			return string(body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("file %s never became readable within %s", path, within)
	return ""
}

// waitForRemoval polls path until it no longer exists or the
// deadline expires.
func waitForRemoval(t *testing.T, path string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		_, err := os.Stat(path)
		if errors.Is(err, fs.ErrNotExist) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("file %s was not removed within %s", path, within)
}
