package cert

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// LoadRevocationFile parses path as a newline-delimited list of
// revoked cert serials. Lines starting with "#" are comments;
// blank lines are ignored. Returns an empty set when the file
// doesn't exist (a missing file is "no revocations" by design —
// callers shouldn't need to create the file just to set up the
// happy path).
func LoadRevocationFile(path string) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]struct{}{}, nil
		}
		return nil, fmt.Errorf("cert: open revocation file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return parseRevocationReader(f)
}

// parseRevocationReader is the io.Reader-flavored variant for
// tests and pubsub-fed sources.
func parseRevocationReader(r io.Reader) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[line] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("cert: read revocation file: %w", err)
	}
	return out, nil
}

// AppendRevocation appends serial to the revocation file at path,
// creating it (mode 0600) if needed. Each serial gets its own
// line; the file is open-and-close per call rather than long-lived
// so concurrent appenders can't trip over a stale fd.
func AppendRevocation(path, serial string) error {
	if serial == "" {
		return fmt.Errorf("cert: cannot revoke empty serial")
	}
	if strings.ContainsAny(serial, "\n#") {
		return fmt.Errorf("cert: serial %q contains forbidden character (newline / comment marker)", serial)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("cert: open revocation file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := fmt.Fprintln(f, serial); err != nil {
		return fmt.Errorf("cert: write revocation entry: %w", err)
	}
	return nil
}
