package wallet

import (
	"bytes"
	"testing"
)

// FuzzParseContent pins two properties of the strict parser:
//   - it never panics on arbitrary input; and
//   - canonical idempotence — anything it accepts must re-render to the
//     exact same bytes, so non-canonical input can never slip through.
//
// Run the seed corpus with `go test`; explore with
// `go test ./wallet -run=FuzzParseContent -fuzz=FuzzParseContent`.
func FuzzParseContent(f *testing.F) {
	for _, v := range goldenFixtures() {
		f.Add([]byte(v.Content))
	}
	f.Add([]byte(""))
	f.Add([]byte("mosey session authorization v1"))
	f.Add([]byte("garbage\n\nnot a delegation"))

	f.Fuzz(func(t *testing.T, data []byte) {
		fields, err := ParseContent(data)
		if err != nil {
			return
		}
		if got := fields.Render(); !bytes.Equal(got, data) {
			t.Errorf("parser accepted non-canonical content:\n in: %q\nout: %q", data, got)
		}
	})
}
