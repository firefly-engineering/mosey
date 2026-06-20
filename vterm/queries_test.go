package vterm

import (
	"bytes"
	"testing"
)

func TestDAResponder(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		wantOut     string
		wantRespHex string // "" = no response; else compare to the canned reply
	}{
		{"plain text", "hello", "hello", ""},
		{"DA1 bare", "\x1b[c", "", "da1"},
		{"DA1 zero", "\x1b[0c", "", "da1"},
		{"DA2 bare", "\x1b[>c", "", "da2"},
		{"DA2 zero", "\x1b[>0c", "", "da2"},
		{"DA1 amid text", "a\x1b[cb", "ab", "da1"},
		{"SGR passthrough", "\x1b[31mX\x1b[0m", "\x1b[31mX\x1b[0m", ""},
		{"DSR passthrough", "\x1b[6n", "\x1b[6n", ""},
		{"DA response passthrough", "\x1b[?1;2c", "\x1b[?1;2c", ""},
		{"unknown ESC", "\x1bP", "\x1bP", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var d daResponder
			out, resp := d.process([]byte(c.in))
			if string(out) != c.wantOut {
				t.Errorf("out = %q, want %q", out, c.wantOut)
			}
			switch c.wantRespHex {
			case "":
				if len(resp) != 0 {
					t.Errorf("resp = %q, want none", resp)
				}
			case "da1":
				if !bytes.Equal(resp, da1Response) {
					t.Errorf("resp = %q, want DA1 %q", resp, da1Response)
				}
			case "da2":
				if !bytes.Equal(resp, da2Response) {
					t.Errorf("resp = %q, want DA2 %q", resp, da2Response)
				}
			}
		})
	}
}

// TestDAResponderSplit confirms a query split across reads is still
// detected (state carries between process calls).
func TestDAResponderSplit(t *testing.T) {
	var d daResponder
	out, resp := d.process([]byte("\x1b["))
	if len(out) != 0 || len(resp) != 0 {
		t.Fatalf("after partial: out=%q resp=%q, want both empty", out, resp)
	}
	out, resp = d.process([]byte("c"))
	if len(out) != 0 {
		t.Errorf("out = %q, want empty (query stripped)", out)
	}
	if !bytes.Equal(resp, da1Response) {
		t.Errorf("resp = %q, want DA1", resp)
	}
}
