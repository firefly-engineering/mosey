package wallet

import "testing"

func TestCapsString(t *testing.T) {
	cases := []struct {
		caps Caps
		want string
	}{
		{0, "view-only"},
		{CapWrite, "write"},
		{CapResize, "resize"},
		{CapForge, "forge"},
		{CapWrite | CapResize, "write, resize"},
		{AllCaps, "write, resize, forge"},
	}
	for _, tc := range cases {
		if got := tc.caps.String(); got != tc.want {
			t.Errorf("Caps(%d).String() = %q, want %q", tc.caps, got, tc.want)
		}
	}
}

func TestParseCapsRoundTrip(t *testing.T) {
	for caps := Caps(0); caps <= AllCaps; caps++ {
		s := caps.String()
		got, err := ParseCaps(s)
		if err != nil {
			t.Fatalf("ParseCaps(%q): %v", s, err)
		}
		if got != caps {
			t.Errorf("ParseCaps(%q) = %d, want %d", s, got, caps)
		}
	}
}

func TestParseCapsRejectsNonCanonical(t *testing.T) {
	bad := []string{
		"",                // empty must be "view-only"
		"write, write",    // duplicate
		"resize, write",   // wrong order
		"write,resize",    // missing space
		"WRITE",           // wrong case
		"owner",           // not a delegable cap
		"write, resize, ", // trailing token
		"write, resize, forge, extra",
	}
	for _, s := range bad {
		if _, err := ParseCaps(s); err == nil {
			t.Errorf("ParseCaps(%q) = nil error, want rejection", s)
		}
	}
}

func TestCapsSubset(t *testing.T) {
	if !(CapWrite).Subset(AllCaps) {
		t.Error("write should be a subset of all caps")
	}
	if !(Caps(0)).Subset(CapWrite) {
		t.Error("empty should be a subset of anything")
	}
	if (CapForge).Subset(CapWrite | CapResize) {
		t.Error("forge should not be a subset of write|resize")
	}
	if !AllCaps.Subset(AllCaps) {
		t.Error("all caps should be a subset of itself")
	}
}

func TestCapsHas(t *testing.T) {
	c := CapWrite | CapResize
	if !c.Has(CapWrite) || !c.Has(CapResize) {
		t.Error("write|resize should have write and resize")
	}
	if c.Has(CapForge) {
		t.Error("write|resize should not have forge")
	}
	if !c.Has(CapWrite | CapResize) {
		t.Error("Has should accept a multi-bit mask it fully covers")
	}
}

func TestParseCapsLenient(t *testing.T) {
	wr := CapWrite | CapResize
	cases := []struct {
		in   string
		want Caps
	}{
		{"write,resize", wr},
		{"write, resize", wr},
		{"resize, write", wr},   // order-independent
		{" write , resize ", wr}, // extra spaces
		{"write,resize,", wr},    // trailing comma
		{"view-only", 0},
		{"", 0},
		{"forge", CapForge},
	}
	for _, c := range cases {
		got, err := ParseCapsLenient(c.in)
		if err != nil {
			t.Errorf("ParseCapsLenient(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseCapsLenient(%q) = %d, want %d", c.in, got, c.want)
		}
	}
	if _, err := ParseCapsLenient("write,bogus"); err == nil {
		t.Error("ParseCapsLenient(write,bogus) = nil, want error")
	}
}
