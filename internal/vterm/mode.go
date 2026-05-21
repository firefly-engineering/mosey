package vterm

import (
	"fmt"

	"github.com/firefly-engineering/ship/internal/api"
)

// Mode controls how a vterm.Session accepts and manages concurrent
// attach clients.
//
// The four modes form a progression: Exclusive is the strictest
// (one writer, no one else admitted), Supersede is the friendliest
// for roaming (newest connection wins, older clients exit cleanly),
// PrimaryObserver lets a writer plus N watchers coexist, and
// MultiWrite is tmux-style (everyone with the Write cap can type;
// bytes interleave).
type Mode int

const (
	// ModeUnspecified is the zero value. Run() rejects it; valid
	// callers must pick a mode explicitly. Reserved as the "I
	// didn't choose" sentinel for the CLI's flag parser.
	ModeUnspecified Mode = iota

	// ModeSupersede: a new attach kicks all existing attaches.
	// Older clients see EOF on their PTY stream and exit cleanly.
	// Single live attacher at any time. Best default for "I roam
	// between machines."
	ModeSupersede

	// ModeExclusive: while a session has any attached client, new
	// attaches are refused. Most restrictive; useful when you
	// don't want surprise interlopers and explicitly know you're
	// the only user.
	ModeExclusive

	// ModePrimaryObserver: the first writer-capable attach wins
	// the "writer seat"; subsequent attaches are forced to
	// observer mode regardless of their auth caps. If the writer
	// disconnects, the seat stays vacant until a new
	// writer-capable client attaches — observers are never
	// auto-promoted (per the design discussion: explicit role
	// transitions only).
	ModePrimaryObserver

	// ModeMultiWrite: every writer-capable attach can type; bytes
	// interleave into the PTY in arrival order. Works for "same
	// human in N places" (no contention); error-prone if two
	// humans share. Closest to tmux's multi-client model.
	ModeMultiWrite
)

// String renders a Mode in the CLI form ("supersede", "exclusive",
// …). Stable; --mode parses against this set.
func (m Mode) String() string {
	switch m {
	case ModeSupersede:
		return "supersede"
	case ModeExclusive:
		return "exclusive"
	case ModePrimaryObserver:
		return "primary-observer"
	case ModeMultiWrite:
		return "multi-write"
	default:
		return "unspecified"
	}
}

// ParseMode reads the CLI form back into a [Mode]. Returns an
// error for any string outside the documented set, including the
// empty string (callers should default to [ModeSupersede] before
// calling).
func ParseMode(s string) (Mode, error) {
	switch s {
	case "supersede":
		return ModeSupersede, nil
	case "exclusive":
		return ModeExclusive, nil
	case "primary-observer":
		return ModePrimaryObserver, nil
	case "multi-write":
		return ModeMultiWrite, nil
	default:
		return ModeUnspecified, fmt.Errorf("vterm: unknown mode %q (have: supersede, exclusive, primary-observer, multi-write)", s)
	}
}

// modeFromAPI maps an [api.SetMode_Kind] to the corresponding
// [Mode]. Returns ModeUnspecified for unknown kinds — callers
// should treat the unspecified result as a no-op (silently ignore
// the SetMode message).
func modeFromAPI(k api.SetMode_Kind) Mode {
	switch k {
	case api.SetMode_KIND_SUPERSEDE:
		return ModeSupersede
	case api.SetMode_KIND_EXCLUSIVE:
		return ModeExclusive
	case api.SetMode_KIND_PRIMARY_OBSERVER:
		return ModePrimaryObserver
	case api.SetMode_KIND_MULTI_WRITE:
		return ModeMultiWrite
	default:
		return ModeUnspecified
	}
}
