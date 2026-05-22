// Package screen renders raw PTY bytes into a rendered terminal
// surface, so downstream observers can pattern-match the *displayed*
// state of an attached vterm instead of fighting ANSI escapes and
// cursor moves in the byte stream.
//
// Typical use is alongside an attach client: feed every byte the
// attach output goroutine reads into [Screen.Write], then snapshot
// [Screen.Text] (or inspect individual [Cell] values) whenever the
// observer wants to evaluate a match.
//
//	s := screen.New(80, 24)
//	go func() {
//	    buf := make([]byte, 4096)
//	    for {
//	        n, err := ptyOutput.Read(buf)
//	        if n > 0 { _, _ = s.Write(buf[:n]) }
//	        if err != nil { return }
//	    }
//	}()
//	// later:
//	if strings.Contains(s.Text(), "Waiting for input") { ... }
//
// The implementation wraps a vt100 emulator ([vt10x.Terminal]).
// Geometry is fixed by [New] / [Screen.Resize]; mosey does not
// coordinate resize with the upstream vterm here — the consumer
// picks whatever (cols, rows) is convenient for their matching
// rules, and the emulator letterboxes / clips as needed.
package screen

import (
	"io"

	"github.com/hinshun/vt10x"
)

// Cell is a single grid position's rendered state. Just the rune
// today; colour / attribute fields can land as observer use cases
// demand them.
type Cell struct {
	// Char is the displayed rune at this cell. Cells that have
	// never been written are blank spaces.
	Char rune
}

// Screen is the rendered terminal surface produced by replaying
// PTY bytes through a vt100 emulator.
type Screen interface {
	// Writer accepts raw PTY bytes (escape sequences, cursor moves,
	// printable text) and updates the rendered grid. Always
	// consumes the full input — n == len(p), err == nil — short of
	// catastrophic emulator failure.
	io.Writer

	// Size returns the configured (cols, rows). Stable across
	// reads; changes only via Resize.
	Size() (cols, rows int)

	// Resize reshapes the grid. The underlying emulator's reflow
	// rules apply; in particular, narrowing the grid clips, not
	// wraps, the offscreen content.
	Resize(cols, rows int)

	// Text returns the rendered grid as one string: rows joined
	// with '\n', each row padded with spaces out to the grid's
	// configured width and terminated with a trailing '\n'. Stable
	// shape regardless of what was written — easy to substring /
	// regex against.
	Text() string

	// Cell returns the rune at (col, row). Out-of-bounds positions
	// return the zero Cell.
	Cell(col, row int) Cell

	// Cursor returns the current cursor position (col, row).
	Cursor() (col, row int)
}

// New constructs a Screen of the given dimensions. cols and rows
// must be positive; the function does not validate — passing zero
// or negative values produces an emulator that ignores writes.
func New(cols, rows int) Screen {
	return &vtScreen{
		term: vt10x.New(vt10x.WithSize(cols, rows)),
		cols: cols,
		rows: rows,
	}
}

// vtScreen is the only Screen implementation. Kept private so a
// future swap to a different emulator doesn't break callers.
type vtScreen struct {
	term vt10x.Terminal
	cols int
	rows int
}

func (s *vtScreen) Write(p []byte) (int, error) { return s.term.Write(p) }

func (s *vtScreen) Size() (int, int) { return s.term.Size() }

func (s *vtScreen) Resize(cols, rows int) {
	s.term.Resize(cols, rows)
	s.cols, s.rows = cols, rows
}

func (s *vtScreen) Text() string { return s.term.String() }

func (s *vtScreen) Cell(col, row int) Cell {
	cols, rows := s.term.Size()
	if col < 0 || row < 0 || col >= cols || row >= rows {
		return Cell{}
	}
	return Cell{Char: s.term.Cell(col, row).Char}
}

func (s *vtScreen) Cursor() (int, int) {
	c := s.term.Cursor()
	return c.X, c.Y
}
