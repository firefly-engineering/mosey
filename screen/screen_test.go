package screen_test

import (
	"strings"
	"testing"

	"github.com/firefly-engineering/mosey/screen"
)

// pad returns s right-padded with spaces to width cols. Mirrors
// what the underlying vt100 emulator writes when it pads the grid
// out to its configured width, so tests can build the expected
// Text() output without manually counting spaces.
func pad(s string, cols int) string {
	if len(s) >= cols {
		return s[:cols]
	}
	return s + strings.Repeat(" ", cols-len(s))
}

func TestNew_BlankGrid(t *testing.T) {
	s := screen.New(10, 3)
	cols, rows := s.Size()
	if cols != 10 || rows != 3 {
		t.Fatalf("Size = (%d, %d), want (10, 3)", cols, rows)
	}
	got := s.Text()
	want := strings.Repeat(pad("", 10)+"\n", 3)
	if got != want {
		t.Fatalf("blank grid text mismatch:\ngot  %q\nwant %q", got, want)
	}
	if col, row := s.Cursor(); col != 0 || row != 0 {
		t.Fatalf("cursor = (%d, %d), want (0, 0)", col, row)
	}
}

func TestWrite_PlainText(t *testing.T) {
	s := screen.New(10, 2)
	if _, err := s.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, want := s.Text(), pad("hello", 10)+"\n"+pad("", 10)+"\n"; got != want {
		t.Fatalf("text mismatch:\ngot  %q\nwant %q", got, want)
	}
	if c := s.Cell(0, 0); c.Char != 'h' {
		t.Errorf("Cell(0,0).Char = %q, want 'h'", c.Char)
	}
	if c := s.Cell(4, 0); c.Char != 'o' {
		t.Errorf("Cell(4,0).Char = %q, want 'o'", c.Char)
	}
	if c := s.Cell(5, 0); c.Char != ' ' {
		t.Errorf("Cell(5,0).Char = %q, want ' '", c.Char)
	}
	if col, row := s.Cursor(); col != 5 || row != 0 {
		t.Errorf("cursor = (%d, %d), want (5, 0)", col, row)
	}
}

func TestWrite_NewlineAdvancesRow(t *testing.T) {
	s := screen.New(10, 3)
	if _, err := s.Write([]byte("abc\r\ndef")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, want := s.Text(), pad("abc", 10)+"\n"+pad("def", 10)+"\n"+pad("", 10)+"\n"; got != want {
		t.Fatalf("text mismatch:\ngot  %q\nwant %q", got, want)
	}
	if col, row := s.Cursor(); col != 3 || row != 1 {
		t.Errorf("cursor = (%d, %d), want (3, 1)", col, row)
	}
}

func TestWrite_AnsiColourIsStripped(t *testing.T) {
	// SGR colour escapes shouldn't appear in Text(); only the
	// printable runes do. This is the property observers most rely
	// on — regex against rendered output, not raw stream.
	s := screen.New(10, 1)
	if _, err := s.Write([]byte("\x1b[31mRED\x1b[0m")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, want := s.Text(), pad("RED", 10)+"\n"; got != want {
		t.Fatalf("text mismatch:\ngot  %q\nwant %q", got, want)
	}
}

func TestWrite_CursorMoveOverwrites(t *testing.T) {
	s := screen.New(10, 1)
	// Write "hello", move cursor to col 0 via CR, overwrite with "HE".
	if _, err := s.Write([]byte("hello\rHE")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, want := s.Text(), pad("HEllo", 10)+"\n"; got != want {
		t.Fatalf("text mismatch:\ngot  %q\nwant %q", got, want)
	}
}

func TestCell_OutOfBoundsReturnsZero(t *testing.T) {
	s := screen.New(5, 2)
	for _, p := range [][2]int{{-1, 0}, {0, -1}, {5, 0}, {0, 2}, {10, 10}} {
		if c := s.Cell(p[0], p[1]); c != (screen.Cell{}) {
			t.Errorf("Cell(%d, %d) = %+v, want zero", p[0], p[1], c)
		}
	}
}

func TestResize_ChangesSize(t *testing.T) {
	s := screen.New(10, 3)
	s.Resize(20, 5)
	if cols, rows := s.Size(); cols != 20 || rows != 5 {
		t.Fatalf("after resize Size = (%d, %d), want (20, 5)", cols, rows)
	}
	// Blank grid in the new geometry.
	if got, want := s.Text(), strings.Repeat(pad("", 20)+"\n", 5); got != want {
		t.Fatalf("post-resize blank text mismatch:\ngot  %q\nwant %q", got, want)
	}
}
