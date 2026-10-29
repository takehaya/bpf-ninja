package syscallhook

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMapTypesFIFO(t *testing.T) {
	p, r, _ := mapTypesFixture()
	r.MapTypesELF = filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(r.MapTypesELF, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- supplyMapTypes(&p, r) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO read blocked")
	}
}
