package program

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestFollowerLockTimesOutAndRecovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "follow.lock")
	first, err := lockFollowers(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first()

	started := time.Now()
	if _, err := lockFollowers(path, 40*time.Millisecond); !errors.Is(err, ErrFollowerLockTimeout) {
		t.Fatalf("contended lock: %v, want ErrFollowerLockTimeout", err)
	}
	if elapsed := time.Since(started); elapsed < 40*time.Millisecond || elapsed > 250*time.Millisecond {
		t.Fatalf("contended lock waited %s, want 40ms..250ms", elapsed)
	}

	first()
	second, err := lockFollowers(path, 40*time.Millisecond)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	second()
}
