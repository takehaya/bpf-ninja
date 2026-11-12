package program

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// FollowerLockPath serializes follower admission and attach across captures.
	FollowerLockPath = "/run/bpf-ninja/follow.lock"
	followerLockWait = time.Second
)

// ErrFollowerLockTimeout is returned when another capture holds the follower
// lock for the full wait bound.
var ErrFollowerLockTimeout = errors.New("timed out waiting for the follower lock")

// LockFollowers takes the process-shared lock used around one program's
// follower admission and attaches.
func LockFollowers() (func(), error) {
	if err := os.MkdirAll(filepath.Dir(FollowerLockPath), 0o755); err != nil {
		return nil, fmt.Errorf("create follower lock directory: %w", err)
	}
	return lockFollowers(FollowerLockPath, followerLockWait)
}

func lockFollowers(path string, wait time.Duration) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open follower lock %s: %w", path, err)
	}
	deadline := time.Now().Add(wait)
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			var once sync.Once
			return func() {
				once.Do(func() {
					_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
					_ = f.Close()
				})
			}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = f.Close()
			return nil, fmt.Errorf("lock follower file %s: %w", path, err)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			_ = f.Close()
			return nil, fmt.Errorf("%w: %s", ErrFollowerLockTimeout, path)
		}
		if remaining > 10*time.Millisecond {
			remaining = 10 * time.Millisecond
		}
		time.Sleep(remaining)
	}
}
