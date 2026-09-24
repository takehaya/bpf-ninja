package fastrb

import (
	"errors"
	"os"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Cursor observes ring positions without consuming records. It may coexist
// with either reader implementation. Only the owning shard acknowledges a
// watermark, after its sink has finished the batch.
type Cursor struct{ consumer, producer []byte }

func NewCursor(fd int) (*Cursor, error) {
	page := os.Getpagesize()
	cons, err := unix.Mmap(fd, 0, page, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	prod, err := unix.Mmap(fd, int64(page), page, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		_ = unix.Munmap(cons)
		return nil, err
	}
	return &Cursor{cons, prod}, nil
}
func (c *Cursor) Produced() uint64 {
	return atomic.LoadUint64((*uint64)(unsafe.Pointer(&c.producer[0])))
}
func (c *Cursor) Consumed() uint64 {
	return atomic.LoadUint64((*uint64)(unsafe.Pointer(&c.consumer[0])))
}
func (c *Cursor) Close() error {
	if c.consumer == nil {
		return nil
	}
	err := errors.Join(unix.Munmap(c.consumer), unix.Munmap(c.producer))
	c.consumer = nil
	c.producer = nil
	return err
}
