// Package fastrb is a minimal BPF_MAP_TYPE_RINGBUF reader that
// bypasses cilium/ebpf's per-record Reader API. It mmaps the
// ringbuf directly, walks records in a batch, and lets the caller
// process each record via callback. Linux-only; tied to the kernel's
// BPF ringbuf userland ABI (see kernel/bpf/ringbuf.c). Header bit
// constants are re-declared here because cilium/ebpf keeps them in
// an internal/ package not importable from out-of-tree.
package fastrb

import (
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Kernel ringbuf record header bits, mirroring the UAPI constants
// BPF_RINGBUF_{BUSY,DISCARD}_BIT and BPF_RINGBUF_HDR_SZ (see
// kernel/bpf/ringbuf.c and include/uapi/linux/bpf.h).
const (
	hdrBusyBit    uint32 = 1 << 31
	hdrDiscardBit uint32 = 1 << 30
	hdrLenMask    uint32 = ^uint32(hdrBusyBit | hdrDiscardBit)
	hdrSize       uint32 = 8
)

// Reader reads from a single BPF ringbuf map. Single-owner: do not
// create both a fastrb.Reader and a cilium/ebpf ringbuf.Reader on the
// same map FD; they would race on the consumer-position page.
type Reader struct {
	mapFD   int
	epollFD int

	consMmap []byte // [page]   RW, holds consumer_pos at offset 0
	prodMmap []byte // [page + 2*ring] RO, producer_pos at 0, ring at [page:]

	consPos *uintptr // points into consMmap[0:8]
	prodPos *uintptr // points into prodMmap[0:8]

	ring     []byte  // alias of prodMmap[pageSize:], length = 2 × ringSize
	mask     uintptr // ringSize - 1, for masking ringbuf positions
	ringSize int

	events [1]unix.EpollEvent
}

// New mmaps the ringbuf map and registers it with a fresh epoll
// instance. ringSize is the kernel-side BPF_MAP_TYPE_RINGBUF
// MaxEntries (= ring capacity in bytes, must be a power of two).
func New(mapFD int, ringSize int) (*Reader, error) {
	pageSize := os.Getpagesize()

	cons, err := unix.Mmap(mapFD, 0, pageSize,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap consumer page: %w", err)
	}

	prod, err := unix.Mmap(mapFD, int64(pageSize), pageSize+2*ringSize,
		unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		_ = unix.Munmap(cons)
		return nil, fmt.Errorf("mmap producer+data pages: %w", err)
	}

	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		_ = unix.Munmap(cons)
		_ = unix.Munmap(prod)
		return nil, fmt.Errorf("epoll_create1: %w", err)
	}
	ev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(mapFD)}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, mapFD, &ev); err != nil {
		_ = unix.Close(epfd)
		_ = unix.Munmap(cons)
		_ = unix.Munmap(prod)
		return nil, fmt.Errorf("epoll_ctl ADD: %w", err)
	}

	r := &Reader{
		mapFD:    mapFD,
		epollFD:  epfd,
		consMmap: cons,
		prodMmap: prod,
		consPos:  (*uintptr)(unsafe.Pointer(&cons[0])),
		prodPos:  (*uintptr)(unsafe.Pointer(&prod[0])),
		ring:     prod[pageSize:],
		mask:     uintptr(ringSize - 1),
		ringSize: ringSize,
	}
	return r, nil
}

// Close unmaps the regions and closes the epoll fd. It does not
// close the underlying map FD — that belongs to the caller.
func (r *Reader) Close() error {
	var errs []error
	if r.epollFD >= 0 {
		if err := unix.Close(r.epollFD); err != nil {
			errs = append(errs, err)
		}
		r.epollFD = -1
	}
	if r.prodMmap != nil {
		if err := unix.Munmap(r.prodMmap); err != nil {
			errs = append(errs, err)
		}
		r.prodMmap = nil
	}
	if r.consMmap != nil {
		if err := unix.Munmap(r.consMmap); err != nil {
			errs = append(errs, err)
		}
		r.consMmap = nil
	}
	return errors.Join(errs...)
}

// WaitForData blocks until the kernel signals new data on the
// underlying map FD, or timeoutMs elapses (-1 = no timeout).
// Returns the number of fds ready (0 on timeout, 1 on data, or an
// error). The caller should ReadBatch immediately after a successful
// wake.
func (r *Reader) WaitForData(timeoutMs int) (int, error) {
	for {
		n, err := unix.EpollWait(r.epollFD, r.events[:], timeoutMs)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return 0, err
		}
		return n, nil
	}
}

// ReadBatch walks every committed record between the consumer and
// producer positions, invoking fn for each non-discard record.
// fn's record slice points directly into the mmap'd ring and is
// only valid until ReadBatch returns (the consumer position is
// advanced past it).
//
// Returns the number of records delivered to fn (discards are
// counted as advances but not delivered).
func (r *Reader) ReadBatch(fn func(record []byte)) int {
	prod := atomic.LoadUintptr(r.prodPos)
	cons := *r.consPos
	n := 0

	for cons < prod {
		off := cons & r.mask
		// Atomic load of the 32-bit length+flags word — establishes
		// happens-before with the kernel's xchg that publishes BUSY→
		// committed.
		lenWord := atomic.LoadUint32((*uint32)(unsafe.Pointer(&r.ring[off])))
		if lenWord&hdrBusyBit != 0 {
			break
		}
		dataLen := lenWord & hdrLenMask
		// Data is 8-byte aligned. Header is 8 bytes (length word +
		// pg_off pad). Total advance = header + alignUp8(dataLen).
		alignedData := (uintptr(dataLen) + 7) &^ 7
		dataStart := cons + uintptr(hdrSize)
		dataOff := dataStart & r.mask

		if lenWord&hdrDiscardBit == 0 {
			fn(r.ring[dataOff : dataOff+uintptr(dataLen)])
			n++
		}
		cons = dataStart + alignedData
	}

	atomic.StoreUintptr(r.consPos, cons)
	return n
}
