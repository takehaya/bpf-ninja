// Package output — InMemoryRawDumpWriter: raw-dump writer that
// holds all bytes in a pre-touched Go-heap buffer until Close(),
// avoiding both syscall.Write and tmpfs page-fault costs in the
// capture hot path. Trade-off: per-shard buffer memory footprint
// scales with expected capture size.
package output

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/takehaya/xdp-ninja/internal/capture"
)

// InMemoryRawDumpWriter writes raw ringbuf records into a
// MAP_POPULATE-prefaulted mmap'd anonymous region and only flushes
// to disk at Close (or when the buffer fills). Total memory =
// bufSize × numShards.
type InMemoryRawDumpWriter struct {
	file *os.File
	buf  []byte
	pos  int
	// anomalies records flushAll() failures so callers can verify
	// captured-counter == bytes-on-disk. Atomicity not needed: each
	// shard owns its writer.
	anomalies WriteAnomalies
}

// Anomalies returns a snapshot of the flushAll-path failure
// counters. Zero-valued when the writer has flushed cleanly.
func (w *InMemoryRawDumpWriter) Anomalies() WriteAnomalies { return w.anomalies }

// NewInMemoryRawDumpWriter mmaps a sizeBytes anonymous region with
// MAP_POPULATE so the kernel allocates and zero-fills all physical
// pages immediately. Subsequent WriteRaw calls write into already-
// resident memory without page faults on the capture hot path.
func NewInMemoryRawDumpWriter(path string, wallOffsetNs uint64, sizeBytes int) (*InMemoryRawDumpWriter, error) {
	if sizeBytes < RawDumpHeaderSize+capture.MetadataSize {
		return nil, fmt.Errorf("buffer size %d too small (need >= %d)", sizeBytes, RawDumpHeaderSize+capture.MetadataSize)
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("creating raw-dump file: %w", err)
	}
	buf, err := unix.Mmap(-1, 0, sizeBytes,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_ANON|unix.MAP_PRIVATE|unix.MAP_POPULATE)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("mmap %d bytes: %w", sizeBytes, err)
	}
	w := &InMemoryRawDumpWriter{file: f, buf: buf}
	if err := w.writeHeader(wallOffsetNs); err != nil {
		_ = unix.Munmap(buf)
		_ = f.Close()
		return nil, err
	}
	return w, nil
}

func (w *InMemoryRawDumpWriter) writeHeader(wallOffsetNs uint64) error {
	fillRawDumpHeader(w.buf[:RawDumpHeaderSize], wallOffsetNs)
	w.pos = RawDumpHeaderSize
	return nil
}

// WriteRaw memcopies a trimmed record into the buffer. If the
// buffer fills, it flushes once to disk and resets the write
// position, so capture continues without loss (just slower for
// that one flush). A single record larger than the buffer is an
// error.
func (w *InMemoryRawDumpWriter) WriteRaw(raw []byte) error {
	if len(raw) < capture.MetadataSize {
		return fmt.Errorf("raw record too short: %d bytes", len(raw))
	}
	want := rawRecordPayloadLen(raw)
	if w.pos+want > len(w.buf) {
		if err := w.flushAll(); err != nil {
			return err
		}
		if want > len(w.buf) {
			return fmt.Errorf("record size %d exceeds buffer %d", want, len(w.buf))
		}
	}
	copy(w.buf[w.pos:], raw[:want])
	w.pos += want
	return nil
}

func (w *InMemoryRawDumpWriter) flushAll() error {
	if w.pos == 0 {
		return nil
	}
	total := w.pos
	off := 0
	for off < total {
		n, err := w.file.Write(w.buf[off:total])
		if err != nil {
			w.anomalies.FlushErrors++
			w.anomalies.BytesLost += int64(total - off)
			w.pos = 0
			return fmt.Errorf("flushing in-memory buffer (wrote %d/%d bytes before error): %w", off+n, total, err)
		}
		if n == 0 {
			// io.Writer contract: n==0 with err==nil is invalid;
			// guard against driver bugs to avoid infinite loop.
			w.anomalies.ShortWrites++
			w.anomalies.BytesLost += int64(total - off)
			w.pos = 0
			return fmt.Errorf("flushing in-memory buffer: write returned 0 with no error after %d/%d bytes", off, total)
		}
		if n < total-off {
			w.anomalies.ShortWrites++
		}
		off += n
	}
	w.pos = 0
	return nil
}

func (w *InMemoryRawDumpWriter) Flush() error {
	return w.flushAll()
}

func (w *InMemoryRawDumpWriter) Close() error {
	flushErr := w.flushAll()
	if w.buf != nil {
		_ = unix.Munmap(w.buf)
		w.buf = nil
	}
	closeErr := w.file.Close()
	if flushErr != nil {
		return flushErr
	}
	return closeErr
}
