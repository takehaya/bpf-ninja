// Package output — RawDumpWriter: --raw-dump path's writer. Writes
// ringbuf records verbatim to a per-CPU file with a 32 B header;
// `xdp-ninja convert` reconstructs standard pcap-ng offline.
//
// On-disk layout per file:
//
//	[ 0..16] magic "XNINJA-RAW-V1\0\0\0"
//	[16..20] u32 endian magic 0x12345678 (big-endian on wire)
//	[20..28] u64 wall_offset_ns LE — wall_clock - clock_monotonic
//	[28..32] u32 reserved
//	[32..  ] sequence of ringbuf records, each
//	          [16 B metadata + caplen B data] (no padding)
//
// Filename convention: <basePath>.W<wall_offset_ns>.cpu<N>.raw

package output

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/takehaya/xdp-ninja/internal/capture"
)

var (
	RawDumpMagic       = []byte("XNINJA-RAW-V1\x00\x00\x00") // 16 bytes
	RawDumpEndianMagic = uint32(0x12345678)
)

// RawDumpHeaderSize = magic(16) + endian(4) + offset(8) + reserved(4).
const RawDumpHeaderSize = 32

// WriteAnomalies records flushAll-path failures so callers can
// verify that captured-counter == bytes-on-disk. Zero-valued when
// the writer flushed cleanly; non-zero implies bytes the underlying
// file rejected. Aggregated across shards by captureLoopShardedRaw.
type WriteAnomalies struct {
	FlushErrors int64 // write(2) returned err
	ShortWrites int64 // write(2) returned n < requested (incl. n==0)
	BytesLost   int64 // sum of bytes the file didn't accept
}

// Add merges another WriteAnomalies into the receiver.
func (a *WriteAnomalies) Add(other WriteAnomalies) {
	a.FlushErrors += other.FlushErrors
	a.ShortWrites += other.ShortWrites
	a.BytesLost += other.BytesLost
}

// Any reports whether any failure was recorded.
func (a WriteAnomalies) Any() bool {
	return a.FlushErrors > 0 || a.ShortWrites > 0 || a.BytesLost > 0
}

// Sink is the common contract for raw-dump writers (write(2)-backed
// or in-memory). Allows captureLoopShardedRaw to dispatch on flag
// without dropping the concrete-type stop semantics.
type Sink interface {
	WriteRaw(raw []byte) error
	Flush() error
	Close() error
}

// AnomalyReporter is an optional capability: sinks that can surface
// mid-flush write errors (e.g. ENOSPC on a tmpfs target) implement
// it so captureLoopShardedRaw can warn at shutdown when the
// captured-counter and bytes-on-disk diverge. File-backed writers
// that retry short writes internally (bufio.Writer) do not need to
// implement this; the aggregation site uses an interface assertion.
type AnomalyReporter interface {
	Anomalies() WriteAnomalies
}

var (
	_ Sink            = (*RawDumpWriter)(nil)
	_ Sink            = (*InMemoryRawDumpWriter)(nil)
	_ AnomalyReporter = (*InMemoryRawDumpWriter)(nil)
)

// fillRawDumpHeader writes the 32 B raw-dump file header into hdr.
// Shared between the file-backed and in-memory writers.
func fillRawDumpHeader(hdr []byte, wallOffsetNs uint64) {
	copy(hdr[0:16], RawDumpMagic)
	binary.BigEndian.PutUint32(hdr[16:20], RawDumpEndianMagic)
	binary.LittleEndian.PutUint64(hdr[20:28], wallOffsetNs)
}

// rawRecordPayloadLen returns the number of bytes from a kernel
// ringbuf record that should be persisted: MetadataSize + caplen,
// clamped to the actual slice length. Shared between the file-backed
// and in-memory writers; both trim the fixed reservation's trailing
// slack the same way.
func rawRecordPayloadLen(raw []byte) int {
	want := capture.MetadataSize + int(capture.RecordCapLen(raw))
	if want > len(raw) {
		want = len(raw)
	}
	return want
}

// RawDumpWriter writes raw ringbuf records to a per-CPU file. The
// caller embeds W<wall_offset_ns> in the path so `xdp-ninja convert`
// can group per-session files by glob pattern.
type RawDumpWriter struct {
	file *os.File
	buf  *bufio.Writer
}

func NewRawDumpWriter(path string, wallOffsetNs uint64) (*RawDumpWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("creating raw-dump file: %w", err)
	}
	w := &RawDumpWriter{
		file: f,
		buf:  bufio.NewWriterSize(f, fileBufSize),
	}
	if err := w.writeHeader(wallOffsetNs); err != nil {
		_ = f.Close()
		return nil, err
	}
	return w, nil
}

func (w *RawDumpWriter) writeHeader(wallOffsetNs uint64) error {
	var hdr [RawDumpHeaderSize]byte
	fillRawDumpHeader(hdr[:], wallOffsetNs)
	if _, err := w.buf.Write(hdr[:]); err != nil {
		return fmt.Errorf("writing raw-dump header: %w", err)
	}
	return nil
}

// WriteRaw splats a single ringbuf record into the bufio'd file,
// trimming the kernel's fixed reservation down to (16 + caplen) so
// on-disk records are self-delimiting.
func (w *RawDumpWriter) WriteRaw(raw []byte) error {
	if len(raw) < capture.MetadataSize {
		return fmt.Errorf("raw record too short: %d bytes", len(raw))
	}
	if _, err := w.buf.Write(raw[:rawRecordPayloadLen(raw)]); err != nil {
		return fmt.Errorf("writing raw record: %w", err)
	}
	return nil
}

// Flush drains the bufio'd buffer to the underlying file.
func (w *RawDumpWriter) Flush() error {
	if w.buf != nil {
		return w.buf.Flush()
	}
	return nil
}

func (w *RawDumpWriter) Close() error {
	if err := w.Flush(); err != nil {
		_ = w.file.Close()
		return err
	}
	return w.file.Close()
}
