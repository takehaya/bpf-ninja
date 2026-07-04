package output

import (
	"testing"
	"time"

	"github.com/takehaya/xdp-ninja/internal/capture"
)

// Benchmarks isolating the userspace overhead that --split-by-tag adds over
// a plain single-file capture. The in-kernel tag machinery (20B metadata,
// tag read) is always on regardless of the flag, so the flag's incremental
// cost is purely this write-path routing + per-tag writers. All writers are
// backed by /dev/null so the measurement is CPU (routing, lock, per-writer
// pcapng buffers), not disk — the total bytes written are identical between
// plain and split, so disk cost is not the delta.
//
// Run: go test -run '^$' -bench 'BenchmarkPlain|BenchmarkSplit' -benchmem ./internal/output/
//
// Naming: BenchmarkPlain is the flag OFF baseline (one writer). BenchmarkSplit*
// is the flag ON; the TagsN suffix is the number of DISTINCT tags (1/4/16),
// not a batch count, and Clustered/Interleaved is how those tags are ordered
// within a batch (contiguous same-tag runs vs per-packet round-robin).

const benchBatch = 256

func benchPackets(n int, tag func(i int) uint32) []capture.Packet {
	base := time.Unix(1700000000, 0).UTC()
	payload := make([]byte, 64) // shared: WritePacket serializes immediately
	pkts := make([]capture.Packet, n)
	for i := range pkts {
		pkts[i] = capture.Packet{
			Timestamp: base.Add(time.Duration(i) * time.Microsecond),
			Data:      payload,
			Tag:       tag(i),
		}
	}
	return pkts
}

func nullWriter(b *testing.B) *Writer {
	b.Helper()
	w, err := NewWriter("/dev/null", false)
	if err != nil {
		b.Fatalf("NewWriter: %v", err)
	}
	return w
}

// clustered: same-tag packets arrive contiguously (the common case — one
// set-map value's flows batch together). numTags contiguous runs per batch.
func clustered(numTags int) func(i int) uint32 {
	run := benchBatch / numTags
	return func(i int) uint32 { return uint32(i / run) }
}

// interleaved: tags round-robin per packet (worst case — every packet is its
// own run, so one WriteBatch + one lock per packet).
func interleaved(numTags int) func(i int) uint32 {
	return func(i int) uint32 { return uint32(i % numTags) }
}

func reportPerPkt(b *testing.B) {
	b.StopTimer() // exclude this reporting from the measured duration
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*benchBatch), "ns/pkt")
}

// BenchmarkPlain is the non-split baseline: one writer, one WriteBatch per
// batch.
func BenchmarkPlain(b *testing.B) {
	w := nullWriter(b)
	defer func() { _ = w.Close() }()
	pkts := benchPackets(benchBatch, func(int) uint32 { return 0 })
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := w.WriteBatch(pkts); err != nil {
			b.Fatal(err)
		}
	}
	reportPerPkt(b)
}

// benchmarkSplit mirrors captureLoopShardedSplit.writeShard: run-length group
// the batch by tag and WriteBatch each run into its per-tag writer.
func benchmarkSplit(b *testing.B, tag func(i int) uint32) {
	writers := map[uint32]*Writer{}
	defer func() {
		for _, w := range writers {
			_ = w.Close()
		}
	}()
	writerFor := func(t uint32) *Writer {
		if w := writers[t]; w != nil {
			return w
		}
		w := nullWriter(b)
		writers[t] = w
		return w
	}
	pkts := benchPackets(benchBatch, tag)
	// Warm up every tag's writer before timing so the one-time os.Create +
	// pcapng-header init is not charged to the measured write loop.
	for i := range pkts {
		writerFor(pkts[i].Tag)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		for i := 0; i < len(pkts); {
			t := pkts[i].Tag
			j := i + 1
			for j < len(pkts) && pkts[j].Tag == t {
				j++
			}
			if err := writerFor(t).WriteBatch(pkts[i:j]); err != nil {
				b.Fatal(err)
			}
			i = j
		}
	}
	reportPerPkt(b)
}

func BenchmarkSplitTags1(b *testing.B)             { benchmarkSplit(b, func(int) uint32 { return 0 }) }
func BenchmarkSplitTags4Clustered(b *testing.B)    { benchmarkSplit(b, clustered(4)) }
func BenchmarkSplitTags16Clustered(b *testing.B)   { benchmarkSplit(b, clustered(16)) }
func BenchmarkSplitTags4Interleaved(b *testing.B)  { benchmarkSplit(b, interleaved(4)) }
func BenchmarkSplitTags16Interleaved(b *testing.B) { benchmarkSplit(b, interleaved(16)) }
