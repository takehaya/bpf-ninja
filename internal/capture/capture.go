// Package capture reads packets from the BPF ringbuf transport.
package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
)

// WallOffsetNs is wall_clock_ns − CLOCK_MONOTONIC_ns measured once at
// package init; ParseRawSample uses it to convert bpf_ktime_get_ns()
// to wall clock. Long-running captures may need to re-sync as NTP
// slews the wall clock.
var WallOffsetNs uint64

// LegacyTimestamp, when true, switches Packet.Timestamp to a per-batch
// userspace time.Now() (all packets in a 256-batch share one
// timestamp) instead of the per-packet kernel monotonic-time. Set via
// the --legacy-timestamp CLI flag.
var LegacyTimestamp bool

// BusyPoll, when true, makes the fast-reader shard goroutines spin on
// ReadBatch instead of blocking in epoll_wait. The consumer never
// sleeps, so it drains the ringbuf continuously and needs no producer-
// side wakeup — pair with --no-wakeup to take wakeup backpressure off
// the RX softirq. Burns a core per shard. Set via --busy-poll.
var BusyPoll bool

// SplitCoreRX, when > 0, pins readers to allowed CPU IDs >= SplitCoreRX.
// Every producer shard is still drained, even if NIC steering sends traffic
// to an unexpected CPU. Set via --rx-cores.
var SplitCoreRX int

// DisableCPUAffinity, when true, skips pinning each per-shard reader
// goroutine to its producer CPU. Default-false pins goroutine N to
// CPU N so the read stays on the cache line the BPF producer just
// wrote. Set via --no-cpu-affinity for diagnostic use.
var DisableCPUAffinity bool

// shardPollTimeoutMs caps how long the fast-reader's epoll_wait
// blocks before the shard goroutine re-checks the stop channel.
// On the hot path EpollWait returns immediately (data is ready);
// the timeout only bounds shutdown latency under idle traffic.
const shardPollTimeoutMs = 1

// LatencySamplePeriod, when > 0, makes the fast-reader sample every
// Nth ringbuf record's BPF-submit→reader-read latency. Samples land
// in per-shard slices accumulated under LatencySamples and drained
// at stop(). Set via --latency-sample-period at startup; default 0
// means no sampling.
var LatencySamplePeriod int64

// LatencySamples collects per-shard latency_ns int64 slices. Each
// shard goroutine appends only to its own index (no atomic / lock
// needed); the caller reads after stop() drains all readers.
var LatencySamples [][]int64

func init() {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err == nil {
		mono := uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
		WallOffsetNs = uint64(time.Now().UnixNano()) - mono
	}
}

// Packet represents a captured packet.
type Packet struct {
	Timestamp time.Time
	Data      []byte
	Action    uint32 // hook verdict: XDP action / TC verdict (fexit only)
	Mode      uint8  // 0=entry(fentry), 1=exit(fexit), 2=xdp-native
	CapLen    uint16 // bytes the BPF side actually copied into Data
	Tag       uint32 // set-map value of the matched entry (0 when no set matched)
}

// Reader reads captured packets from the ringbuf.
type Reader struct {
	reader *ringbuf.Reader
	rec    ringbuf.Record

	session      *shardSession
	cursors      []*fastrb.Cursor
	shardReaders []*ringbuf.Reader
}

// ShardSink processes a batch of packets from one per-CPU shard.
type ShardSink func(shardIdx int, pkts []Packet) error

// ErrClosed is returned when the reader has been closed.
var ErrClosed = errors.New("reader closed")

// NewReader creates a new packet reader from a BPF ringbuf map. The
// ringbuf size is set at map-creation time; the size argument here is
// retained for compatibility but ignored — BPF_MAP_TYPE_RINGBUF carries
// its own MaxEntries.
func NewReader(eventsMap *ebpf.Map, _ int) (*Reader, error) {
	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return nil, fmt.Errorf("creating ringbuf reader: %w", err)
	}
	return &Reader{reader: reader}, nil
}

// Ringbuf record layout emitted by captureWithRingbuf / captureXDPNative:
//
//	RawSample = [metadata (20B)] [packet bytes (caplen B)] [trailing slack]
//	metadata:
//	  u64 kernel_ts_ns (offset 0)  — bpf_ktime_get_ns() at packet ingest
//	  u32 action       (offset 8)
//	  u8  mode         (offset 12)
//	  u8  _pad         (offset 13)
//	  u16 caplen       (offset 14)
//	  u32 tag          (offset 16) — set-map value of the matched entry, 0 if none
//
// All multi-byte fields are host-endian: BPF stores via asm.StoreMem
// produce native-endian writes, so readers must use binary.NativeEndian.
const (
	MetadataSize   = 20
	OffsetKernelTs = 0
	OffsetAction   = 8
	OffsetMode     = 12
	OffsetCapLen   = 14
	OffsetTag      = 16
)

// RecordKernelTs reads the kernel_ts_ns field from a raw ringbuf record.
func RecordKernelTs(raw []byte) uint64 {
	return binary.NativeEndian.Uint64(raw[OffsetKernelTs : OffsetKernelTs+8])
}

// RecordCapLen reads the caplen field from a raw ringbuf record.
func RecordCapLen(raw []byte) uint16 {
	return binary.NativeEndian.Uint16(raw[OffsetCapLen : OffsetCapLen+2])
}

// Read returns the next captured packet. Blocks until a packet is available.
func (r *Reader) Read() (Packet, error) {
	if err := r.reader.ReadInto(&r.rec); err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return Packet{}, ErrClosed
		}
		return Packet{}, fmt.Errorf("reading ringbuf event: %w", err)
	}

	pkt, err := ParseRawSample(r.rec.RawSample)
	if err != nil {
		return Packet{}, err
	}
	if LegacyTimestamp {
		pkt.Timestamp = time.Now()
	}
	return pkt, nil
}

// pollPastDeadline is a fixed past timestamp used to flip the
// underlying ringbuf.Reader into non-blocking poll mode for ReadBatch.
// time.Unix(1, 0) is well before any plausible wall-clock so every
// ringbuf.Reader.ReadInto call after the deadline change returns
// os.ErrDeadlineExceeded immediately when the buffer is empty.
var pollPastDeadline = time.Unix(1, 0)

// ReadBatch fills buf with up to len(buf) packets in one call. The
// first record blocks; subsequent records are drained non-blockingly
// until the buffer is empty or buf fills.
func (r *Reader) ReadBatch(buf []Packet) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	// First record blocks under the caller-set deadline (default
	// blocking). Take the wall-clock once on success.
	if err := r.reader.ReadInto(&r.rec); err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return 0, ErrClosed
		}
		return 0, fmt.Errorf("reading ringbuf event: %w", err)
	}
	now := time.Now()

	pkt, err := ParseRawSample(r.rec.RawSample)
	if err != nil {
		return 0, err
	}
	if LegacyTimestamp {
		pkt.Timestamp = now
	}
	buf[0] = pkt
	n := 1

	// Flip to poll-only mode: any subsequent ReadInto with no
	// pending record returns os.ErrDeadlineExceeded immediately.
	r.reader.SetDeadline(pollPastDeadline)
	defer r.reader.SetDeadline(time.Time{})

	for n < len(buf) {
		err := r.reader.ReadInto(&r.rec)
		if err != nil {
			// Empty ring → we're done with this batch. ringbuf
			// surfaces the deadline as os.ErrDeadlineExceeded; treat
			// any error other than ErrClosed as "drained, return what
			// we have".
			if errors.Is(err, ringbuf.ErrClosed) {
				return n, ErrClosed
			}
			return n, nil
		}
		pkt, err := ParseRawSample(r.rec.RawSample)
		if err != nil {
			return n, err
		}
		if LegacyTimestamp {
			pkt.Timestamp = now
		}
		buf[n] = pkt
		n++
	}
	return n, nil
}

// ParseRawSample parses a raw ringbuf record into a Packet.
// Packet.Timestamp = kernel_ts_ns + WallOffsetNs.
func ParseRawSample(raw []byte) (Packet, error) {
	if len(raw) < MetadataSize {
		return Packet{}, fmt.Errorf("sample too short: %d bytes", len(raw))
	}

	kernelTs := RecordKernelTs(raw)
	caplen := RecordCapLen(raw)
	end := min(MetadataSize+int(caplen), len(raw))
	return Packet{
		Timestamp: time.Unix(0, int64(kernelTs+WallOffsetNs)),
		Action:    binary.NativeEndian.Uint32(raw[OffsetAction : OffsetAction+4]),
		Mode:      raw[OffsetMode],
		CapLen:    caplen,
		Tag:       binary.NativeEndian.Uint32(raw[OffsetTag : OffsetTag+4]),
		Data:      raw[MetadataSize:end],
	}, nil
}

// Close closes the reader.
func (r *Reader) Close() error {
	if r.reader != nil {
		return r.reader.Close()
	}
	return nil
}

// NewShardedReader opens one ringbuf.Reader per inner map.
func NewShardedReader(inners []*ebpf.Map) (*Reader, error) {
	r := &Reader{shardReaders: make([]*ringbuf.Reader, 0, len(inners))}
	for i, m := range inners {
		rr, err := ringbuf.NewReader(m)
		if err != nil {
			for _, prev := range r.shardReaders {
				_ = prev.Close()
			}
			return nil, fmt.Errorf("creating shard reader %d: %w", i, err)
		}
		r.shardReaders = append(r.shardReaders, rr)
	}
	for _, m := range inners {
		c, err := fastrb.NewCursor(m.FD())
		if err != nil {
			for _, rr := range r.shardReaders {
				_ = rr.Close()
			}
			for _, c := range r.cursors {
				_ = c.Close()
			}
			return nil, err
		}
		r.cursors = append(r.cursors, c)
	}
	return r, nil
}

// batchSize is the target batch size: the initial Packet/arena capacity
// and the drain bound for the default reader (RunShards stops draining
// and flushes once the batch reaches batchSize). The fast reader
// (RunShardsFast) drains every committed record in one ReadBatch pass
// and flushes once afterward, so a single fast-reader batch may exceed
// batchSize; the arena and Packet slice grow to fit.
const batchSize = 256

// arenaInitPerPacket sizes the per-shard copy arena: batchSize × this
// many bytes is pre-allocated so a full default-reader batch of
// MTU-sized packets fits without reallocating. Larger fast-reader
// batches grow the arena to a high-water mark and then reuse it.
const arenaInitPerPacket = 2048

// batchBuilder accumulates a batch of Packets for one shard while
// owning their payload bytes. ParseRawSample returns a Packet whose
// Data aliases the source buffer — the cilium/ebpf ringbuf.Record
// (default reader) or the mmap'd ring (fast reader) — and that backing
// memory is overwritten by the next read. Because a batch is flushed to
// sink only after it fills, holding those aliases would hand sink stale
// bytes. add() therefore copies each payload into a reusable per-shard
// arena and repoints Data into it. The arena is reset (not freed) on
// every flush, so steady-state allocation is zero.
type batchBuilder struct {
	shardIdx int
	sink     ShardSink
	buf      []Packet
	arena    []byte
}

func newBatchBuilder(shardIdx int, sink ShardSink) *batchBuilder {
	return &batchBuilder{
		shardIdx: shardIdx,
		sink:     sink,
		buf:      make([]Packet, 0, batchSize),
		arena:    make([]byte, 0, batchSize*arenaInitPerPacket),
	}
}

// add copies pkt's payload into the arena, repoints pkt.Data into it,
// and appends pkt to the batch. add never calls sink, so it is safe to
// invoke from inside fastrb.Reader.ReadBatch's callback, where flushing
// would run sink I/O before the consumer position is committed and add
// ringbuf backpressure on the producer.
//
// If the payload does not fit the arena's spare capacity, append grows
// it. A reallocation does not corrupt payloads already queued in this
// batch: their Data slices keep the old backing array (with its bytes
// intact) alive until the batch is flushed. The arena reaches a
// high-water mark and is reset, not freed, on flush, so steady-state
// allocation is zero.
func (b *batchBuilder) add(pkt Packet) {
	n := len(pkt.Data)
	start := len(b.arena)
	b.arena = append(b.arena, pkt.Data...)
	pkt.Data = b.arena[start : start+n]
	b.buf = append(b.buf, pkt)
}

// flush hands the accumulated batch to sink and resets the buffers for
// reuse. sink must consume (write/copy) every Packet.Data before
// returning; once flush resets the arena those bytes are recycled.
func (b *batchBuilder) flush() error {
	if len(b.buf) == 0 {
		return nil
	}
	err := b.sink(b.shardIdx, b.buf)
	b.buf = b.buf[:0]
	b.arena = b.arena[:0]
	return err
}

// RunShards launches per-shard goroutines pumping into sink. Returns
// a stop function that drains and joins all shards.
func (r *Reader) RunShards(sink ShardSink) (func(), error) {
	builders := make([]*batchBuilder, len(r.shardReaders))
	for i := range builders {
		builders[i] = newBatchBuilder(i, sink)
	}
	return r.run(func(i int, raw []byte) error {
		pkt, err := ParseRawSample(raw)
		if err != nil {
			r.session.stats.Malformed.Add(1)
			return nil
		}
		if LegacyTimestamp {
			pkt.Timestamp = time.Now()
		}
		builders[i].add(pkt)
		return nil
	}, func(i int) error { return builders[i].flush() })
}

func (r *Reader) Stats() *SessionStats {
	if r.session == nil {
		return nil
	}
	return &r.session.stats
}
func (r *Reader) Err() error { return r.session.Err() }

func (r *Reader) run(sink RawShardSink, flush func(int) error) (func(), error) {
	if len(r.shardReaders) == 0 {
		return nil, errors.New("no shards")
	}
	cpus, err := readerCPUs(len(r.shardReaders))
	if err != nil {
		return nil, err
	}
	r.session = newShardSession(r.cursors)
	s := r.session
	for i, rr := range r.shardReaders {
		s.done.Add(1)
		go func(i int, rr *ringbuf.Reader) {
			defer s.done.Done()
			defer func() { s.fail(rr.Close()) }()
			pinReaderToCPU(cpus[i])
			var rec ringbuf.Record
			for {
				draining := s.stopping()
				// Bounded polling also observes NO_WAKEUP submissions. Once producers
				// quiesce, a past deadline drains all committed records before EOF.
				if draining {
					rr.SetDeadline(pollPastDeadline)
				} else {
					rr.SetDeadline(time.Now().Add(time.Millisecond))
				}
				n := 0
				for n < batchSize {
					err := rr.ReadInto(&rec)
					if err != nil {
						if errors.Is(err, os.ErrDeadlineExceeded) {
							break
						}
						s.fail(err)
						s.fail(flush(i))
						return
					}
					n++
					s.stats.Consumed.Add(1)
					if draining {
						s.stats.DrainedAtStop.Add(1)
					}
					s.fail(sink(i, rec.RawSample))
					rr.SetDeadline(pollPastDeadline)
				}
				s.fail(flush(i))
				if draining && r.cursors[i].Consumed() >= s.final[i] {
					return
				}
			}
		}(i, rr)
	}
	return s.stop, nil
}

// RawShardSink processes a single ringbuf record for one per-CPU
// shard. rec.RawSample is reused on the next ReadInto, so the sink
// must finish writing or copying the bytes before returning.
type RawShardSink func(shardIdx int, raw []byte) error

// RunRawShards is the raw-bytes twin of RunShards: per-shard
// goroutines pump ringbuf records into rawSink without ParseRawSample
// or batch buffering.
func (r *Reader) RunRawShards(sink RawShardSink) (func(), error) {
	return r.run(sink, func(int) error { return nil })
}

// FastShardedReader is the cilium/ebpf-bypass variant of the
// sharded raw-dump reader. It mmaps each per-CPU ringbuf directly
// and walks records in a batch per epoll wake, instead of paying
// the per-record cost of ringbuf.Reader.ReadInto. Use via
// NewFastShardedReader + RunRawShardsFast; not compatible with
// NewShardedReader on the same maps (they would race on the
// consumer-position page).
type FastShardedReader struct {
	session *shardSession
	cursors []*fastrb.Cursor
	readers []*fastrb.Reader
}

// NewFastShardedReader mmaps each inner ringbuf map directly.
func NewFastShardedReader(inners []*ebpf.Map) (*FastShardedReader, error) {
	rs := make([]*fastrb.Reader, 0, len(inners))
	for i, m := range inners {
		r, err := fastrb.New(m.FD(), int(m.MaxEntries()))
		if err != nil {
			for _, prev := range rs {
				_ = prev.Close()
			}
			return nil, fmt.Errorf("inner %d: %w", i, err)
		}
		rs = append(rs, r)
	}
	r := &FastShardedReader{readers: rs}
	for _, m := range inners {
		c, err := fastrb.NewCursor(m.FD())
		if err != nil {
			for _, rr := range rs {
				_ = rr.Close()
			}
			for _, c := range r.cursors {
				_ = c.Close()
			}
			return nil, err
		}
		r.cursors = append(r.cursors, c)
	}
	return r, nil
}

// RunShardsFast is the parsed-Packet twin of RunRawShardsFast.
// Each shard goroutine drains its mmap'd ringbuf, runs every record
// through ParseRawSample, batches into 256-Packet groups, and hands
// the batch to sink. Used by the pcap-ng capture loop so the
// fast-reader path is no longer raw-dump-only.
//
// Compared to RunShards (cilium/ebpf based): same batch semantics,
// but the read side avoids the per-record ringbuf.Record alloc and
// the epoll wakeup the kernel skips when BPF_RB_NO_WAKEUP is set on
// the producer side.
func (r *FastShardedReader) RunShardsFast(sink ShardSink) (func(), error) {
	builders := make([]*batchBuilder, len(r.readers))
	for i := range builders {
		builders[i] = newBatchBuilder(i, sink)
	}
	return r.run(func(i int, raw []byte) error {
		pkt, err := ParseRawSample(raw)
		if err != nil {
			r.session.stats.Malformed.Add(1)
			return nil
		}
		if LegacyTimestamp {
			pkt.Timestamp = time.Now()
		}
		builders[i].add(pkt)
		return nil
	}, func(i int) error { return builders[i].flush() })
}

func (r *FastShardedReader) Stats() *SessionStats {
	if r.session == nil {
		return nil
	}
	return &r.session.stats
}
func (r *FastShardedReader) Err() error { return r.session.Err() }

func (r *FastShardedReader) RunRawShardsFast(sink RawShardSink) (func(), error) {
	return r.run(sink, func(int) error { return nil })
}

func (r *FastShardedReader) run(sink RawShardSink, flush func(int) error) (func(), error) {
	if len(r.readers) == 0 {
		return nil, errors.New("no shards")
	}
	cpus, err := readerCPUs(len(r.readers))
	if err != nil {
		return nil, err
	}
	r.session = newShardSession(r.cursors)
	s := r.session
	if LatencySamplePeriod > 0 {
		LatencySamples = make([][]int64, len(r.readers))
	}
	for i, rr := range r.readers {
		s.done.Add(1)
		go func(i int, rr *fastrb.Reader) {
			defer s.done.Done()
			defer func() { s.fail(rr.Close()) }()
			pinReaderToCPU(cpus[i])
			var seen int64
			var samples []int64
			defer func() {
				if LatencySamplePeriod > 0 {
					LatencySamples[i] = samples
				}
			}()
			for {
				draining := s.stopping()
				if !draining && !BusyPoll {
					if _, err := rr.WaitForData(shardPollTimeoutMs); err != nil {
						s.fail(err)
						return
					}
				}
				rr.ReadBatch(func(raw []byte) {
					s.stats.Consumed.Add(1)
					if draining {
						s.stats.DrainedAtStop.Add(1)
					}
					s.fail(sink(i, raw))
					if LatencySamplePeriod > 0 {
						if seen%LatencySamplePeriod == 0 && len(raw) >= 8 {
							samples = append(samples, time.Now().UnixNano()-int64(WallOffsetNs)-int64(RecordKernelTs(raw)))
						}
						seen++
					}
				})
				s.fail(flush(i))
				if draining && r.cursors[i].Consumed() >= s.final[i] {
					return
				}
			}
		}(i, rr)
	}
	return s.stop, nil
}
