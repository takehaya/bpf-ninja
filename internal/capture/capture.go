// Package capture reads packets from the BPF ringbuf transport.
package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
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

// SplitCoreRX, when > 0, puts the fast-reader in split-core mode: it
// assumes RX/capture is confined to cores 0..SplitCoreRX-1 (the caller
// sets the NIC queue count to SplitCoreRX via `ethtool -L`), runs only
// the first SplitCoreRX shard readers, and pins reader i to core
// SplitCoreRX+i — the upper core half — so a --busy-poll spin does not
// steal cycles from the RX softirqs. Set via --rx-cores.
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

// pinReaderToCPU pins the calling goroutine's OS thread to cpu. Best-
// effort: ignores SchedSetaffinity errors (e.g. cgroup restrictions).
// LockOSThread without a matching Unlock terminates the thread when
// the goroutine exits, keeping the pinned affinity from leaking back
// into the runtime's thread pool.
func pinReaderToCPU(cpu int) {
	if DisableCPUAffinity {
		return
	}
	runtime.LockOSThread()
	var set unix.CPUSet
	set.Set(cpu)
	_ = unix.SchedSetaffinity(0, &set)
}

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
	Action    uint32 // XDP action (fexit only)
	Mode      uint8  // 0=entry(fentry), 1=exit(fexit), 2=xdp-native
	CapLen    uint16 // bytes the BPF side actually copied into Data
	Tag       uint32 // set-map value of the matched entry (0 when no set matched)
}

// XDP actions for display.
var XDPActionNames = map[uint32]string{
	0: "ABORTED",
	1: "DROP",
	2: "PASS",
	3: "TX",
	4: "REDIRECT",
}

// Reader reads captured packets from the ringbuf.
type Reader struct {
	reader *ringbuf.Reader
	rec    ringbuf.Record

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

// full reports whether the batch has reached batchSize, signalling the
// drain loop to stop and flush.
func (b *batchBuilder) full() bool { return len(b.buf) >= cap(b.buf) }

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
func (b *batchBuilder) flush() {
	if len(b.buf) == 0 {
		return
	}
	_ = b.sink(b.shardIdx, b.buf)
	b.buf = b.buf[:0]
	b.arena = b.arena[:0]
}

// RunShards launches per-shard goroutines pumping into sink. Returns
// a stop function that drains and joins all shards.
func (r *Reader) RunShards(sink ShardSink) (stop func(), err error) {
	if len(r.shardReaders) == 0 {
		return nil, errors.New("no shards")
	}
	stopCh := make(chan struct{})
	doneCh := make(chan struct{}, len(r.shardReaders))
	for idx, rr := range r.shardReaders {
		go func(shardIdx int, rr *ringbuf.Reader) {
			pinReaderToCPU(shardIdx)
			defer func() { doneCh <- struct{}{} }()
			bb := newBatchBuilder(shardIdx, sink)
			var rec ringbuf.Record
			pollPast := time.Unix(1, 0)
			for {
				select {
				case <-stopCh:
					return
				default:
				}
				if err := rr.ReadInto(&rec); err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					continue
				}
				now := time.Now()
				if pkt, perr := ParseRawSample(rec.RawSample); perr == nil {
					if LegacyTimestamp {
						pkt.Timestamp = now
					}
					bb.add(pkt)
				}
				rr.SetDeadline(pollPast)
				for !bb.full() {
					if err := rr.ReadInto(&rec); err != nil {
						break
					}
					pkt, perr := ParseRawSample(rec.RawSample)
					if perr != nil {
						continue
					}
					if LegacyTimestamp {
						pkt.Timestamp = now
					}
					bb.add(pkt)
				}
				rr.SetDeadline(time.Time{})
				bb.flush()
			}
		}(idx, rr)
	}
	stop = func() {
		close(stopCh)
		for _, rr := range r.shardReaders {
			_ = rr.Close()
		}
		for range r.shardReaders {
			<-doneCh
		}
	}
	return stop, nil
}

// RawShardSink processes a single ringbuf record for one per-CPU
// shard. rec.RawSample is reused on the next ReadInto, so the sink
// must finish writing or copying the bytes before returning.
type RawShardSink func(shardIdx int, raw []byte) error

// RunRawShards is the raw-bytes twin of RunShards: per-shard
// goroutines pump ringbuf records into rawSink without ParseRawSample
// or batch buffering.
func (r *Reader) RunRawShards(rawSink RawShardSink) (stop func(), err error) {
	if len(r.shardReaders) == 0 {
		return nil, errors.New("no shards")
	}
	stopCh := make(chan struct{})
	doneCh := make(chan struct{}, len(r.shardReaders))
	for idx, rr := range r.shardReaders {
		go func(shardIdx int, rr *ringbuf.Reader) {
			pinReaderToCPU(shardIdx)
			defer func() { doneCh <- struct{}{} }()
			var rec ringbuf.Record
			for {
				select {
				case <-stopCh:
					return
				default:
				}
				if err := rr.ReadInto(&rec); err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					continue
				}
				_ = rawSink(shardIdx, rec.RawSample)
			}
		}(idx, rr)
	}
	stop = func() {
		close(stopCh)
		for _, rr := range r.shardReaders {
			_ = rr.Close()
		}
		for range r.shardReaders {
			<-doneCh
		}
	}
	return stop, nil
}

// FastShardedReader is the cilium/ebpf-bypass variant of the
// sharded raw-dump reader. It mmaps each per-CPU ringbuf directly
// and walks records in a batch per epoll wake, instead of paying
// the per-record cost of ringbuf.Reader.ReadInto. Use via
// NewFastShardedReader + RunRawShardsFast; not compatible with
// NewShardedReader on the same maps (they would race on the
// consumer-position page).
type FastShardedReader struct {
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
	return &FastShardedReader{readers: rs}, nil
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
func (r *FastShardedReader) RunShardsFast(sink ShardSink) (stop func(), err error) {
	if len(r.readers) == 0 {
		return nil, errors.New("no shards")
	}
	stopCh := make(chan struct{})
	doneCh := make(chan struct{}, len(r.readers))
	launched := 0
	for idx, rdr := range r.readers {
		// Split-core mode: only shards 0..SplitCoreRX-1 are fed (RX
		// confined to cores 0..SplitCoreRX-1 via ethtool -L); pin
		// their readers to the upper core half so the busy-poll spin
		// does not contend with the RX softirqs.
		if SplitCoreRX > 0 && idx >= SplitCoreRX {
			break
		}
		pinCPU := idx
		if SplitCoreRX > 0 {
			// Consumers occupy cores [SplitCoreRX, NumCPU); spread the
			// SplitCoreRX reader goroutines across them (more than one
			// per core when RX takes the larger share).
			consumerCores := max(runtime.NumCPU()-SplitCoreRX, 1)
			pinCPU = SplitCoreRX + idx%consumerCores
		}
		launched++
		go func(shardIdx, pinCPU int, rdr *fastrb.Reader) {
			pinReaderToCPU(pinCPU)
			defer func() { doneCh <- struct{}{} }()
			bb := newBatchBuilder(shardIdx, sink)
			for {
				select {
				case <-stopCh:
					return
				default:
				}
				if !BusyPoll {
					if _, err := rdr.WaitForData(shardPollTimeoutMs); err != nil {
						return
					}
				}
				now := time.Now()
				rdr.ReadBatch(func(record []byte) {
					pkt, perr := ParseRawSample(record)
					if perr != nil {
						return
					}
					if LegacyTimestamp {
						pkt.Timestamp = now
					}
					bb.add(pkt)
				})
				bb.flush()
			}
		}(idx, pinCPU, rdr)
	}
	stop = func() {
		close(stopCh)
		for i := 0; i < launched; i++ {
			<-doneCh
		}
		for _, rdr := range r.readers {
			_ = rdr.Close()
		}
	}
	return stop, nil
}

// RunRawShardsFast launches per-shard goroutines that mmap-read the
// ringbufs directly and call rawSink for each record. Shape matches
// RunRawShards so the caller can drop-in switch via a flag.
//
// When LatencySamplePeriod > 0, every Nth record per shard has its
// BPF-submit→reader-read latency (mono_now − record.kernel_ts)
// appended to LatencySamples[shardIdx]. The wall→mono offset is
// WallOffsetNs (init time); we re-derive mono_now per sample by
// subtracting it from time.Now().UnixNano() to avoid a
// clock_gettime syscall on the hot path.
func (r *FastShardedReader) RunRawShardsFast(rawSink RawShardSink) (stop func(), err error) {
	if len(r.readers) == 0 {
		return nil, errors.New("no shards")
	}
	if LatencySamplePeriod > 0 {
		LatencySamples = make([][]int64, len(r.readers))
	}
	stopCh := make(chan struct{})
	doneCh := make(chan struct{}, len(r.readers))
	launched := 0
	for idx, rdr := range r.readers {
		// Split-core mode: see RunShardsFast — only shards
		// 0..SplitCoreRX-1 run, pinned to the upper core half.
		if SplitCoreRX > 0 && idx >= SplitCoreRX {
			break
		}
		pinCPU := idx
		if SplitCoreRX > 0 {
			consumerCores := max(runtime.NumCPU()-SplitCoreRX, 1)
			pinCPU = SplitCoreRX + idx%consumerCores
		}
		launched++
		go func(shardIdx, pinCPU int, rdr *fastrb.Reader) {
			pinReaderToCPU(pinCPU)
			defer func() { doneCh <- struct{}{} }()
			var seen int64
			period := LatencySamplePeriod
			wallOffset := int64(WallOffsetNs)
			var localSamples []int64
			if period > 0 {
				localSamples = make([]int64, 0, 4096)
			}
			for {
				select {
				case <-stopCh:
					if period > 0 {
						LatencySamples[shardIdx] = localSamples
					}
					return
				default:
				}
				// Bounds stopCh-check latency under idle traffic;
				// on the saturated hot path EpollWait returns
				// immediately because data is always ready.
				if !BusyPoll {
					if _, err := rdr.WaitForData(shardPollTimeoutMs); err != nil {
						if period > 0 {
							LatencySamples[shardIdx] = localSamples
						}
						return
					}
				}
				rdr.ReadBatch(func(record []byte) {
					_ = rawSink(shardIdx, record)
					if period > 0 {
						if seen%period == 0 && len(record) >= 8 {
							monoNow := time.Now().UnixNano() - wallOffset
							recordTs := int64(binary.NativeEndian.Uint64(record[0:8]))
							localSamples = append(localSamples, monoNow-recordTs)
						}
						seen++
					}
				})
			}
		}(idx, pinCPU, rdr)
	}
	stop = func() {
		close(stopCh)
		for i := 0; i < launched; i++ {
			<-doneCh
		}
		for _, rdr := range r.readers {
			_ = rdr.Close()
		}
	}
	return stop, nil
}
