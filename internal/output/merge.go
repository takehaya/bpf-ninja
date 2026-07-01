// Merge per-CPU shard pcap-ng files (<base>.cpuN) into a single
// time-ordered pcap-ng at <base>. Each shard is written in timestamp
// order by its single producer, so a k-way merge across shards yields a
// globally ordered file without loading every packet into memory.
package output

import (
	"container/heap"
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket/pcapgo"

	"github.com/takehaya/xdp-ninja/internal/capture"
)

type mergeItem struct {
	ts   time.Time
	data []byte
	idx  int // which shard reader to pull the next packet from
}

// mergeHeap is a min-heap on packet timestamp.
type mergeHeap []mergeItem

func (h mergeHeap) Len() int           { return len(h) }
func (h mergeHeap) Less(i, j int) bool { return h[i].ts.Before(h[j].ts) }
func (h mergeHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *mergeHeap) Push(x any)        { *h = append(*h, x.(mergeItem)) }
func (h *mergeHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	*h = old[:n-1]
	return it
}

// MergeShardFiles merges <basePath>.cpu0..cpu(numShards-1) into a single
// time-ordered pcap-ng written to basePath. Missing or empty shard files
// are skipped. The shard files are left in place.
func MergeShardFiles(basePath string, numShards int, isFexit bool) error {
	var closers []*os.File
	var readers []*pcapgo.NgReader
	defer func() {
		for _, f := range closers {
			_ = f.Close()
		}
	}()

	for i := range numShards {
		p := fmt.Sprintf("%s.cpu%d", basePath, i)
		f, err := os.Open(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("opening shard %s: %w", p, err)
		}
		r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			_ = f.Close()
			return fmt.Errorf("reading shard %s: %w", p, err)
		}
		closers = append(closers, f)
		readers = append(readers, r)
	}

	out, err := NewWriter(basePath, isFexit)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	h := &mergeHeap{}
	for i, r := range readers {
		if it, ok := nextItem(r, i); ok {
			heap.Push(h, it)
		}
	}

	for h.Len() > 0 {
		it := heap.Pop(h).(mergeItem)
		if err := out.Write(capture.Packet{Timestamp: it.ts, Data: it.data}); err != nil {
			return fmt.Errorf("writing merged packet: %w", err)
		}
		if next, ok := nextItem(readers[it.idx], it.idx); ok {
			heap.Push(h, next)
		}
	}
	return nil
}

// nextItem reads the next packet from a shard reader. Returns ok=false at
// EOF (or on any read error, which ends that shard's contribution). The
// packet bytes are copied because pcapgo reuses its read buffer.
func nextItem(r *pcapgo.NgReader, idx int) (mergeItem, bool) {
	data, ci, err := r.ReadPacketData()
	if err != nil {
		return mergeItem{}, false
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return mergeItem{ts: ci.Timestamp, data: cp, idx: idx}, true
}
