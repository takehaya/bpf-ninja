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
	ts     time.Time
	data   []byte
	action uint32 // source interface index = XDP action (fexit); preserved on write
	idx    int    // which shard reader to pull the next packet from
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
	inPaths := make([]string, numShards)
	for i := range numShards {
		inPaths[i] = fmt.Sprintf("%s.cpu%d", basePath, i)
	}
	return mergeFiles(inPaths, basePath, isFexit)
}

// mergeFiles k-way merges the given pcap-ng input files (each already in
// timestamp order) into a single time-ordered pcap-ng at outPath, written
// atomically via a temp file + rename. Missing or unreadable inputs are
// skipped so a crashed shard never aborts the merge. Inputs are left in
// place. Shared by MergeShardFiles, the tag-split merge, and the `merge`
// subcommand.
func mergeFiles(inPaths []string, outPath string, isFexit bool) error {
	var closers []*os.File
	var readers []*pcapgo.NgReader
	defer func() {
		for _, f := range closers {
			_ = f.Close()
		}
	}()

	for _, p := range inPaths {
		f, err := os.Open(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("opening shard %s: %w", p, err)
		}
		r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			// A truncated / 0-byte shard (e.g. from a crash mid-write)
			// shouldn't abort the whole merge — skip it, as documented.
			_ = f.Close()
			continue
		}
		closers = append(closers, f)
		readers = append(readers, r)
	}

	// Write to a temp file and rename on success so a mid-merge failure
	// (disk full / short write) never leaves a truncated base file over the
	// still-valid per-CPU shards — the merge is atomic.
	tmpPath := outPath + ".merging"
	out, err := NewWriter(tmpPath, isFexit)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = out.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	// One reusable buffer per shard. The heap holds at most one item per
	// shard at a time, and a shard's next packet is only read after its
	// current item has been popped and written, so overwriting the buffer
	// is safe and avoids a per-packet allocation across the whole merge.
	bufs := make([][]byte, len(readers))
	h := &mergeHeap{}
	for i, r := range readers {
		if it, ok := nextItem(r, i, &bufs[i]); ok {
			heap.Push(h, it)
		}
	}

	for h.Len() > 0 {
		it := heap.Pop(h).(mergeItem)
		// Action carries the source interface index so fexit merges keep
		// the per-action interface (xdp:PASS/DROP/...); output.Writer maps
		// action->interface identically to how the shards were written.
		if err := out.Write(capture.Packet{Timestamp: it.ts, Data: it.data, Action: it.action}); err != nil {
			return fmt.Errorf("writing merged packet: %w", err)
		}
		if next, ok := nextItem(readers[it.idx], it.idx, &bufs[it.idx]); ok {
			heap.Push(h, next)
		}
	}

	// Flush+close the temp before renaming so all bytes are on disk; a
	// close (flush) failure must fail the merge, not silently truncate.
	if err := out.Close(); err != nil {
		return fmt.Errorf("closing merged file: %w", err)
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		return fmt.Errorf("renaming merged file into place: %w", err)
	}
	committed = true
	return nil
}

// nextItem reads the next packet from a shard reader into the shard's
// reusable buffer *buf (grown as needed). Returns ok=false at EOF (or on
// any read error, which ends that shard's contribution). The bytes are
// copied out because pcapgo reuses its own internal read buffer.
func nextItem(r *pcapgo.NgReader, idx int, buf *[]byte) (mergeItem, bool) {
	data, ci, err := r.ReadPacketData()
	if err != nil {
		return mergeItem{}, false
	}
	if cap(*buf) < len(data) {
		*buf = make([]byte, len(data))
	} else {
		*buf = (*buf)[:len(data)]
	}
	copy(*buf, data)
	return mergeItem{ts: ci.Timestamp, data: *buf, action: uint32(ci.InterfaceIndex), idx: idx}, true
}
