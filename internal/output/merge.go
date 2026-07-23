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
)

type mergeItem struct {
	ts       time.Time
	data     []byte
	srcIface int // source-file interface index; mapped to the output by name (fexit)
	idx      int // which shard reader to pull the next packet from
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
func MergeShardFiles(basePath string, numShards int, cfg Config) error {
	inPaths := make([]string, numShards)
	for i := range numShards {
		inPaths[i] = fmt.Sprintf("%s.cpu%d", basePath, i)
	}
	return mergeFiles(inPaths, basePath, cfg)
}

// mergeFiles k-way merges the given pcap-ng input files (each already in
// timestamp order) into a single time-ordered pcap-ng at outPath, written
// atomically via a temp file + rename. Missing or unreadable inputs are
// skipped so a crashed shard never aborts the merge. Inputs are left in
// place. Shared by MergeShardFiles, the tag-split merge, and the `merge`
// subcommand.
func mergeFiles(inPaths []string, outPath string, cfg Config) error {
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

	// Exit-mode merge with no configured verdict interfaces (the
	// standalone `bpf-ninja merge` subcommand does not know the hook):
	// seed the output layout from the first input's interface table so
	// the merged file keeps the shards' interface names whatever hook
	// wrote them.
	if cfg.IsFexit && len(cfg.Actions) == 0 && len(readers) > 0 {
		r := readers[0]
		for i := range r.NInterfaces() {
			intf, ierr := r.Interface(i)
			if ierr != nil {
				break
			}
			cfg.Actions = append(cfg.Actions, ActionName{Value: uint32(i), Name: intf.Name})
			if cfg.LinkType == 0 {
				cfg.LinkType = intf.LinkType
			}
		}
	}
	if cfg.IsFexit && len(cfg.Actions) == 0 {
		// Nothing usable to seed from (all inputs missing/unreadable):
		// behave like the readerless merge below and produce no output.
		return nil
	}

	// Write to a temp file and rename on success so a mid-merge failure
	// (disk full / short write) never leaves a truncated base file over the
	// still-valid per-CPU shards — the merge is atomic.
	tmpPath := outPath + ".merging"
	out, err := NewWriter(tmpPath, cfg)
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

	// Exit-mode interface mapping is by NAME, not index: each shard may
	// have lazily added unknown-verdict interfaces in its own encounter
	// order, so the same index can mean different verdicts across shards.
	// ifaceMap caches source-index → output-id per reader.
	ifaceMap := make([]map[int]int, len(readers))
	outIface := func(rIdx, srcIdx int) int {
		if !cfg.IsFexit {
			return 0
		}
		m := ifaceMap[rIdx]
		if m == nil {
			m = map[int]int{}
			ifaceMap[rIdx] = m
		}
		if id, ok := m[srcIdx]; ok {
			return id
		}
		id := 0
		if intf, ierr := readers[rIdx].Interface(srcIdx); ierr == nil {
			id = out.ifaceIDByName(intf.Name)
		}
		m[srcIdx] = id
		return id
	}

	for h.Len() > 0 {
		it := heap.Pop(h).(mergeItem)
		if err := out.writePacketIface(it.ts, it.data, outIface(it.idx, it.srcIface)); err != nil {
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
	return mergeItem{ts: ci.Timestamp, data: *buf, srcIface: ci.InterfaceIndex, idx: idx}, true
}
