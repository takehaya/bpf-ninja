package output

import (
	"bufio"
	"bytes"
	"container/heap"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Hook shards have a fixed, identical interface table. Preserve complete EPBs,
// including packet ids, instead of passing them through NgReader (which drops
// EPB options). Only this writer's little-endian, nanosecond layout is accepted.
const (
	hookDescriptionPrefix = "bpf-ninja capture site_id="
	maxHookBlockSize      = 1 << 20
	hookEPBHeaderSize     = 28
)

func detectHookLayout(paths []string) ([]string, layers.LinkType, error) {
	var linkType layers.LinkType
	var hooks []string
	var legacy bool
	for _, path := range paths {
		names, lt, err := readHookLayout(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, 0, fmt.Errorf("reading shard %s layout: %w", path, err)
		}
		if len(names) == 0 {
			legacy = true
		} else if len(hooks) == 0 {
			hooks, linkType = names, lt
		}
		if legacy && len(hooks) > 0 {
			return nil, 0, fmt.Errorf("cannot merge legacy and hook capture shards")
		}
	}
	return hooks, linkType, nil
}

func readHookLayout(path string) ([]string, layers.LinkType, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return nil, 0, err
	}
	first, err := r.Interface(0)
	if err != nil || !strings.HasPrefix(first.Description, hookDescriptionPrefix) {
		return nil, 0, nil
	}
	if _, _, err := r.ReadPacketData(); err != nil && !errors.Is(err, io.EOF) {
		return nil, 0, err
	}
	names := make([]string, r.NInterfaces())
	for i := range names {
		intf, err := r.Interface(i)
		if err != nil {
			return nil, 0, err
		}
		names[i] = intf.Name
	}
	return names, first.LinkType, nil
}

// readHookBlock bounds allocation to one MiB, including headers and options. A malformed/truncated shard remains available on failure.
func readHookBlock(r io.Reader) ([]byte, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.LittleEndian.Uint32(hdr[4:]))
	if n < 12 || n%4 != 0 || n > maxHookBlockSize {
		return nil, fmt.Errorf("invalid hook block length %d", n)
	}
	b := make([]byte, n)
	copy(b, hdr[:])
	if _, err := io.ReadFull(r, b[8:]); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if binary.LittleEndian.Uint32(b[n-4:]) != uint32(n) {
		return nil, fmt.Errorf("hook block lengths disagree")
	}
	return b, nil
}

func mergeHookFiles(paths []string, outPath string, cfg Config) (err error) {
	var header bytes.Buffer
	w := &Writer{cfg: cfg}
	if err := w.initHooks(&header); err != nil {
		return err
	}
	var files []*os.File
	var readers []*bufio.Reader
	var readerPaths []string
	defer func() {
		for _, f := range files {
			err = errors.Join(err, f.Close())
		}
	}()
	for _, path := range paths {
		f, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		files = append(files, f)
		r := bufio.NewReaderSize(f, 64<<10)
		got := make([]byte, header.Len())
		if _, err := io.ReadFull(r, got); err != nil {
			return fmt.Errorf("hook shard %s header: %w", path, err)
		}
		if !bytes.Equal(got, header.Bytes()) {
			return fmt.Errorf("hook shard %s interface table differs", path)
		}
		readers = append(readers, r)
		readerPaths = append(readerPaths, path)
	}
	out, err := os.Create(outPath + ".merging")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(outPath + ".merging")
		}
		if out != nil {
			err = errors.Join(err, out.Close())
		}
	}()
	dest := bufio.NewWriterSize(out, fileBufSize)
	if _, err := dest.Write(header.Bytes()); err != nil {
		return err
	}
	next := func(i int) (mergeItem, error) {
		b, err := readHookBlock(readers[i])
		if err != nil {
			return mergeItem{}, err
		}
		if binary.LittleEndian.Uint32(b) != blkEPB || len(b) < EPBSizeID(0) {
			return mergeItem{}, fmt.Errorf("expected hook EPB")
		}
		iface := binary.LittleEndian.Uint32(b[8:])
		caplen := int(binary.LittleEndian.Uint32(b[20:]))
		if int(iface) >= len(cfg.Hooks) || caplen > 65535 || len(b) != EPBSizeID(caplen) {
			return mergeItem{}, fmt.Errorf("invalid hook EPB interface or length")
		}
		opt := hookEPBHeaderSize + (caplen+3)&^3
		if binary.LittleEndian.Uint16(b[opt:]) != epbOptPacketID || binary.LittleEndian.Uint16(b[opt+2:]) != 8 || binary.LittleEndian.Uint64(b[opt+4:]) == 0 || binary.LittleEndian.Uint32(b[opt+12:]) != 0 {
			return mergeItem{}, fmt.Errorf("invalid hook packet id option")
		}
		ts := uint64(binary.LittleEndian.Uint32(b[12:]))<<32 | uint64(binary.LittleEndian.Uint32(b[16:]))
		return mergeItem{ts: time.Unix(0, int64(ts)), block: b, idx: i}, nil
	}
	h := &mergeHeap{}
	for i := range readers {
		it, err := next(i)
		if err == nil {
			heap.Push(h, it)
		} else if !errors.Is(err, io.EOF) {
			return fmt.Errorf("reading hook shard %s: %w", readerPaths[i], err)
		}
	}
	for h.Len() > 0 {
		it := heap.Pop(h).(mergeItem)
		if _, err := dest.Write(it.block); err != nil {
			return err
		}
		n, err := next(it.idx)
		if err == nil {
			heap.Push(h, n)
		} else if !errors.Is(err, io.EOF) {
			return fmt.Errorf("reading hook shard %s: %w", readerPaths[it.idx], err)
		}
	}
	if err := dest.Flush(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		out = nil
		return err
	}
	out = nil
	if err := os.Rename(outPath+".merging", outPath); err != nil {
		return err
	}
	committed = true
	return nil
}
