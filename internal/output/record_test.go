package output

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/record"
)

var updateRecordGolden = flag.Bool("update-record-golden", false, "rewrite testdata/record-filter.pcapng")

// Site 1 records value->pol_rc, site 2 nothing; neither tracks runs.
var recordLayout = &record.Layout{Mode: record.ModeFilter, Fields: []record.Field{{Name: "value->pol_rc", Size: 4, Deref: true}}}

func recordConfig() Config {
	return Config{Hooks: []string{"ninja_pol", "ninja_other"}, Records: []*record.Layout{recordLayout, nil}, NoRunIDs: true}
}

func recordBlock(rc uint64) []byte {
	b := make([]byte, recordLayout.Size())
	binary.NativeEndian.PutUint16(b, uint16(len(b)))
	b[record.OffVersion], b[record.OffKind] = record.BlockVersion, record.KindFilter
	binary.NativeEndian.PutUint32(b[record.OffValid:], 1)
	binary.NativeEndian.PutUint64(b[record.HeaderSize:], rc)
	return b
}

func writeRecords(t *testing.T, path string, cpu int64) {
	t.Helper()
	w, err := NewWriter(path, recordConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []capture.Packet{
		{Timestamp: time.Unix(100, 10+cpu), Data: []byte{0x45, 1, 2}, SiteID: 1, Record: recordBlock(2)},
		{Timestamp: time.Unix(100, 20+cpu), Data: []byte{0x45}, SiteID: 2},
	} {
		if err := w.Write(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

// epbComments walks a little-endian pcapng file without the writer's code
// and returns each EPB's opt_comment ("" when it has none).
func epbComments(t *testing.T, b []byte) []string {
	t.Helper()
	var out []string
	for off := 0; off+12 <= len(b); off += int(binary.LittleEndian.Uint32(b[off+4:])) {
		blk := b[off : off+int(binary.LittleEndian.Uint32(b[off+4:]))]
		if binary.LittleEndian.Uint32(blk) != blkEPB {
			continue
		}
		comment := ""
		for o := 28 + (int(binary.LittleEndian.Uint32(blk[20:]))+3)&^3; o < len(blk)-4; {
			code, n := binary.LittleEndian.Uint16(blk[o:]), int(binary.LittleEndian.Uint16(blk[o+2:]))
			if code == epbOptComment {
				comment = string(blk[o+4 : o+4+n])
			}
			o += 4 + (n+3)&^3
		}
		out = append(out, comment)
	}
	return out
}

func TestRecordComment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rec.pcapng")
	writeRecords(t, path, 0)
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "record-filter.pcapng")
	if *updateRecordGolden {
		if err := os.WriteFile(golden, got, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("record bytes changed (review, then -update-record-golden)\ngot=%x\nwant=%x", got, want)
	}
	if c := epbComments(t, got); len(c) != 2 || c[0] != "value->pol_rc=2" || c[1] != "" {
		t.Fatalf("comments %q", c)
	}
	w, err := NewWriter(filepath.Join(t.TempDir(), "bad.pcapng"), recordConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(capture.Packet{SiteID: 1}); err == nil {
		t.Fatal("record without its block accepted")
	}
	_ = w.Close()
}

func TestRecordMergeKeepsComments(t *testing.T) {
	base := filepath.Join(t.TempDir(), "out.pcapng")
	for cpu := range int64(2) {
		writeRecords(t, base+".cpu"+string(rune('0'+cpu)), cpu)
	}
	// An offline merge (no capture config) detects the layout from the files.
	if err := MergeShardFiles(base, 2, Config{}); err != nil {
		t.Fatal(err)
	}
	merged, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	if c := epbComments(t, merged); len(c) != 4 || c[0] != "value->pol_rc=2" || c[1] != "value->pol_rc=2" || c[2] != "" || c[3] != "" {
		t.Fatalf("merged comments %q", c)
	}
}

// entryBlock is an update hook's entry block for pols[2] = {30, 1002}.
func entryBlock(l *record.Layout) []byte {
	b := make([]byte, l.Size())
	ne := binary.NativeEndian
	ne.PutUint16(b, uint16(len(b)))
	b[record.OffVersion], b[record.OffKind] = record.BlockVersion, record.KindEntry
	ne.PutUint32(b[record.OffValid:], record.ValidSite|record.ValidStatus|record.ValidKey|record.ValidValue)
	ne.PutUint32(b[record.EntryOffSite:], 24)
	ne.PutUint16(b[record.EntryOffKeyLen:], uint16(l.Key.Len))
	ne.PutUint16(b[record.EntryOffValueLen:], uint16(l.Value.Len))
	ne.PutUint32(b[record.EntryOffBytes:], 2)
	ne.PutUint32(b[record.EntryOffBytes+4:], 30)
	ne.PutUint16(b[record.EntryOffBytes+8:], 1002)
	return b
}

func benchmarkWrite(b *testing.B, cfg Config, p capture.Packet) {
	w, err := NewWriter(filepath.Join(b.TempDir(), "b.pcapng"), cfg)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	pkts := []capture.Packet{p}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := w.WriteBatch(pkts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteRecordFilter(b *testing.B) {
	benchmarkWrite(b, recordConfig(), capture.Packet{Timestamp: time.Unix(1, 0), Data: []byte{0x45, 1, 2}, SiteID: 1, Record: recordBlock(2)})
}

// BenchmarkWriteRecordEntry decodes a whole struct key and value.
func BenchmarkWriteRecordEntry(b *testing.B) {
	u32, u16 := &btf.Int{Name: "__u32", Size: 4}, &btf.Int{Name: "__u16", Size: 2}
	l := &record.Layout{Mode: record.ModeEntry,
		Site:   record.Scalar{Name: "site", ParamIndex: 1, Size: 4},
		Status: record.Scalar{Name: "status", ParamIndex: 4, Size: 8},
		Key: record.Bytes{Name: "key", ParamIndex: 2, Pointer: true, Size: 4, Len: 4,
			Type: &btf.Struct{Name: "pol_key", Size: 4, Members: []btf.Member{{Name: "policy_index", Type: u32}}}},
		Value: record.Bytes{Name: "value", ParamIndex: 3, Pointer: true, Size: 8, Len: 8,
			Type: &btf.Struct{Name: "pol", Size: 8, Members: []btf.Member{
				{Name: "pol_rc", Type: u32}, {Name: "port", Type: u16, Offset: 32}, {Name: "pad", Type: u16, Offset: 48}}}},
	}
	if c, err := l.Comment(entryBlock(l)); err != nil || c != "site=24 status=0x0000000000000000 key->policy_index=2 value->pol_rc=30 value->port=1002 value->pad=0" {
		b.Fatalf("comment %q %v", c, err)
	}
	cfg := Config{Hooks: []string{"ninja_pol"}, Records: []*record.Layout{l}, NoRunIDs: true}
	benchmarkWrite(b, cfg, capture.Packet{Timestamp: time.Unix(1, 0), Data: []byte{0x45, 1, 2}, SiteID: 1, Record: entryBlock(l)})
}

func BenchmarkWritePlain(b *testing.B) {
	benchmarkWrite(b, Config{}, capture.Packet{Timestamp: time.Unix(1, 0), Data: []byte{0x45, 1, 2}})
}

func TestCheckHookOptions(t *testing.T) {
	le := binary.LittleEndian
	opt := func(code, n uint16, val []byte) []byte {
		b := make([]byte, 4)
		le.PutUint16(b, code)
		le.PutUint16(b[2:], n)
		b = append(b, val...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	id := func(v uint64) []byte { x := make([]byte, 8); le.PutUint64(x, v); return opt(epbOptPacketID, 8, x) }
	comment := opt(epbOptComment, 3, []byte("abc"))
	end := opt(optEndOfOpt, 0, nil)
	ok := func(parts ...[]byte) []byte {
		var b []byte
		for _, p := range parts {
			b = append(b, p...)
		}
		return b
	}
	for _, c := range []struct {
		name   string
		opts   []byte
		hasID  bool
		reject string
	}{
		{"none", nil, false, ""},
		{"id-only", ok(id(5), end), true, ""},
		{"id-comment", ok(id(5), comment, end), true, ""},
		{"comment-only", ok(comment, end), false, ""},
		{"zero-id", ok(id(0), end), false, "invalid epb_packetid"},
		{"empty-comment", ok(opt(epbOptComment, 0, nil), end), false, "empty opt_comment"},
		{"comment-before-id", ok(comment, id(5), end), false, "epb_packetid after opt_comment"},
		{"two-comments", ok(comment, comment, end), false, "duplicate opt_comment"},
		{"two-ids", ok(id(5), id(6), end), false, "duplicate epb_packetid"},
		{"no-end", ok(id(5)), false, "missing opt_endofopt"},
		{"unknown", ok(opt(99, 4, []byte{1, 2, 3, 4}), end), false, "unexpected hook EPB option 99"},
	} {
		hasID, err := checkHookOptions(c.opts)
		if c.reject != "" {
			if err == nil || !strings.Contains(err.Error(), c.reject) {
				t.Errorf("%s: err %v, want %q", c.name, err, c.reject)
			}
			continue
		}
		if err != nil || hasID != c.hasID {
			t.Errorf("%s: hasID=%v err=%v", c.name, hasID, err)
		}
	}
}

// An exit capture puts return=0x%08x first, including at a site that
// records nothing else.
func TestRecordReturnFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exit.pcapng")
	cfg := recordConfig()
	cfg.RecordReturn = true
	w, err := NewWriter(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []capture.Packet{
		{Timestamp: time.Unix(1, 0), Data: []byte{1}, SiteID: 1, Action: 0xfffffffe, Record: recordBlock(2)},
		{Timestamp: time.Unix(1, 1), Data: []byte{2}, SiteID: 2, Action: 0},
	} {
		if err := w.Write(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if c := epbComments(t, b); len(c) != 2 || c[0] != "return=0xfffffffe value->pol_rc=2" || c[1] != "return=0x00000000" {
		t.Fatalf("comments %q", c)
	}
}

// A merge of shards whose run-id presence disagrees is refused.
func TestRecordMergeRunIDMismatch(t *testing.T) {
	base := filepath.Join(t.TempDir(), "mix.pcapng")
	// cpu0: records without run ids (the recording-capture shape).
	writeRecords(t, base+".cpu0", 0)
	// cpu1: a hook EPB that carries a packet id (the follow-run shape).
	cfg := Config{Hooks: []string{"ninja_pol", "ninja_other"}}
	w, err := NewWriter(base+".cpu1", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(capture.Packet{Timestamp: time.Unix(100, 5), Data: []byte{0x45}, SiteID: 1, PacketID: 7}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := MergeShardFiles(base, 2, Config{}); err == nil || !strings.Contains(err.Error(), "epb_packetid presence") {
		t.Fatalf("mixed run-id shards: %v", err)
	}
}

// A damaged record after a good one fails the batch but leaves the record
// already written as a readable, mergeable prefix (failBatch flushes it).
func TestRecordBadBlockAfterGood(t *testing.T) {
	base := filepath.Join(t.TempDir(), "bad.pcapng")
	w, err := NewWriter(base+".cpu0", recordConfig())
	if err != nil {
		t.Fatal(err)
	}
	good := capture.Packet{Timestamp: time.Unix(100, 10), Data: []byte{0x45, 1, 2}, SiteID: 1, Record: recordBlock(2)}
	bad := capture.Packet{Timestamp: time.Unix(100, 20), Data: []byte{0x45}, SiteID: 1, Record: recordBlock(3)[:4]}
	if err := w.WriteBatch([]capture.Packet{good, bad}); err == nil || !strings.Contains(err.Error(), "record block") {
		t.Fatalf("damaged block accepted: %v", err)
	}
	_ = w.Close() // returns the batch error again
	b, err := os.ReadFile(base + ".cpu0")
	if err != nil {
		t.Fatal(err)
	}
	if c := epbComments(t, b); len(c) != 1 || c[0] != "value->pol_rc=2" {
		t.Fatalf("prefix comments %q", c)
	}
	if err := MergeShardFiles(base, 1, Config{}); err != nil {
		t.Fatal(err)
	}
	merged, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	if c := epbComments(t, merged); len(c) != 1 || c[0] != "value->pol_rc=2" {
		t.Fatalf("merged prefix comments %q", c)
	}
}

// WriteHookPacket writes a comment up to the pcapng option limit and
// refuses a longer one.
func TestHookPacketCommentLimit(t *testing.T) {
	w, err := NewWriter(filepath.Join(t.TempDir(), "long.pcapng"), recordConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	if err := w.fastWriter.WriteHookPacket(time.Unix(1, 0), []byte{0x45}, 0, 0, bytes.Repeat([]byte("x"), 65535)); err != nil {
		t.Fatalf("65535-byte comment: %v", err)
	}
	if err := w.fastWriter.WriteHookPacket(time.Unix(1, 0), []byte{0x45}, 0, 0, bytes.Repeat([]byte("x"), 65536)); err == nil {
		t.Fatal("65536-byte comment accepted")
	}
}

// The tag-split merge keeps each tag's record comments.
func TestRecordTagSplitMerge(t *testing.T) {
	base := filepath.Join(t.TempDir(), "split.pcapng")
	for cpu := range 2 {
		for _, tag := range []uint32{1, 7} {
			writeRecords(t, TagShardPath(base, cpu, tag), int64(cpu))
		}
	}
	if err := MergeTagShards(base, Config{}, nil); err != nil {
		t.Fatal(err)
	}
	for _, tag := range []uint32{1, 7} {
		b, err := os.ReadFile(TagMergedPath(base, tag))
		if err != nil {
			t.Fatal(err)
		}
		if c := epbComments(t, b); len(c) != 4 || c[0] != "value->pol_rc=2" || c[1] != "value->pol_rc=2" || c[2] != "" || c[3] != "" {
			t.Fatalf("tag %d comments %q", tag, c)
		}
	}
}

// Build refuses a layout whose worst-case comment would overflow a pcapng
// option, so capture fails up front rather than on the first packet.
func TestRecordCommentBoundRejected(t *testing.T) {
	u32 := &btf.Int{Name: "__u32", Size: 4}
	var members []btf.Member
	for i := 0; i < 4096; i++ { // 4096 one-byte fields named "mNNNN"
		members = append(members, btf.Member{Name: fmt.Sprintf("m%04d", i), Type: &btf.Int{Size: 1}, Offset: btf.Bits(i * 8)})
	}
	_ = u32
	wide := &btf.Struct{Name: "wide", Size: 4096, Members: members}
	l := &record.Layout{Mode: record.ModeEntry, Site: record.Scalar{ParamIndex: -1}, Status: record.Scalar{ParamIndex: -1},
		Key:   record.Bytes{Name: "key", ParamIndex: -1},
		Value: record.Bytes{Name: "value", ParamIndex: 3, Pointer: true, Size: 4096, Len: 4096, Type: &btf.Const{Type: wide}}}
	if n := l.MaxCommentLen(); n <= record.MaxCommentBytes {
		t.Fatalf("wide struct bound %d did not exceed %d", n, record.MaxCommentBytes)
	}
}

// A write that fails because the disk is full reports its cause once, as
// on main, although failBatch flushes after it.
func TestWriteErrorReportedOnce(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("no /dev/full")
	}
	w, err := NewWriter("/dev/full", Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	pkt := []capture.Packet{{Timestamp: time.Unix(1, 0), Data: make([]byte, 60000)}}
	for range 1000 {
		if err = w.WriteBatch(pkt); err != nil {
			break
		}
	}
	if err == nil || strings.Count(err.Error(), "no space left on device") != 1 {
		t.Fatalf("write error %q", err)
	}
}
