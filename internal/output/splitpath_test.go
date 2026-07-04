package output

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"
)

func TestTagShardPath(t *testing.T) {
	cases := []struct {
		base       string
		shard      int
		tag        uint32
		wantShard  string
		wantMerged string
	}{
		{"out.pcap", 0, 1, "out.cpu0.1.pcap", "out.1.pcap"},
		{"out.pcap", 3, 42, "out.cpu3.42.pcap", "out.42.pcap"},
		{"/tmp/cap.pcapng", 2, 7, "/tmp/cap.cpu2.7.pcapng", "/tmp/cap.7.pcapng"},
		{"noext", 1, 5, "noext.cpu1.5", "noext.5"}, // no extension: tag appended
	}
	for _, c := range cases {
		if got := TagShardPath(c.base, c.shard, c.tag); got != c.wantShard {
			t.Errorf("TagShardPath(%q,%d,%d) = %q, want %q", c.base, c.shard, c.tag, got, c.wantShard)
		}
		if got := TagMergedPath(c.base, c.tag); got != c.wantMerged {
			t.Errorf("TagMergedPath(%q,%d) = %q, want %q", c.base, c.tag, got, c.wantMerged)
		}
	}
}

// TestMergeTagShards writes per-CPU shards for two tags and checks that each
// tag's shards merge into its own <base>.<tag> file, time-ordered, while an
// unrelated .cpuN file (no tag) is ignored.
func TestMergeTagShards(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "out.pcap")
	epoch := time.Unix(1700000000, 0).UTC()

	// tag 1: interleaved across two shards -> merged order 1,2,3,4.
	writeShardFile(t, TagShardPath(base, 0, 1), epoch, []int{1, 3})
	writeShardFile(t, TagShardPath(base, 1, 1), epoch, []int{2, 4})
	// tag 2: a single shard.
	writeShardFile(t, TagShardPath(base, 0, 2), epoch, []int{5})
	// A plain (non-tag) shard file must not be swept into any tag.
	writeShardFile(t, base+".cpu0", epoch, []int{9})

	if err := MergeTagShards(base, false); err != nil {
		t.Fatalf("MergeTagShards: %v", err)
	}

	readOrder := func(path string) []int {
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		defer func() { _ = f.Close() }()
		r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			t.Fatalf("NgReader %s: %v", path, err)
		}
		var order []int
		for {
			data, _, err := r.ReadPacketData()
			if err != nil {
				break
			}
			order = append(order, int(data[0]))
		}
		return order
	}

	if got := readOrder(TagMergedPath(base, 1)); !equalInts(got, []int{1, 2, 3, 4}) {
		t.Errorf("tag 1 merged order = %v, want [1 2 3 4]", got)
	}
	if got := readOrder(TagMergedPath(base, 2)); !equalInts(got, []int{5}) {
		t.Errorf("tag 2 merged order = %v, want [5]", got)
	}
	// The plain .cpu0 shard should not have produced a tag-merged file for
	// some bogus tag, and out.9.pcap must not exist.
	if _, err := os.Stat(TagMergedPath(base, 9)); err == nil {
		t.Errorf("plain .cpu0 shard was wrongly merged as a tag")
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
