package setmap

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// TestResizeGrowPreservesEntriesAndSchema is the end-to-end for `set
// resize`: create a composite-key set, add entries, grow it, and verify
// the replacement pin keeps the capacity, every entry, and the BTF key
// schema (field names, offsets, widths).
func TestResizeGrowPreservesEntriesAndSchema(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	pin := fmt.Sprintf("/sys/fs/bpf/bpfninja_resize_%d", os.Getpid())
	if err := Create(pin, "imsi:u64,teid:u32", "", 16); err != nil {
		t.Skipf("creating pinned set map (bpffs unavailable?): %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })

	def, err := Open(pin)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := range 3 {
		err := def.Add(map[string]string{
			"imsi": fmt.Sprintf("%d", 999990000000001+i),
			"teid": fmt.Sprintf("%d", 0x1000+i),
		}, uint64(i+1), 0)
		if err != nil {
			def.Close()
			t.Fatalf("Add: %v", err)
		}
	}
	wantFields := def.Fields
	var wantList strings.Builder
	if err := def.List(&wantList); err != nil {
		def.Close()
		t.Fatalf("List: %v", err)
	}
	def.Close()

	oldMax, copied, err := Resize(pin, 4096)
	if err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if oldMax != 16 || copied != 3 {
		t.Fatalf("Resize = (oldMax %d, copied %d), want (16, 3)", oldMax, copied)
	}

	got, err := Open(pin)
	if err != nil {
		t.Fatalf("Open after resize: %v", err)
	}
	t.Cleanup(got.Close)
	if got.Map.MaxEntries() != 4096 {
		t.Fatalf("max_entries = %d, want 4096", got.Map.MaxEntries())
	}
	if fmt.Sprintf("%+v", got.Fields) != fmt.Sprintf("%+v", wantFields) {
		t.Fatalf("key schema changed: %+v, want %+v", got.Fields, wantFields)
	}
	var gotList strings.Builder
	if err := got.List(&gotList); err != nil {
		t.Fatalf("List after resize: %v", err)
	}
	if sortedLines(gotList.String()) != sortedLines(wantList.String()) {
		t.Fatalf("entries changed:\n got: %q\nwant: %q", gotList.String(), wantList.String())
	}
	if _, err := os.Stat(pin + "_resize_tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary pin left behind: %v", err)
	}
}

// TestResizeShrinkBelowCountFails verifies a shrink below the live entry
// count is rejected up front and the original map survives untouched.
func TestResizeShrinkBelowCountFails(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	pin := fmt.Sprintf("/sys/fs/bpf/bpfninja_shrink_%d", os.Getpid())
	if err := Create(pin, "teid:u32", "", 16); err != nil {
		t.Skipf("creating pinned set map (bpffs unavailable?): %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })

	def, err := Open(pin)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := range 3 {
		if err := def.Add(map[string]string{"teid": fmt.Sprintf("%d", i+1)}, 1, 0); err != nil {
			def.Close()
			t.Fatalf("Add: %v", err)
		}
	}
	def.Close()

	if _, _, err := Resize(pin, 2); err == nil || !strings.Contains(err.Error(), "cannot shrink") {
		t.Fatalf("Resize(2) = %v, want 'cannot shrink' error", err)
	}

	got, err := Open(pin)
	if err != nil {
		t.Fatalf("Open after failed shrink: %v", err)
	}
	t.Cleanup(got.Close)
	if got.Map.MaxEntries() != 16 {
		t.Fatalf("max_entries = %d, want the original 16", got.Map.MaxEntries())
	}
}

// TestResizeLeftoverTmpPinFails verifies a leftover temporary pin (from a
// crashed or concurrent resize) is reported with a recovery hint instead
// of a bare EEXIST from the pin syscall.
func TestResizeLeftoverTmpPinFails(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	pin := fmt.Sprintf("/sys/fs/bpf/bpfninja_tmppin_%d", os.Getpid())
	if err := Create(pin, "teid:u32", "", 16); err != nil {
		t.Skipf("creating pinned set map (bpffs unavailable?): %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })
	if err := Create(pin+"_resize_tmp", "teid:u32", "", 16); err != nil {
		t.Fatalf("creating leftover tmp pin: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin + "_resize_tmp") })

	if _, _, err := Resize(pin, 32); err == nil || !strings.Contains(err.Error(), "remove it and retry") {
		t.Fatalf("Resize = %v, want a leftover-tmp error with a recovery hint", err)
	}
}

// TestResizeSameCapacityNoop verifies a same-capacity resize succeeds
// without touching the map.
func TestResizeSameCapacityNoop(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	pin := fmt.Sprintf("/sys/fs/bpf/bpfninja_noop_%d", os.Getpid())
	if err := Create(pin, "teid:u32", "", 16); err != nil {
		t.Skipf("creating pinned set map (bpffs unavailable?): %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })

	oldMax, copied, err := Resize(pin, 16)
	if err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if oldMax != 16 || copied != 0 {
		t.Fatalf("Resize = (oldMax %d, copied %d), want (16, 0)", oldMax, copied)
	}
}

// TestTagsRoundTrip verifies Tags returns exactly the tag of every live
// entry (duplicates included) and tracks runtime add/delete — the view
// --exit-when-capped polls.
func TestTagsRoundTrip(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	pin := fmt.Sprintf("/sys/fs/bpf/bpfninja_tags_%d", os.Getpid())
	if err := Create(pin, "imsi:u64", "", 16); err != nil {
		t.Skipf("creating pinned set map (bpffs unavailable?): %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })

	def, err := Open(pin)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(def.Close)

	sortedTags := func() []uint32 {
		tags, err := def.Tags()
		if err != nil {
			t.Fatalf("Tags: %v", err)
		}
		slices.Sort(tags)
		return tags
	}

	if got := sortedTags(); len(got) != 0 {
		t.Fatalf("Tags on empty map = %v, want empty", got)
	}

	entries := map[string]uint64{"1001": 1, "1002": 2, "1003": 2}
	for imsi, tag := range entries {
		if err := def.Add(map[string]string{"imsi": imsi}, tag, 0); err != nil {
			t.Fatalf("Add(%s): %v", imsi, err)
		}
	}
	if got, want := sortedTags(), []uint32{1, 2, 2}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Tags = %v, want %v", got, want)
	}

	if err := def.Delete(map[string]string{"imsi": "1002"}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got, want := sortedTags(), []uint32{1, 2}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Tags after delete = %v, want %v", got, want)
	}
}

// TestExtendedValueLayout is the end-to-end for the default
// tag/state/max_bytes value: create, re-open (BTF round-trip), add with
// and without a cap, list rendering, TagInfos, the active-only Tags
// view, and SetState transitions.
func TestExtendedValueLayout(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	pin := fmt.Sprintf("/sys/fs/bpf/bpfninja_extval_%d", os.Getpid())
	if err := Create(pin, "imsi:u64", "", 16); err != nil {
		t.Skipf("creating pinned set map (bpffs unavailable?): %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })

	def, err := Open(pin)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(def.Close)

	if def.TagWidth() != 4 {
		t.Fatalf("TagWidth = %d, want 4", def.TagWidth())
	}
	if def.StateOff() != 4 {
		t.Fatalf("StateOff = %d, want 4", def.StateOff())
	}
	if f, ok := def.ValField(ValFieldMaxBytes); !ok || f.Off != 8 || f.Size != 8 {
		t.Fatalf("max_bytes field = %+v ok=%v, want off 8 size 8", f, ok)
	}

	if err := def.Add(map[string]string{"imsi": "1001"}, 1, 4096); err != nil {
		t.Fatalf("Add capped: %v", err)
	}
	if err := def.Add(map[string]string{"imsi": "1002"}, 2, 0); err != nil {
		t.Fatalf("Add uncapped: %v", err)
	}

	var list strings.Builder
	if err := def.List(&list); err != nil {
		t.Fatalf("List: %v", err)
	}
	want := sortedLines("imsi=1001 tag=1 state=active max-bytes=4096\nimsi=1002 tag=2 state=active max-bytes=unlimited")
	if got := sortedLines(list.String()); got != want {
		t.Fatalf("List =\n%s\nwant\n%s", got, want)
	}

	infos, err := def.TagInfos()
	if err != nil {
		t.Fatalf("TagInfos: %v", err)
	}
	byTag := map[uint32]TagInfo{}
	for _, in := range infos {
		byTag[in.Tag] = in
	}
	if in := byTag[1]; in.MaxBytes != 4096 || in.State != StateActive {
		t.Fatalf("tag 1 info = %+v", in)
	}
	if in := byTag[2]; in.MaxBytes != 0 {
		t.Fatalf("tag 2 info = %+v", in)
	}

	// Park tag 1: it must leave the active Tags view but stay listed.
	if n, err := def.SetState(1, StateCapped); err != nil || n != 1 {
		t.Fatalf("SetState = (%d, %v), want (1, nil)", n, err)
	}
	tags, err := def.Tags()
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if len(tags) != 1 || tags[0] != 2 {
		t.Fatalf("active Tags = %v, want [2]", tags)
	}
	list.Reset()
	if err := def.List(&list); err != nil {
		t.Fatalf("List after park: %v", err)
	}
	if !strings.Contains(list.String(), "imsi=1001 tag=1 state=capped") {
		t.Fatalf("parked entry not listed: %q", list.String())
	}
	// Idempotent: same state again updates nothing.
	if n, err := def.SetState(1, StateCapped); err != nil || n != 0 {
		t.Fatalf("SetState repeat = (%d, %v), want (0, nil)", n, err)
	}
}

// TestLegacyValueLayoutCompat pins the pre-#89 behavior: a plain u32
// tag value still opens, adds, and lists — with caps rejected and every
// entry reported active/uncapped.
func TestLegacyValueLayoutCompat(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	pin := fmt.Sprintf("/sys/fs/bpf/bpfninja_legacyval_%d", os.Getpid())
	if err := Create(pin, "imsi:u64", "tag:u32", 16); err != nil {
		t.Skipf("creating pinned set map (bpffs unavailable?): %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })

	def, err := Open(pin)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(def.Close)

	if def.StateOff() != -1 {
		t.Fatalf("StateOff = %d, want -1", def.StateOff())
	}
	if err := def.Add(map[string]string{"imsi": "1001"}, 3, 0); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := def.Add(map[string]string{"imsi": "1002"}, 4, 100); err == nil || !strings.Contains(err.Error(), ValFieldMaxBytes) {
		t.Fatalf("Add with cap on legacy layout = %v, want max_bytes error", err)
	}
	if n, err := def.SetState(3, StateCapped); err != nil || n != 0 {
		t.Fatalf("SetState on legacy layout = (%d, %v), want (0, nil)", n, err)
	}
	infos, err := def.TagInfos()
	if err != nil {
		t.Fatalf("TagInfos: %v", err)
	}
	if len(infos) != 1 || infos[0] != (TagInfo{Tag: 3}) {
		t.Fatalf("TagInfos = %+v, want [{3 0 0}]", infos)
	}
}

// sortedLines canonicalizes multi-line output whose line order is not
// stable (hash map iteration order).
func sortedLines(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}
