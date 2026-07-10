package setmap

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/takehaya/xdp-ninja/internal/testutil"
)

// TestResizeGrowPreservesEntriesAndSchema is the end-to-end for `set
// resize`: create a composite-key set, add entries, grow it, and verify
// the replacement pin keeps the capacity, every entry, and the BTF key
// schema (field names, offsets, widths).
func TestResizeGrowPreservesEntriesAndSchema(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	pin := fmt.Sprintf("/sys/fs/bpf/xdpninja_resize_%d", os.Getpid())
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
		}, uint64(i+1))
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

	pin := fmt.Sprintf("/sys/fs/bpf/xdpninja_shrink_%d", os.Getpid())
	if err := Create(pin, "teid:u32", "", 16); err != nil {
		t.Skipf("creating pinned set map (bpffs unavailable?): %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })

	def, err := Open(pin)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := range 3 {
		if err := def.Add(map[string]string{"teid": fmt.Sprintf("%d", i+1)}, 1); err != nil {
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

// TestResizeSameCapacityNoop verifies a same-capacity resize succeeds
// without touching the map.
func TestResizeSameCapacityNoop(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	pin := fmt.Sprintf("/sys/fs/bpf/xdpninja_noop_%d", os.Getpid())
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

// sortedLines canonicalizes multi-line output whose line order is not
// stable (hash map iteration order).
func sortedLines(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}
