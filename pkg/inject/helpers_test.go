package inject

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
)

// helperFnName spells a helper name the way cilium/ebpf names its
// asm.BuiltinFunc constants: "bpf_map_lookup_elem" -> "FnMapLookupElem".
func helperFnName(name string) string {
	var b strings.Builder
	b.WriteString("Fn")
	for _, part := range strings.Split(strings.TrimPrefix(name, "bpf_"), "_") {
		if part != "" {
			b.WriteString(strings.ToUpper(part[:1]) + part[1:])
		}
	}
	return b.String()
}

func TestHelperTable(t *testing.T) {
	if len(helperTable) != 212 {
		t.Fatalf("helperTable has %d rows, want 212", len(helperTable))
	}
	if helperTable[0].Ret != RetUnsupported {
		t.Errorf("row 0 is %s, want %s", helperTable[0].Ret, RetUnsupported)
	}
	for id, row := range helperTable {
		if id > 0 && row.Ret != RetScalar && row.Ret != RetPointer && row.Ret != RetVoid {
			t.Errorf("id %d %s: kind %q", id, row.Name, row.Ret)
		}
		if got, want := asm.BuiltinFunc(id).String(), helperFnName(row.Name); got != want {
			t.Errorf("id %d: cilium/ebpf names it %s, table %s (%s)", id, got, row.Name, want)
		}
	}
	// cilium/ebpf knows exactly the same 212 Linux helpers.
	if s := asm.BuiltinFunc(212).String(); strings.HasPrefix(s, "Fn") {
		t.Errorf("cilium/ebpf knows helper 212 (%s); regenerate the table", s)
	}
}

func TestHelperByID(t *testing.T) {
	want := map[asm.BuiltinFunc]CalleeRet{
		asm.FnTailCall:      RetVoid,
		asm.FnSpinLock:      RetVoid,
		asm.FnSpinUnlock:    RetVoid,
		asm.FnKtimeGetNs:    RetScalar,
		asm.FnSkLookupTcp:   RetPointer,
		asm.FnMapLookupElem: RetPointer,
	}
	for fn, ret := range want {
		row, ok := helperByID(int64(fn))
		if !ok || row.Ret != ret {
			t.Errorf("helperByID(%s) = %v, %v; want %s", fn, row, ok, ret)
		}
	}
	for _, id := range []int64{-1, 212} {
		if row, ok := helperByID(id); ok {
			t.Errorf("helperByID(%d) = %v, true; want false", id, row)
		}
	}
}
