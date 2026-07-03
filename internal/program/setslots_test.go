package program

import (
	"testing"

	"github.com/takehaya/xdp-ninja/internal/setmap"
)

func setWithKey(name string, keySize uint32, fields []setmap.KeyField) *setmap.Set {
	return &setmap.Set{
		SpecRef: setmap.SpecRef{Name: name},
		Def:     &setmap.Definition{KeySize: keySize, Fields: fields},
	}
}

func TestPktSetSlotsAllocatesDistinctBuffersLazily(t *testing.T) {
	sets := []*setmap.Set{
		setWithKey("a", 8, []setmap.KeyField{{Name: "teid", Off: 0, Size: 4}, {Name: "mt", Off: 4, Size: 1}}),
		setWithKey("b", 4, []setmap.KeyField{{Name: "sid", Off: 0, Size: 4}}),
	}
	p := newPktSetSlots(sets)
	// SlotFor allocates on first use; both sets land inside [-40,-24) and
	// don't overlap.
	offA, szA, okA := p.SlotFor("a", "teid")
	offB, _, okB := p.SlotFor("b", "sid")
	if !okA || !okB {
		t.Fatalf("SlotFor missing: a=%v b=%v", okA, okB)
	}
	if szA != 4 {
		t.Errorf("teid size = %d, want 4", szA)
	}
	for _, off := range []int16{offA, offB} {
		if off < pktSetKeyFloor || off >= pktSetKeyTop {
			t.Errorf("slot %d outside host region [%d,%d)", off, pktSetKeyFloor, pktSetKeyTop)
		}
	}
	if offA == offB {
		t.Errorf("sets share a buffer base (%d)", offA)
	}
	// Field offset within the key is honored.
	offMT, _, _ := p.SlotFor("a", "mt")
	if offMT != offA+4 {
		t.Errorf("mt slot = %d, want %d", offMT, offA+4)
	}
	if err := p.allocErr(); err != nil {
		t.Errorf("unexpected allocErr: %v", err)
	}
}

func TestPktSetSlotsRejectsOverBudget(t *testing.T) {
	// Two 16-byte keys = 32 bytes > the 16-byte packet-extraction budget.
	sets := []*setmap.Set{
		setWithKey("a", 16, []setmap.KeyField{{Name: "k", Off: 0, Size: 8}}),
		setWithKey("b", 16, []setmap.KeyField{{Name: "k", Off: 0, Size: 8}}),
	}
	p := newPktSetSlots(sets)
	p.SlotFor("a", "k") // fits
	if _, _, ok := p.SlotFor("b", "k"); ok {
		t.Fatal("second 16-byte set should not fit the budget")
	}
	if p.allocErr() == nil {
		t.Fatal("expected over-budget allocErr")
	}
}

func TestPktSetSlotsOnlyReferencedConsumeBudget(t *testing.T) {
	// An arg-filter-only set (never queried via SlotFor) must not consume
	// the packet-key budget, so a 16-byte packet set still fits.
	sets := []*setmap.Set{
		setWithKey("argonly", 16, []setmap.KeyField{{Name: "k", Off: 0, Size: 8}}),
		setWithKey("pkt", 16, []setmap.KeyField{{Name: "k", Off: 0, Size: 8}}),
	}
	p := newPktSetSlots(sets)
	if _, _, ok := p.SlotFor("pkt", "k"); !ok {
		t.Fatal("packet set should fit when the arg-only set is not queried")
	}
	if p.allocErr() != nil {
		t.Errorf("unexpected allocErr: %v", p.allocErr())
	}
}

func TestPktSetSlotsKeepsWiderKeysAligned(t *testing.T) {
	// Allocate a u32-key set first, then a u64-key set. The u64 slot must
	// stay 8-aligned so kunai's DWord store isn't verifier-rejected.
	sets := []*setmap.Set{
		setWithKey("small", 4, []setmap.KeyField{{Name: "teid", Off: 0, Size: 4}}),
		setWithKey("wide", 8, []setmap.KeyField{{Name: "sid", Off: 0, Size: 8}}),
	}
	p := newPktSetSlots(sets)
	p.SlotFor("small", "teid")
	off, size, ok := p.SlotFor("wide", "sid")
	if !ok {
		t.Fatal("wide set should fit")
	}
	if size != 8 {
		t.Fatalf("size = %d, want 8", size)
	}
	if off%8 != 0 {
		t.Errorf("u64 slot %d is not 8-aligned (DWord store would be rejected)", off)
	}
}

func TestPktSetSlotsUnknownSetOrField(t *testing.T) {
	p := newPktSetSlots([]*setmap.Set{setWithKey("a", 4, []setmap.KeyField{{Name: "teid", Off: 0, Size: 4}})})
	if p.HasSet("nope") {
		t.Error("HasSet(nope) should be false")
	}
	if _, _, ok := p.SlotFor("a", "nofield"); ok {
		t.Error("SlotFor for unknown field should fail")
	}
}
