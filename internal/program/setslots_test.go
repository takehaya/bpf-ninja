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

func TestNewPktSetSlotsAllocatesDistinctBuffers(t *testing.T) {
	sets := []*setmap.Set{
		setWithKey("a", 8, []setmap.KeyField{{Name: "teid", Off: 0, Size: 4}, {Name: "mt", Off: 4, Size: 1}}),
		setWithKey("b", 4, []setmap.KeyField{{Name: "sid", Off: 0, Size: 4}}),
	}
	p, err := newPktSetSlots(sets)
	if err != nil {
		t.Fatalf("newPktSetSlots: %v", err)
	}
	// Both sets sit inside the host region [-40,-24) and don't overlap.
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
}

func TestNewPktSetSlotsRejectsOverBudget(t *testing.T) {
	// Two 16-byte keys = 32 bytes > the 16-byte packet-extraction budget.
	sets := []*setmap.Set{
		setWithKey("a", 16, []setmap.KeyField{{Name: "k", Off: 0, Size: 8}}),
		setWithKey("b", 16, []setmap.KeyField{{Name: "k", Off: 0, Size: 8}}),
	}
	if _, err := newPktSetSlots(sets); err == nil {
		t.Fatal("expected over-budget error")
	}
}

func TestPktSetSlotsUnknownSetOrField(t *testing.T) {
	p, err := newPktSetSlots([]*setmap.Set{setWithKey("a", 4, []setmap.KeyField{{Name: "teid", Off: 0, Size: 4}})})
	if err != nil {
		t.Fatalf("newPktSetSlots: %v", err)
	}
	if p.HasSet("nope") {
		t.Error("HasSet(nope) should be false")
	}
	if _, _, ok := p.SlotFor("a", "nofield"); ok {
		t.Error("SlotFor for unknown field should fail")
	}
}
