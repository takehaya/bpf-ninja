package regionval

import (
	"encoding/binary"
	"encoding/hex"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// exportDir holds synthetic captures: clean rewrites and rewrites with one
// planted fault each.
const exportDir = "testdata/export"

func exportFiles(t *testing.T, set string) []string {
	t.Helper()
	fs, _ := filepath.Glob(filepath.Join(exportDir, set, "*.json"))
	if len(fs) == 0 {
		t.Fatalf("no files in %s/%s", exportDir, set)
	}
	return fs
}

// The 15 clean pairs are validated, every window of them. clean-missfirst-copy
// is clean-missfirst-any with the hit hook given a 16-byte stack copy of the
// value at r10-48, as CopyReadOnly lays it out; it was built by hand, not
// captured from a load.
func TestExportClean(t *testing.T) {
	fs := exportFiles(t, "clean")
	for _, f := range fs {
		if r := Run(f); !r.Validated || r.Counts.Validated != r.Counts.Windows {
			t.Errorf("%s: %+v", filepath.Base(f), r)
		}
	}
	if len(fs) != 15 {
		t.Errorf("%d clean pairs, want 15", len(fs))
	}
}

// plantedWant is the rule each planted fault must be rejected by. 30 faults
// must fail an obligation of their target; the other 14 fail in the
// structure checks or the allowlist. PL-RB-a to d keep the target's
// behaviour and give a hook the wrong key or value (rule RB): a value from
// the hook's frame instead of the result (a), a miss key from the result
// slot (b), a wrapper keeping r4 as the key (c), and swapped hit and miss
// hook calls in a wrapper (d). Where a kind's clause is a common
// obligation applied to that window, the common rule is named: P1-b, P1b-b
// and P9-a move the prologue's spill into [f,0), which is C1's `o+w ≤ f`;
// P7-c's backward jump is C4 inside the hook body (P7's "branches forward").
var plantedWant = map[string]string{
	"PL-C1-a": "C1", "PL-C1-b": "C1", "PL-C2-a": "C2", "PL-C2-b": "C2",
	"PL-C4-a": "C4", "PL-C4-b": "C4", "PL-C4-c": "C4", "PL-C5-a": "C5", "PL-C5-b": "C5",
	"PL-P1-a": "P1", "PL-P1-b": "C1", "PL-P1b-a": "P1b", "PL-P1b-b": "C1",
	"PL-P7-b": "P7", "PL-P7-c": "C4", "PL-P7-d": "P7", "PL-P8-b": "P8", "PL-P8-e": "P8",
	"PL-P9-a": "C1", "PL-P9-b": "P9",
	"PL-R0-a": "R0", "PL-R0-b": "R0", "PL-R0-c": "R0", "PL-R0-d": "R0", "PL-R15-a": "R15", "PL-R15-b": "R15",
	"PL-RB-a": "RB", "PL-RB-b": "RB", "PL-RB-c": "RB", "PL-RB-d": "RB",
	// Allowlist (ST is not in the table; atomic, xor32, 0xff) and structure.
	"PL-C3-a": "C6", "PL-C3-b": "C6", "PL-C6-a": "C6", "PL-C6-b": "C6", "PL-C6-c": "C6", "PL-P7-a": "C6", "PL-P8-a": "C6",
	"PL-C6-d": "struct:kappa", "PL-P8-c": "struct:kappa", "PL-P8-d": "struct:kappa",
	"PL-S-a": "struct:kappa", "PL-S-b": "struct:kappa", "PL-S-c": "struct:edges", "PL-S-d": "struct:windows",
}

func TestExportPlanted(t *testing.T) {
	fs := exportFiles(t, "planted")
	obl := 0
	for _, f := range fs {
		id := strings.TrimSuffix(filepath.Base(f), ".json")
		want, ok := plantedWant[id]
		if !ok {
			t.Errorf("%s: no expected rule", id)
			continue
		}
		r := Run(f)
		var got []string
		if !r.Structure.OK {
			got = []string{"struct:" + r.Structure.Stage}
		}
		for _, w := range r.Windows {
			if !w.Validated {
				got = append(got, w.Rule)
			}
		}
		if r.Validated || !slices.Equal(got, []string{want}) {
			t.Errorf("%s: rejected by %v, want exactly [%s] (%+v)", id, got, want, r.Windows)
		}
		if !strings.HasPrefix(want, "struct:") && want != "C6" {
			obl++
		}
	}
	if len(fs) != 44 || obl != 30 {
		t.Errorf("%d planted files, %d rejected by an obligation; want 44 and 30", len(fs), obl)
	}
}

// One-byte rewriter faults RB must refuse: in clean-missfirst-any the hit
// hook's `r4 = r0` (raw slot 24) becomes `r4 = *(u64 *)(r0 + 0)`, which
// passes the value's first 8 bytes as the value pointer; in
// clean-missfirst-copy the copy's address r10-48 becomes r10-40.
func TestRBOneByteFaults(t *testing.T) {
	for _, c := range []struct {
		file   string
		at     int // byte offset in transformed_insns_hex
		was    byte
		now    []byte
		clause string
	}{
		{"clean-missfirst-any", 24 * 8, 0xbf, []byte{0x79}, "value argument r4 is u14/8, not the helper's result"},
		{"clean-missfirst-copy", 30*8 + 4, 0xd0, []byte{0xd8}, "not the copy at r10-48"},
	} {
		cp, err := LoadCapture(filepath.Join(exportDir, "clean", c.file+".json"))
		if err != nil {
			t.Fatal(err)
		}
		b, err := hex.DecodeString(cp.TransformedInsnsHex)
		if err != nil || b[c.at] != c.was {
			t.Fatalf("%s: byte %d is %#x (%v)", c.file, c.at, b[c.at], err)
		}
		copy(b[c.at:], c.now)
		cp.TransformedInsnsHex = hex.EncodeToString(b)
		r := runFile(t, cp)
		var got []string
		for _, w := range r.Windows {
			if !w.Validated {
				got = append(got, w.Rule)
				if !strings.Contains(w.Reason, c.clause) {
					t.Errorf("%s: reason %q, want %q", c.file, w.Reason, c.clause)
				}
			}
		}
		if r.Validated || !r.Structure.OK || !slices.Equal(got, []string{"RB"}) {
			t.Errorf("%s: rejected by %v, want [RB]: %+v", c.file, got, r)
		}
	}
}

// A copied value whose BTF type is a 16-byte FLOAT is sized like any other
// (the rewriter accepts every type btf.Sizeof sizes): clean-missfirst-copy
// with its value type, CONST -> struct session (16 bytes), pointed at a
// FLOAT appended to the BTF stays validated by both cores.
func TestRBCopyFloatValue(t *testing.T) {
	c, err := LoadCapture(filepath.Join(exportDir, "clean", "clean-missfirst-copy.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(c.TransformedBTFHex)
	if err != nil {
		t.Fatal(err)
	}
	le := binary.LittleEndian
	hdr, typeLen := le.Uint32(b[4:]), le.Uint32(b[12:])
	end := int(hdr + le.Uint32(b[8:]) + typeLen)
	const constID, constOff, floatID = 15, 244, 25 // type 15 is CONST of type 14, struct session
	if k := le.Uint32(b[int(hdr)+constOff+4:]) >> 24; k != 10 || le.Uint32(b[int(hdr)+constOff+8:]) != 14 {
		t.Fatalf("type %d is kind %d, not CONST of 14", constID, k)
	}
	le.PutUint32(b[int(hdr)+constOff+8:], floatID)
	float := le.AppendUint32(le.AppendUint32(le.AppendUint32(nil, 0), 16<<24), 16) // FLOAT, size 16
	b = append(append(slices.Clone(b[:end]), float...), b[end:]...)
	le.PutUint32(b[12:], typeLen+12)
	le.PutUint32(b[16:], le.Uint32(b[16:])+12)
	c.TransformedBTFHex = hex.EncodeToString(b)
	l, err := Analyze(c)
	if err != nil {
		t.Fatal(err)
	}
	if f := l.TFuncs[1]; f.Name != "lookup_hook_sessions" || f.Sizes[3] != 16 {
		t.Fatalf("%s: value size %v", f.Name, f.Sizes)
	}
	if r := runFile(t, c); !r.Validated || r.Counts.Disagree != 0 || r.Counts.Validated != r.Counts.Windows {
		t.Errorf("copy of a FLOAT value: %+v", r)
	}
}

// C3-a/b, P7-a and P8-a were planted as ST (imm store),
// which the allowlist refuses before any obligation runs. Their STX
// versions (`*(u32 *)(r10+off) = r0`, same position) must be rejected by the
// store clause of the targeted obligation. C3 sits behind C1's `o+w ≤ f`
// (TestC3BehindC1), so C3-a/b are refused as C1; P8-a's store names r10,
// so it is refused by P8's r10 clause before its store clause.
func TestExportPlantedSTX(t *testing.T) {
	exportFiles(t, "planted")
	for id, want := range map[string]string{"PL-C3-a": "C1", "PL-C3-b": "C1", "PL-P7-a": "P7", "PL-P8-a": "P8"} {
		c, err := LoadCapture(filepath.Join(exportDir, "planted", id+".json"))
		if err != nil {
			t.Fatal(err)
		}
		b, err := hex.DecodeString(c.TransformedInsnsHex)
		if err != nil {
			t.Fatal(err)
		}
		l, err := Analyze(c)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for j, x := range l.T {
			if i := x.Raw * 8; x.Op == 0x62 && !slices.Contains(l.Kappa, j) { // an inserted ST
				b[i], b[i+1] = 0x63, 10 // STX W, src r0
				clear(b[i+4 : i+8])
				n++
			}
		}
		if n != 1 {
			t.Fatalf("%s: %d ST instructions", id, n)
		}
		c.TransformedInsnsHex = hex.EncodeToString(b)
		r := runFile(t, c)
		var got []string
		for _, w := range r.Windows {
			if !w.Validated {
				got = append(got, w.Rule)
			}
		}
		if r.Validated || !r.Structure.OK || !slices.Equal(got, []string{want}) {
			t.Errorf("%s (STX): rejected by %v, want [%s]: %+v", id, got, want, r)
		}
	}
}
