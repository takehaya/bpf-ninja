package hook

import (
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// TestVlanLayout checks the VLAN member walk on synthetic sk_buff layouts
// shaped like the two kernel generations: before 6.2 a vlan_present
// bitfield inside a struct group (an anonymous union of an anonymous
// struct), from 6.2 on a vlan_all union around vlan_proto / vlan_tci.
func TestVlanLayout(t *testing.T) {
	u8 := &btf.Int{Name: "__u8", Size: 1}
	u16 := &btf.Int{Name: "__u16", Size: 2}
	u32 := &btf.Int{Name: "u32", Size: 4}
	protoTCI := &btf.Struct{Size: 4, Members: []btf.Member{
		{Name: "vlan_proto", Type: u16, Offset: 0},
		{Name: "vlan_tci", Type: u16, Offset: 16},
	}}

	// 6.2+: union { u32 vlan_all; struct { vlan_proto; vlan_tci; }; } at byte 156.
	modern := &btf.Struct{Name: "sk_buff", Size: 232, Members: []btf.Member{
		{Name: "len", Type: u32, Offset: 0},
		{Type: &btf.Union{Size: 4, Members: []btf.Member{
			{Name: "vlan_all", Type: u32, Offset: 0},
			{Type: protoTCI, Offset: 0},
		}}, Offset: 156 * 8},
	}}
	// 6.1: a struct group at byte 120 holding a flags byte whose bit 5 is
	// vlan_present (bit offset 128*8+5 overall), then proto and tci at 152.
	headers := &btf.Struct{Size: 40, Members: []btf.Member{
		{Name: "pkt_type", Type: u8, Offset: 8 * 8, BitfieldSize: 3},
		{Name: "vlan_present", Type: u8, Offset: 8*8 + 5, BitfieldSize: 1},
		{Name: "vlan_proto", Type: u16, Offset: 32 * 8},
		{Name: "vlan_tci", Type: u16, Offset: 34 * 8},
	}}
	legacy := &btf.Struct{Name: "sk_buff", Size: 232, Members: []btf.Member{
		{Name: "len", Type: u32, Offset: 0},
		{Type: &btf.Union{Size: 40, Members: []btf.Member{
			{Type: headers, Offset: 0},
			{Name: "headers", Type: headers, Offset: 0},
		}}, Offset: 120 * 8},
	}}

	for _, tc := range []struct {
		name string
		skb  *btf.Struct
		big  bool
		want skBuffVlan
	}{
		{"6.2+", modern, false, skBuffVlan{proto: 156, tci: 158}},
		{"6.1", legacy, false, skBuffVlan{proto: 152, tci: 154, presentByte: 128, presentBit: 5, hasPresent: true}},
		{"6.1 big-endian", legacy, true, skBuffVlan{proto: 152, tci: 154, presentByte: 128, presentBit: 2, hasPresent: true}},
	} {
		got, err := vlanLayout(tc.skb, tc.big)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
	if _, err := vlanLayout(&btf.Struct{Name: "sk_buff", Members: []btf.Member{{Name: "len", Type: u32}}}, false); err == nil {
		t.Error("a sk_buff without vlan members must be an error")
	}
}

// TestSkbOuterVlanTagHonoursPresentBit checks the emitted test of the
// vlan_present bit: with it, a clear bit reports no tag (R2 = 0).
func TestSkbOuterVlanTagHonoursPresentBit(t *testing.T) {
	v := skBuffVlan{proto: 152, tci: 154, presentByte: 128, presentBit: 5, hasPresent: true}
	insns := outerVlanTagInsns(v)
	var sawJSet bool
	for _, ins := range insns {
		if ins.OpCode.JumpOp() == asm.JSet && ins.Constant == 1<<5 {
			sawJSet = true
		}
	}
	if !sawJSet {
		t.Fatalf("no JSET on bit 5 of byte 128:\n%v", insns)
	}
	if n := len(outerVlanTagInsns(skBuffVlan{proto: 156, tci: 158})); n != 2 {
		t.Errorf("without vlan_present: %d insns, want the two loads", n)
	}
}
