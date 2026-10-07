package hook

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/cilium/ebpf/btf"
)

// skBuffPacketOffsets returns the kernel BTF byte offsets of
// `struct sk_buff`'s `data` (8B pointer), `len` (4B u32), and
// `data_len` (4B u32) members. `len - data_len` is the linear head
// length (skb_headlen()); the prologues clamp the packet window to it
// because a GRO/GSO or fragmented skb keeps `data_len` bytes in frags
// that a flat read from `data` must not cross.
// tc clsact fexit/fentry programs receive a `struct sk_buff *` (the
// kernel struct, NOT the BPF-rewritten `__sk_buff` view) at args[0],
// so the linear-region read needs the actual member offsets — which
// drift across kernel versions, hence runtime BTF resolution.
//
// Cached at first call: BTF spec load + walk is on the order of
// milliseconds, fine to amortise across all probes loaded in-process.
func skBuffPacketOffsets() (data uint32, length uint32, dataLen uint32, err error) {
	skBuffOnce.Do(func() {
		var spec *btf.Spec
		spec, skBuffErr = btf.LoadKernelSpec()
		if skBuffErr != nil {
			skBuffErr = fmt.Errorf("loading kernel BTF: %w", skBuffErr)
			return
		}
		var skb *btf.Struct
		if err := spec.TypeByName("sk_buff", &skb); err != nil {
			skBuffErr = fmt.Errorf("BTF type sk_buff not found: %w", err)
			return
		}
		var foundData, foundLen, foundDataLen bool
		for _, m := range skb.Members {
			switch m.Name {
			case "data":
				skBuffDataOff = m.Offset.Bytes()
				foundData = true
			case "len":
				skBuffLenOff = m.Offset.Bytes()
				foundLen = true
			case "data_len":
				skBuffDataLenOff = m.Offset.Bytes()
				foundDataLen = true
			}
		}
		if !foundData || !foundLen || !foundDataLen {
			skBuffErr = fmt.Errorf("BTF struct sk_buff missing data, len, or data_len member (data=%v len=%v data_len=%v)", foundData, foundLen, foundDataLen)
			return
		}
	})
	return skBuffDataOff, skBuffLenOff, skBuffDataLenOff, skBuffErr
}

var (
	skBuffOnce       sync.Once
	skBuffDataOff    uint32
	skBuffLenOff     uint32
	skBuffDataLenOff uint32
	skBuffErr        error
)

// skBuffVlan locates the outer VLAN tag kept in `struct sk_buff`
// metadata (skb_vlan_untag on receive, the hwaccel tag on transmit).
// The members sit inside anonymous unions and struct groups, so the walk
// descends into anonymous members and adds their offsets. Kernels before
// 6.2 mark presence with the `vlan_present` bitfield (proto and tci may
// be stale when it is clear); later kernels clear `vlan_all` and test it
// for zero, so a non-zero vlan_proto means a tag.
type skBuffVlan struct {
	proto, tci uint32 // byte offsets: __be16 vlan_proto, __u16 vlan_tci
	// presentByte / presentBit locate `vlan_present` (presentBit is the
	// bit's position from the least significant bit of that byte, as a
	// mask shift); hasPresent is false on kernels without it.
	presentByte uint32
	presentBit  uint8
	hasPresent  bool
}

func skBuffVlanOffsets() (skBuffVlan, error) {
	skBuffVlanOnce.Do(func() {
		spec, err := btf.LoadKernelSpec()
		if err != nil {
			skBuffVlanErr = fmt.Errorf("loading kernel BTF: %w", err)
			return
		}
		var skb *btf.Struct
		if err := spec.TypeByName("sk_buff", &skb); err != nil {
			skBuffVlanErr = fmt.Errorf("BTF type sk_buff not found: %w", err)
			return
		}
		skBuffVlanVal, skBuffVlanErr = vlanLayout(skb, nativeBigEndian)
	})
	return skBuffVlanVal, skBuffVlanErr
}

// vlanLayout reads the VLAN members out of a struct sk_buff type. A
// bitfield's BTF bit offset counts from the first bit in memory order:
// the least significant bit of a byte on a little-endian host, the most
// significant on a big-endian one.
func vlanLayout(skb *btf.Struct, bigEndian bool) (skBuffVlan, error) {
	proto, okProto := findMember(skb, "vlan_proto", 0)
	tci, okTCI := findMember(skb, "vlan_tci", 0)
	if !okProto || !okTCI {
		return skBuffVlan{}, fmt.Errorf("BTF struct sk_buff missing vlan_proto or vlan_tci")
	}
	v := skBuffVlan{proto: proto.Offset.Bytes(), tci: tci.Offset.Bytes()}
	if p, ok := findMember(skb, "vlan_present", 0); ok {
		v.presentByte = uint32(p.Offset) / 8
		v.presentBit = uint8(uint32(p.Offset) % 8)
		if bigEndian {
			v.presentBit = 7 - v.presentBit
		}
		v.hasPresent = true
	}
	return v, nil
}

// nativeBigEndian is true on a big-endian host.
var nativeBigEndian = binary.NativeEndian.Uint16([]byte{0, 1}) == 1

// findMember finds a member by name in t (a struct or union) or,
// recursively, in its anonymous struct / union members. The returned
// member's Offset is relative to the outermost type; base is the bit
// offset of t in it.
func findMember(t btf.Type, name string, base btf.Bits) (btf.Member, bool) {
	var members []btf.Member
	switch c := btf.UnderlyingType(t).(type) {
	case *btf.Struct:
		members = c.Members
	case *btf.Union:
		members = c.Members
	default:
		return btf.Member{}, false
	}
	for _, m := range members {
		if m.Name == name {
			m.Offset += base
			return m, true
		}
		if m.Name == "" {
			if found, ok := findMember(m.Type, name, base+m.Offset); ok {
				return found, true
			}
		}
	}
	return btf.Member{}, false
}

var (
	skBuffVlanOnce sync.Once
	skBuffVlanVal  skBuffVlan
	skBuffVlanErr  error
)
