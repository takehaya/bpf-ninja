import Kunai.Packet

/-!
# Packet builders for vectors

Header layouts written out byte by byte; checksums are zero (the DSL never
reads them). Mirrors the shapes `pkg/kunai/dsltest/builders.go` produces.
-/
namespace Kunai.Pkt

/-- `n` as `len` big-endian bytes. -/
def be (len : Nat) (n : Nat) : List UInt8 :=
  (List.range len).reverse.map fun i => UInt8.ofNat ((n / 256 ^ i) % 256)

def eth (ethertype : Nat) (dst : Nat := 0x001122334455) (src : Nat := 0x66778899aabb) : Packet :=
  be 6 dst ++ be 6 src ++ be 2 ethertype

def vlan (tci ethertype : Nat) : Packet := be 2 tci ++ be 2 ethertype

/-- One MPLS label stack entry; `s` marks the bottom of stack. -/
def mpls (label : Nat) (s : Nat) (tc : Nat := 0) (ttl : Nat := 64) : Packet :=
  be 4 (label * 4096 + tc * 16 + s * 256 + ttl)

/-- IPv4 header. `ihl` in 32-bit words; `options` must be `(ihl - 5) * 4` bytes. -/
def ipv4 (proto : Nat) (src : Nat := 0x0a000001) (dst : Nat := 0x0a000002) (ttl : Nat := 64)
    (totalLength : Nat := 40) (ihl : Nat := 5) (options : Packet := []) (version : Nat := 4) : Packet :=
  be 1 (version * 16 + ihl) ++ be 1 0 ++ be 2 totalLength ++ be 2 0 ++ be 2 0
    ++ be 1 ttl ++ be 1 proto ++ be 2 0 ++ be 4 src ++ be 4 dst ++ options

def ipv6 (nextHeader : Nat) (src : Nat := 0xfc000000000000000000000000000001)
    (dst : Nat := 0xfc000000000000000000000000000002) (payloadLength : Nat := 20)
    (hopLimit : Nat := 64) (version : Nat := 6) : Packet :=
  be 4 (version * 2 ^ 28) ++ be 2 payloadLength ++ be 1 nextHeader ++ be 1 hopLimit ++ be 16 src ++ be 16 dst

/-- TCP header. `dataOffset` in 32-bit words; `options` must be `(dataOffset - 5) * 4` bytes. -/
def tcp (sport dport : Nat) (flags : Nat := 0x02) (seq : Nat := 1) (ack : Nat := 0)
    (window : Nat := 65535) (dataOffset : Nat := 5) (options : Packet := []) : Packet :=
  be 2 sport ++ be 2 dport ++ be 4 seq ++ be 4 ack ++ be 2 (dataOffset * 4096 + flags)
    ++ be 2 window ++ be 2 0 ++ be 2 0 ++ options

def udp (sport dport : Nat) (length : Nat := 8) : Packet := be 2 sport ++ be 2 dport ++ be 2 length ++ be 2 0

def vxlan (vni : Nat) : Packet := be 1 0x08 ++ be 3 0 ++ be 3 vni ++ be 1 0

def payload (n : Nat) : Packet := List.replicate n 0x61

/-- eth / ipv4 / tcp with a 5-byte payload, like `dsltest.BuildEthIPv4TCP`. -/
def ethIPv4TCP (sport : Nat := 12345) (dport : Nat := 80) : Packet :=
  eth 0x0800 ++ ipv4 6 (totalLength := 45) ++ tcp sport dport ++ payload 5

example : (ethIPv4TCP).length = 59 := by decide

end Kunai.Pkt
