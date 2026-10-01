/-!
# Vocabulary (protocol table) as data

Hand-transcribed from `pkg/kunai/protocols/{eth,vlan,ipv4,ipv6,tcp,udp,vxlan,
mpls}.p4`. Only the primary header, its length rule, self-validation, and the
`KUNAI_<CHILD>_<PARENT>_…` dispatch edges are represented. Aux headers
(options, extension headers, stacks) are Phase 5 (DECISIONS.md D-012).
-/
namespace Kunai

structure FieldSpec where
  name : String
  bitOff : Nat
  width : Nat
  deriving Repr, BEq, DecidableEq

/-- Header length in bytes: `((byte[byteOff] & mask) >> shift) * scale`,
mirroring `vocab.HeaderLength` in Go. -/
structure LenRule where
  byteOff : Nat
  mask : Nat
  shift : Nat
  scale : Nat
  deriving Repr, BEq, DecidableEq

structure ProtoSpec where
  name : String
  fields : List FieldSpec
  /-- Byte length of the fixed header (`SumBits / 8`). -/
  fixedLen : Nat
  /-- Present for variable-length headers (ipv4 IHL, tcp data offset). -/
  lenRule : Option LenRule := none
  /-- Self-validation from the parser block (`select(version) { 4: …; default: reject }`). -/
  requires : List (String × Nat) := []
  /-- `<SELF>_CHAIN_END_<FIELD> = v`: a self-chain stops after a header whose field equals `v`. -/
  chainEnd : Option (String × Nat) := none
  /-- `<SELF>_MAX_DEPTH` (default 8): iteration bound for `+`, `*`, `{n,}`. -/
  maxDepth : Nat := 8
  deriving Repr, BEq, DecidableEq

inductive EdgeKind
  | noCheck
  | field (name : String) (values : List Nat)
  deriving Repr, BEq, DecidableEq

/-- `KUNAI_<CHILD>_<PARENT>_<FIELD> = v` (with `_ALT_*` folded into `values`)
or `KUNAI_<CHILD>_<PARENT>_NO_CHECK`. -/
structure Edge where
  child : String
  parent : String
  kind : EdgeKind
  deriving Repr, BEq, DecidableEq

structure Vocab where
  protos : List ProtoSpec
  edges : List Edge
  deriving Repr, BEq, DecidableEq

def Vocab.proto? (V : Vocab) (name : String) : Option ProtoSpec :=
  V.protos.find? (·.name == name)

def Vocab.edge? (V : Vocab) (child parent : String) : Option Edge :=
  V.edges.find? fun e => e.child == child && e.parent == parent

def ProtoSpec.field? (p : ProtoSpec) (name : String) : Option FieldSpec :=
  p.fields.find? (·.name == name)

/-- Lay out `(name, width)` pairs back to back. -/
private def layout (fs : List (String × Nat)) : List FieldSpec :=
  (fs.foldl (fun (acc : Nat × List FieldSpec) (f : String × Nat) =>
    (acc.1 + f.2, acc.2 ++ [⟨f.1, acc.1, f.2⟩])) (0, [])).2

private def mkProto (name : String) (fs : List (String × Nat)) : ProtoSpec :=
  { name, fields := layout fs, fixedLen := (fs.map (·.2)).sum / 8 }

def ethSpec : ProtoSpec := mkProto "eth" [("dst", 48), ("src", 48), ("ethertype", 16)]

def vlanSpec : ProtoSpec := mkProto "vlan" [("tci", 16), ("ethertype", 16)]

def ipv4Spec : ProtoSpec :=
  { mkProto "ipv4" [("version", 4), ("ihl", 4), ("diffserv", 8), ("total_length", 16),
      ("identification", 16), ("flags", 3), ("frag_offset", 13), ("ttl", 8), ("protocol", 8),
      ("checksum", 16), ("src", 32), ("dst", 32)] with
    lenRule := some ⟨0, 0x0F, 0, 4⟩
    requires := [("version", 4)] }

def ipv6Spec : ProtoSpec :=
  { mkProto "ipv6" [("version", 4), ("traffic_class", 8), ("flow_label", 20),
      ("payload_length", 16), ("next_header", 8), ("hop_limit", 8), ("src", 128), ("dst", 128)] with
    requires := [("version", 6)]
    maxDepth := 4 }

def tcpSpec : ProtoSpec :=
  { mkProto "tcp" [("sport", 16), ("dport", 16), ("seq", 32), ("ack", 32), ("data_offset", 4),
      ("reserved", 3), ("flags", 9), ("window", 16), ("checksum", 16), ("urgent_ptr", 16)] with
    lenRule := some ⟨12, 0xF0, 4, 4⟩
    maxDepth := 40 }

def udpSpec : ProtoSpec := mkProto "udp" [("sport", 16), ("dport", 16), ("length", 16), ("checksum", 16)]

def vxlanSpec : ProtoSpec :=
  mkProto "vxlan" [("flags", 8), ("reserved1", 24), ("vni", 24), ("reserved2", 8)]

def mplsSpec : ProtoSpec :=
  { mkProto "mpls" [("label", 20), ("tc", 3), ("s", 1), ("ttl", 8)] with
    chainEnd := some ("s", 1) }

private def ether (child : String) (v : Nat) : List Edge :=
  [⟨child, "eth", .field "ethertype" [v]⟩, ⟨child, "vlan", .field "ethertype" [v]⟩]

/-- The Phase 2 vocabulary: eight protocols and the edges among them. -/
def vocab : Vocab :=
  { protos := [ethSpec, vlanSpec, ipv4Spec, ipv6Spec, tcpSpec, udpSpec, vxlanSpec, mplsSpec]
    edges :=
      [⟨"eth", "mpls", .noCheck⟩, ⟨"eth", "vxlan", .noCheck⟩]
      ++ ether "vlan" 0x8100 ++ [⟨"vlan", "vlan", .field "ethertype" [0x8100]⟩]
      ++ ether "ipv4" 0x0800 ++ [⟨"ipv4", "ipv4", .field "protocol" [4]⟩]
      ++ ether "ipv6" 0x86DD ++ [⟨"ipv6", "ipv6", .field "next_header" [41]⟩]
      ++ [⟨"tcp", "ipv4", .field "protocol" [6]⟩, ⟨"tcp", "ipv6", .field "next_header" [6]⟩,
          ⟨"udp", "ipv4", .field "protocol" [17]⟩, ⟨"udp", "ipv6", .field "next_header" [17]⟩,
          ⟨"vxlan", "udp", .field "dport" [4789, 8472]⟩]
      ++ ether "mpls" 0x8847 ++ [⟨"mpls", "mpls", .noCheck⟩] }

example : ipv4Spec.fixedLen = 20 ∧ tcpSpec.fixedLen = 20 ∧ ipv6Spec.fixedLen = 40 := by decide
example : ipv4Spec.field? "ttl" = some ⟨"ttl", 64, 8⟩ := by decide

end Kunai
