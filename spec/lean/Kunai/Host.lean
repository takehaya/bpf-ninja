/-!
# Host parameters

Mirror of `codegen.Capabilities` / `HostLayout` (`pkg/kunai/codegen/caps.go`)
and the adapters in `pkg/kunai/host/*`. `action` is the runtime value an
fexit host observed (the program's return value); it is input to the
evaluator because it is not part of the packet.
-/
namespace Kunai

/-- A set the host declares for `field in @name` (`--set name=…`,
`LangCaps.SetSlots`): the key width in bits (8, 16, 32, 64 or 128, the
`set create` key types) and the keys the map holds. The filter extracts
the key and the host looks it up after the filter; the spec folds that
lookup into the verdict (D-036). Only scalar sets are modelled: a
composite key (several fields, the unwritten ones zero-filled by the host)
is outside the spec. -/
structure SetDecl where
  name : String
  width : Nat
  members : List Nat
  deriving Repr, BEq, DecidableEq

structure Host where
  packetStartsAtL3 : Bool := false
  /-- The kernel moved the outer VLAN tag (802.1Q or 802.1ad) into skb
  metadata before the program ran, so it is not in the packet bytes. -/
  vlanInMetadata : Bool := false
  /-- Symbolic action names the host declares (`LangCaps.Action`); empty on entry hosts. -/
  actions : List (String × Nat) := []
  /-- Observed action value (fexit only; ignored when `actions` is empty). -/
  action : Nat := 0
  /-- Sets declared for `in @name`; an undeclared name is ill-typed. -/
  sets : List SetDecl := []
  deriving Repr, BEq, DecidableEq

/-- The declaration of set `name`, if the host has one. -/
def Host.set? (h : Host) (name : String) : Option SetDecl := h.sets.find? (·.name == name)

inductive HostKind
  | xdp_entry | xdp_exit | tc_entry | tc_exit
  | cgroup_skb_entry | cgroup_skb_exit | netfilter_entry | netfilter_exit
  deriving Repr, BEq, DecidableEq

def HostKind.text : HostKind → String
  | .xdp_entry => "xdp_entry" | .xdp_exit => "xdp_exit"
  | .tc_entry => "tc_entry" | .tc_exit => "tc_exit"
  | .cgroup_skb_entry => "cgroup_skb_entry" | .cgroup_skb_exit => "cgroup_skb_exit"
  | .netfilter_entry => "netfilter_entry" | .netfilter_exit => "netfilter_exit"

def xdpActions : List (String × Nat) :=
  [("XDP_ABORTED", 0), ("XDP_DROP", 1), ("XDP_PASS", 2), ("XDP_TX", 3), ("XDP_REDIRECT", 4)]

/-- `host/tc`: TC_ACT_UNSPEC is -1 in Go; actions are compared as unsigned 32-bit. -/
def tcActions : List (String × Nat) :=
  [("TC_ACT_UNSPEC", 2 ^ 32 - 1), ("TC_ACT_OK", 0), ("TC_ACT_RECLASSIFY", 1), ("TC_ACT_SHOT", 2),
   ("TC_ACT_PIPE", 3), ("TC_ACT_STOLEN", 4), ("TC_ACT_QUEUED", 5), ("TC_ACT_REPEAT", 6),
   ("TC_ACT_REDIRECT", 7), ("TC_ACT_TRAP", 8)]

def cgroupSkbActions : List (String × Nat) := [("SK_DROP", 0), ("SK_PASS", 1)]
def netfilterActions : List (String × Nat) := [("NF_DROP", 0), ("NF_ACCEPT", 1)]

/-- Static host parameters; `action` and `sets` are supplied per vector. -/
def HostKind.host (k : HostKind) (action : Nat := 0) (sets : List SetDecl := []) : Host :=
  let h : Host := match k with
    | .xdp_entry => {}
    | .xdp_exit => { actions := xdpActions, action }
    | .tc_entry => { vlanInMetadata := true }
    | .tc_exit => { vlanInMetadata := true, actions := tcActions, action }
    | .cgroup_skb_entry => { vlanInMetadata := true, packetStartsAtL3 := true }
    | .cgroup_skb_exit => { vlanInMetadata := true, packetStartsAtL3 := true, actions := cgroupSkbActions, action }
    | .netfilter_entry => { vlanInMetadata := true, packetStartsAtL3 := true }
    | .netfilter_exit => { vlanInMetadata := true, packetStartsAtL3 := true, actions := netfilterActions, action }
  { h with sets }

/-- `name` is a VLAN tag protocol whose outer instance this host keeps in
metadata (D-008): such a layer must be optional. -/
def Host.tagInMetadata (H : Host) (name : String) : Bool :=
  H.vlanInMetadata && (name == "vlan" || name == "qinq")

end Kunai
