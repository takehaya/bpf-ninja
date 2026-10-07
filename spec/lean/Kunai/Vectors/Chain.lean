import Kunai.Vectors.Base

/-!
# Chain, quantifier, alternation, and host vectors
-/
namespace Kunai
open Pkt

def vlanPkt (tci : Nat := 100) : Packet := eth 0x8100 ++ vlan tci 0x0800 ++ ipv4 6 ++ tcp 12345 80 ++ payload 5
def mpls3 : Packet := eth 0x8847 ++ mpls 5 0 ++ mpls 6 0 ++ mpls 7 1 ++ ipv4 6 ++ tcp 12345 80 ++ payload 5
def mpls1 : Packet := eth 0x8847 ++ mpls 5 1 ++ ipv4 6 ++ tcp 12345 80 ++ payload 5
def ipv6TCP : Packet := eth 0x86DD ++ ipv6 6 ++ tcp 12345 80 ++ payload 5
def vxlanPkt (dport : Nat := 4789) : Packet :=
  eth 0x0800 ++ ipv4 17 ++ udp 1234 dport ++ vxlan 100 ++ eth 0x0800 ++ ipv4 6 ++ tcp 12345 80 ++ payload 5
def ihl6Pkt : Packet := eth 0x0800 ++ ipv4 6 (ihl := 6) (options := [1, 1, 1, 1]) ++ tcp 12345 80 ++ payload 5
def doff8Pkt : Packet := eth 0x0800 ++ ipv4 6 ++ tcp 12345 80 (dataOffset := 8) (options := List.replicate 12 1) ++ payload 5
def ipipPkt : Packet := eth 0x0800 ++ ipv4 4 (ttl := 32) ++ ipv4 6 ++ tcp 12345 80 ++ payload 5
def l3Pkt : Packet := ipv4 6 ++ tcp 12345 80 ++ payload 5

-- §13.3 / §13.4 ------------------------------------------------------------

vector chainAccept := {
  id := "chain-eth-ipv4-tcp", ast := { layers := chain3 }, expected := .accept [] }
vector chainUDPMiss := {
  id := "chain-dispatch-miss-l4", ast := { layers := [P "eth", P "ipv4", P "udp"] },
  expected := .reject, note := "ipv4.protocol = 6, udp needs 17 [E-Layer-Proto-1-Fail-Disp]" }
vector chainIPv6Miss := {
  id := "chain-dispatch-miss-l3", ast := { layers := [P "eth", P "ipv6", P "tcp"] },
  expected := .reject, note := "eth.ethertype = 0x0800, ipv6 needs 0x86DD" }
vector chainTruncIPv4 := {
  id := "chain-truncated-ipv4", ast := { layers := chain3 },
  packet := ethIPv4TCP.take 30, expected := .reject, note := "[E-Layer-Proto-1-Fail-Bounds] inside ipv4" }
vector chainTruncTCP := {
  id := "chain-truncated-tcp", ast := { layers := chain3 },
  packet := ethIPv4TCP.take 50, expected := .reject, note := "[E-Layer-Proto-1-Fail-Bounds] inside tcp" }
vector chainExact := {
  id := "chain-exact-fit", ast := { layers := chain3 },
  packet := ethIPv4TCP.take 54, expected := .accept [], note := "π + |tcp| = |P| is in bounds" }
vector chainIHL6 := {
  id := "chain-ipv4-ihl6",
  ast := { layers := chain3, cond := some (.arith (fld "tcp" "dport") .eq (k 80)) },
  packet := ihl6Pkt, expected := .accept [], note := "total_bytes(ipv4) = ihl*4 = 24 moves the cursor past the options" }
vector chainIHL6Trunc := {
  id := "chain-ipv4-ihl6-truncated", ast := { layers := chain3 },
  packet := ihl6Pkt.take 36, expected := .reject, note := "declared 24-byte header, only 22 bytes present" }
vector chainIHL4 := {
  id := "chain-ipv4-ihl4", ast := { layers := chain3 },
  packet := eth 0x0800 ++ ipv4 6 (ihl := 4) ++ tcp 12345 80 ++ payload 5, expected := .reject, note := "D-016" }
vector chainVersion5 := {
  id := "chain-ipv4-version5", ast := { layers := chain3 },
  packet := eth 0x0800 ++ ipv4 6 (version := 5) ++ tcp 12345 80 ++ payload 5, expected := .reject, note := "D-017 self-validation" }
vector chainDoff8 := {
  id := "chain-tcp-dataoffset8",
  ast := { layers := chain3, cond := some (.arith (fld "tcp" "dport") .eq (k 80)) },
  packet := doff8Pkt, expected := .accept [] }
vector chainDoff4 := {
  id := "chain-tcp-dataoffset4", ast := { layers := chain3 },
  packet := eth 0x0800 ++ ipv4 6 ++ tcp 12345 80 (dataOffset := 4) ++ payload 5, expected := .reject, note := "D-016" }
vector chainDoff8Trunc := {
  id := "chain-tcp-declared-exceeds", ast := { layers := chain3 },
  packet := doff8Pkt.take 60, expected := .reject, note := "data_offset = 8 declares 32 bytes, 26 present" }
vector chainVlan := {
  id := "chain-vlan", ast := { layers := [P "eth", P "vlan", P "ipv4", P "tcp"] },
  packet := vlanPkt, expected := .accept [] }
vector chainVlanMissing := {
  id := "chain-vlan-missing", ast := { layers := [P "eth", P "vlan", P "ipv4", P "tcp"] },
  expected := .reject }
vector chainIPv6 := {
  id := "chain-ipv6-tcp", ast := { layers := [P "eth", P "ipv6", P "tcp"] },
  packet := ipv6TCP, expected := .accept [] }
vector chainVxlan := {
  id := "chain-vxlan",
  ast := { layers := [P "eth", P "ipv4", P "udp", P "vxlan", P "eth", P "ipv4", P "tcp"] },
  packet := vxlanPkt, expected := .accept [], note := "eth under vxlan is a NO_CHECK edge" }
vector chainVxlanAlt := {
  id := "chain-vxlan-alt-port",
  ast := { layers := [P "eth", P "ipv4", P "udp", P "vxlan"] },
  packet := vxlanPkt 8472, expected := .accept [], note := "KUNAI_VXLAN_UDP_DPORT_ALT_LINUX_LEGACY" }
vector chainMplsSingle := {
  id := "chain-mpls-single", ast := { layers := [P "eth", P "mpls", P "ipv4", P "tcp"] },
  packet := mpls1, expected := .accept [] }
vector chainMplsSingleOverrun := {
  id := "chain-mpls-single-overrun", ast := { layers := [P "eth", P "mpls", P "ipv4", P "tcp"] },
  packet := mpls3, expected := .reject, note := "ipv4 parsed at the 2nd label: version ≠ 4" }

-- §13.5 ---------------------------------------------------------------------

def vlanOpt : List Layer := [P "eth", Pq "vlan" .opt, P "ipv4", P "tcp"]
def mplsRange (lo : Nat) (hi : Option Nat) : List Layer := [P "eth", Pq "mpls" (.range lo hi), P "ipv4", P "tcp"]
def mplsPred (v : Nat) (op : CmpOp) (q : Quant) : List Layer :=
  [P "eth", .proto { name := "mpls", preds := [.cmp (f "label") op (.int v)], quant := q }, P "ipv4", P "tcp"]

vector quantOptPresent := {
  id := "quant-opt-present", ast := { layers := vlanOpt }, packet := vlanPkt, expected := .accept [] }
vector quantOptAbsent := {
  id := "quant-opt-absent", ast := { layers := vlanOpt }, expected := .accept [],
  note := "[E-Quant-Optional] case B" }
vector quantOptPredHolds := {
  id := "quant-opt-pred-holds",
  ast := { layers := [P "eth", .proto { name := "vlan", preds := [.cmp (f "tci") .eq (.int 100)], quant := .opt }, P "ipv4", P "tcp"] },
  packet := vlanPkt, expected := .accept [] }
vector quantOptPredFails := {
  id := "quant-opt-pred-fails",
  ast := { layers := [P "eth", .proto { name := "vlan", preds := [.cmp (f "tci") .eq (.int 200)], quant := .opt }, P "ipv4", P "tcp"] },
  packet := vlanPkt, expected := .reject, note := "D-001: dispatch matched, predicate false ⇒ ✗, not skip" }
vector quantOptBounds := {
  id := "quant-opt-bounds-reject", ast := { layers := [P "eth", Pq "vlan" .opt] },
  packet := vlanPkt.take 16, expected := .reject, note := "D-005: case B needs a dispatch miss; bounds failure is ✗" }
vector quantRangeMidTrunc := {
  id := "quant-range-truncated-mid-chain", ast := { layers := [P "eth", Pq "mpls" (.range 1 (some 8))] },
  packet := (eth 0x8847 ++ mpls 5 0 ++ mpls 6 0).take 20, expected := .reject,
  note := "D-005: the 2nd label is cut after 2 bytes ⇒ ✗" }
vector quantRange01Bounds := {
  id := "quant-range01-bounds-skip", ast := { layers := [P "eth", Pq "vlan" (.range 0 (some 1))] },
  packet := vlanPkt.take 16, expected := .reject,
  note := "D-005: bounds failure is ✗ for every quantifier; `?` ≡ `{0,1}` (Laws.lean: opt_eq_range)" }
vector quantStarBounds := {
  id := "quant-star-bounds-skip", ast := { layers := [P "eth", Pq "vlan" .star] },
  packet := vlanPkt.take 16, expected := .reject, note := "D-005: dispatch matched, header truncated ⇒ ✗" }
vector quantMplsRange := {
  id := "quant-mpls-range", ast := { layers := mplsRange 1 (some 8) }, packet := mpls3, expected := .accept [] }
vector quantMplsPlus := {
  id := "quant-mpls-plus", ast := { layers := mplsRange 1 none }, packet := mpls3, expected := .accept [] }
vector quantMplsStarZero := {
  id := "quant-mpls-star-zero", ast := { layers := mplsRange 0 none }, expected := .accept [],
  note := "k = 0 on a plain ipv4 packet" }
vector quantMplsMinUnmet := {
  id := "quant-mpls-min-unmet", ast := { layers := mplsRange 2 (some 8) }, packet := mpls1,
  expected := .reject, note := "[E-Quant-Range-Fail]: chain end after 1 label, n = 2" }
vector quantChainEnd := {
  id := "quant-mpls-chain-end", ast := { layers := mplsRange 1 (some 8) }, packet := mpls1,
  expected := .accept [], note := "MPLS_CHAIN_END_S: s = 1 stops the self-chain, k = 1" }
vector quantGreedyOverrun := {
  id := "quant-range-greedy-overrun", ast := { layers := mplsRange 1 (some 2) }, packet := mpls3,
  expected := .reject, note := "D-002: greedy takes 2 labels; ipv4 then fails at the 3rd" }
vector quantOverrunBounded := {
  id := "quant-overrun-bounded", ast := { layers := [P "eth", Pq "mpls" (.range 1 (some 2))] }, packet := mpls3,
  expected := .reject, note := "D-024: the 2nd label has s = 0, so the stack is deeper than {1,2} allows" }
vector quantOverrunOpen := {
  id := "quant-overrun-open", ast := { layers := [P "eth", Pq "mpls" .plus] },
  packet := eth 0x8847 ++ mpls 1 0 ++ mpls 2 0 ++ mpls 3 0 ++ mpls 4 0 ++ mpls 5 0 ++ mpls 6 0 ++ mpls 7 0 ++ mpls 8 0 ++ mpls 9 1,
  expected := .reject,
  note := "D-024: 9 labels exceed MPLS_MAX_DEPTH = 8 and the 8th has s = 0; the bpf_loop path requires the end signal at the cap too" }
vector quantExactBound := {
  id := "quant-exact-bound", ast := { layers := [P "eth", Pq "mpls" (.range 1 (some 3))] }, packet := mpls3,
  expected := .accept [], note := "3 labels, the 3rd has s = 1: bound reached with the end signal" }
vector quantOptMplsOverrun := {
  id := "quant-opt-mpls-overrun", ast := { layers := [P "eth", Pq "mpls" .opt, P "ipv4", P "tcp"] },
  packet := eth 0x8847 ++ mpls 5 0 ++ mpls 6 1 ++ ipv4 6 ++ tcp 12345 80 ++ payload 5, expected := .reject,
  note := "D-024: `?` requires the end signal after one label, like {0,1}" }
vector quantOptMplsOne := {
  id := "quant-opt-mpls-one", ast := { layers := [P "eth", Pq "mpls" .opt, P "ipv4", P "tcp"] }, packet := mpls1, expected := .accept [] }
vector quantGreedyUnreachable := {
  id := "quant-greedy-unreachable",
  ast := { layers := [P "eth", Pq "mpls" (.range 1 (some 8)), P "mpls", P "ipv4", P "tcp"] }, packet := mpls3,
  expected := .reject, note := "D-002: `mpls{1,8}/mpls` never matches" }
vector quantPredMidFail := {
  id := "quant-pred-mid-fail", ast := { layers := mplsPred 5 .eq (.range 1 (some 8)) }, packet := mpls3,
  expected := .reject, note := "D-001 (b): a predicate failure at any iteration rejects" }
vector quantPredMidFailStatic := {
  id := "quant-pred-mid-fail-static", ast := { layers := mplsPred 5 .eq (.range 1 (some 3)) }, packet := mpls3,
  expected := .reject, note := "D-001 (b); static unroll agrees" }
vector quantPredFirstFail := {
  id := "quant-pred-first-fail", ast := { layers := mplsPred 6 .eq (.range 1 (some 8)) }, packet := mpls3,
  expected := .reject }
vector quantPredAllHold := {
  id := "quant-pred-all-hold", ast := { layers := mplsPred 8 .lt (.range 1 (some 8)) }, packet := mpls3,
  expected := .accept [] }
vector quantSelfValidSkip := {
  id := "quant-selfvalidating-skip", ast := { layers := [P "eth", P "mpls", Pq "ipv4" .opt] },
  packet := eth 0x8847 ++ mpls 5 1 ++ ipv6 6 ++ tcp 1 80, expected := .accept [],
  note := "D-017: no parent constant for ipv4 under mpls, so version = 6 is a dispatch miss and ipv4? skips (Go: a probe of the fields the parser's select requires)" }
def mplsOptIPv4 : List Layer := [P "eth", P "mpls", Pq "ipv4" .opt]
vector quantSelfValidPresent := {
  id := "quant-selfvalidating-present", ast := { layers := mplsOptIPv4 },
  packet := eth 0x8847 ++ mpls 5 1 ++ ipv4 6 ++ tcp 1 80, expected := .accept [] }
vector quantSelfValidShortV4 := {
  id := "quant-selfvalidating-short-v4", ast := { layers := mplsOptIPv4 },
  packet := eth 0x8847 ++ mpls 5 1 ++ [0x45], expected := .reject,
  note := "D-017: version 4 is readable, so the layer is present and its truncated header is a bounds failure" }
vector quantSelfValidShortV6 := {
  id := "quant-selfvalidating-short-v6", ast := { layers := mplsOptIPv4 },
  packet := eth 0x8847 ++ mpls 5 1 ++ [0x60], expected := .accept [],
  note := "version 6 in the one byte that follows: a miss, the layer is skipped" }
vector quantSelfValidEmpty := {
  id := "quant-selfvalidating-empty", ast := { layers := mplsOptIPv4 },
  packet := eth 0x8847 ++ mpls 5 1, expected := .reject,
  note := "D-017: nothing to read is not a miss; the layer falls through to its bounds check" }
vector quantSelfValidCascade := {
  id := "quant-selfvalidating-cascade", ast := { layers := [P "eth", Pq "vlan" .opt, Pq "mpls" .opt, Pq "ipv4" .opt] },
  packet := eth 0x8847 ++ mpls 5 1 ++ ipv6 6 ++ tcp 1 80, expected := .accept [],
  note := "ipv4? under the runtime parent mpls (no constant: probe) or vlan / eth (ethertype)" }
vector quantSelfValidCascadeEth := {
  id := "quant-selfvalidating-cascade-eth", ast := { layers := [P "eth", Pq "vlan" .opt, Pq "mpls" .opt, Pq "ipv4" .opt] },
  expected := .accept [], note := "both optionals absent: ipv4 dispatches on eth.ethertype" }
vector quantSelfValidBroken := {
  id := "quant-selfvalidating-broken", ast := { layers := [P "eth", Pq "ipv4" .opt] },
  packet := eth 0x0800 ++ ipv4 6 (version := 5) ++ tcp 12345 80 ++ payload 5, expected := .reject,
  note := "D-017: eth.ethertype already says ipv4, so version = 5 is a broken header, not absence" }
vector quantOptIPv4Last := {
  id := "quant-opt-ipv4-last", ast := { layers := [P "eth", Pq "ipv4" .opt] }, expected := .accept [],
  note := "an optional variable-length layer at the end of the chain, present" }
vector quantOptIPv4LastAbsent := {
  id := "quant-opt-ipv4-last-absent", ast := { layers := [P "eth", Pq "ipv4" .opt] },
  packet := eth 0x0806 ++ payload 5, expected := .accept [],
  note := "ethertype is not ipv4: the layer is skipped before its bounds are checked (5 bytes follow, fewer than an ipv4 header)" }
vector quantOptIPIP := {
  id := "quant-opt-ipip", ast := { layers := [P "eth", P "ipv4", Pq "ipv4" .opt, P "tcp"] },
  packet := eth 0x0800 ++ ipv4 4 ++ ipv4 6 ++ tcp 12345 80 ++ payload 5, expected := .accept [],
  note := "ipv4 in ipv4 present: tcp dispatches on the inner header" }
def ipipTwice : List Layer := [P "eth", P "ipv4", Pq "ipv4" .opt, Pq "ipv4" .opt, P "tcp"]
vector quantOptIPIPTwiceOne := {
  id := "quant-opt-ipip-twice-one", ast := { layers := ipipTwice },
  packet := eth 0x0800 ++ ipv4 4 ++ ipv4 6 ++ tcp 12345 80 ++ payload 5, expected := .accept [],
  note := "the first optional takes the inner header, the second is absent; tcp dispatches on whichever ipv4 came last" }
vector quantOptIPIPTwiceNone := {
  id := "quant-opt-ipip-twice-none", ast := { layers := ipipTwice }, expected := .accept [] }
vector quantOptIPIPTwiceBoth := {
  id := "quant-opt-ipip-twice-both", ast := { layers := ipipTwice },
  packet := eth 0x0800 ++ ipv4 4 ++ ipv4 4 ++ ipv4 6 ++ tcp 12345 80 ++ payload 5, expected := .accept [] }
vector quantExactOneMachine := {
  id := "quant-exact-one-machine", ast := { layers := [P "eth", Pq "ipv4" (.range 1 (some 1)), P "tcp"] },
  packet := ihl6Pkt, expected := .accept [],
  note := "{1,1} is the plain layer: the header length rule still moves the cursor past the options" }
vector typAltExactOne := {
  id := "typ-alt-exact-one", ast := { layers := [P "eth", .alt [{ name := "ipv4", quant := .range 1 (some 1) }, { name := "ipv6" }], P "tcp"] },
  expected := .illTyped "alternatives cannot carry quantifiers",
  note := "{1,1} is still a quantifier where the typing rules look at one" }
vector typRepeatNoSelfEdge := {
  id := "typ-repeat-no-self-edge", ast := { layers := [P "eth", P "ipv6", Pq "srv6" (.range 0 (some 2)), P "tcp"] },
  expected := .illTyped "repeated srv6 needs a dispatch constant under itself",
  note := "D-037: srv6 declares no srv6-under-srv6 constant; one optional header (`srv6?`) is fine" }
vector typRepeatNoSelfEdgeStar := {
  id := "typ-repeat-no-self-edge-star", ast := { layers := [P "eth", P "ipv4", Pq "gre" .star, P "ipv4", P "tcp"] },
  expected := .illTyped "repeated gre needs a dispatch constant under itself" }
vector quantOptIPIPAbsent := {
  id := "quant-opt-ipip-absent", ast := { layers := [P "eth", P "ipv4", Pq "ipv4" .opt, P "tcp"] },
  expected := .accept [], note := "no inner ipv4: tcp dispatches on the outer header (D-034)" }
vector typOptionalAfterSkip := {
  id := "typ-no-dispatch-after-skip", ast := { layers := [P "eth", Pq "ipv4" .opt, P "tcp"] },
  expected := .illTyped "no dispatch constant for tcp under eth",
  note := "if ipv4 is skipped, tcp sits under eth with no constant (the resolver rejects it too)" }
vector typOptionalNoCheck := {
  id := "typ-optional-nocheck", ast := { layers := [P "eth", P "ipv4", P "udp", P "vxlan", Pq "eth" .opt, P "ipv4", P "tcp"] },
  packet := vxlanPkt, expected := .illTyped "optional eth with no-check dispatch cannot detect absence" }
vector chainMandatorySelfEdgeMiss := {
  id := "chain-mpls-self-edge-miss", ast := { layers := [P "eth", P "mpls", P "mpls", P "ipv4", P "tcp"] }, packet := mpls1,
  expected := .reject, note := "parent_dispatch: the first label has s = 1, so the second mpls is a dispatch miss and, being mandatory, rejects" }
vector quantSelfEdgeStar := {
  id := "quant-self-edge-star", ast := { layers := [P "eth", P "mpls", Pq "mpls" .star, P "ipv4", P "tcp"] },
  packet := mpls3, expected := .accept [],
  note := "NO_CHECK self-edge with CHAIN_END: the s bit of the previous label detects absence" }
vector quantSelfEdgeOpt := {
  id := "quant-self-edge-opt", ast := { layers := [P "eth", P "mpls", Pq "mpls" .opt, P "ipv4", P "tcp"] },
  packet := mpls1, expected := .accept [],
  note := "skips on the s bit of the first label" }
vector absentConsecutiveEthertype := {
  id := "absent-consecutive-ethertype", ast := { layers := [P "eth", Pq "qinq" .opt, Pq "vlan" .opt, P "ipv4", P "tcp"] },
  packet := vlanPkt, expected := .accept [],
  note := "D-034: qinq absent, vlan present; ipv4 dispatches on vlan.ethertype (Go: same bytes as eth/qinq, static-parent read is sound)" }
vector absentConsecutiveSelfValid := {
  id := "absent-consecutive-selfvalidating", ast := { layers := [P "eth", Pq "vlan" .opt, Pq "mpls" .opt, P "ipv4", P "tcp"] },
  packet := vlanPkt, expected := .accept [],
  note := "D-034: vlan present, mpls absent; ipv4 dispatches on vlan.ethertype (Go: a cascade on the optionals' entry slots picks the runtime parent)" }
vector absentConsecutiveMplsOnly := {
  id := "absent-consecutive-mpls-only", ast := { layers := [P "eth", Pq "vlan" .opt, Pq "mpls" .opt, P "ipv4", P "tcp"] },
  packet := mpls1, expected := .accept [], note := "D-034: vlan absent, mpls present; ipv4 self-validates under mpls" }
vector absentConsecutiveNeither := {
  id := "absent-consecutive-neither", ast := { layers := [P "eth", Pq "vlan" .opt, Pq "mpls" .opt, P "ipv4", P "tcp"] },
  expected := .accept [], note := "D-034: both absent; ipv4 dispatches on eth.ethertype" }
vector absentConsecutiveArp := {
  id := "absent-consecutive-non-ip", ast := { layers := [P "eth", Pq "vlan" .opt, Pq "mpls" .opt, P "ipv4", P "tcp"] },
  packet := eth 0x0806 ++ ipv4 6 ++ tcp 12345 80 ++ payload 5, expected := .reject,
  note := "D-034: both absent and eth.ethertype is not ipv4; the self-validating version nibble alone would have accepted" }
vector quantFirstOptional := {
  id := "quant-first-optional", ast := { layers := [Pq "vlan" .opt, P "ipv4"] },
  expected := .illTyped "the first layer cannot be optional" }

-- Alternation (D-004, D-010) -----------------------------------------------

def vxlan6Pkt (inner : Packet) : Packet :=
  eth 0x86DD ++ ipv6 17 ++ udp 1234 4789 ++ vxlan 100 ++ inner ++ tcp 12345 80 ++ payload 5
def vxlanAltL : List Layer :=
  [P "eth", P "ipv6", P "udp", P "vxlan", P "eth", .alt [{ name := "ipv4" }, { name := "ipv6" }]]
set_option maxRecDepth 16384 in
vector altAfterVxlan6 := {
  id := "alt-after-vxlan-ipv6", ast := { layers := vxlanAltL }, packet := vxlan6Pkt (eth 0x86DD ++ ipv6 6),
  expected := .accept [],
  note := "the inner group's parent starts at a runtime offset; its member guard reads through a bounded cursor" }
set_option maxRecDepth 16384 in
vector altAfterVxlan4 := {
  id := "alt-after-vxlan-ipv4", ast := { layers := vxlanAltL }, packet := vxlan6Pkt (eth 0x0800 ++ ipv4 6),
  expected := .accept [] }
def altL3 : List Layer := [P "eth", .alt [{ name := "ipv4" }, { name := "ipv6" }], P "tcp"]

vector altFirst := {
  id := "alt-first", ast := { layers := altL3 }, expected := .accept [] }
vector altSecond := {
  id := "alt-second", ast := { layers := altL3 }, packet := ipv6TCP, expected := .accept [] }
vector altNone := {
  id := "alt-none", ast := { layers := altL3 }, packet := eth 0x0806 ++ payload 28, expected := .reject }
vector altFirstPredFails := {
  id := "alt-first-pred-fails",
  ast := { layers := [P "eth", .alt [{ name := "ipv4", preds := [.cmp (f "ttl") .eq (.int 1)] }, { name := "ipv4" }], P "tcp"] },
  expected := .reject,
  note := "[E-Layer-Alt-First]: the first alternative commits" }
vector altRoot := {
  id := "alt-root-illtyped", ast := { layers := [.alt [{ name := "ipv4" }, { name := "ipv6" }], P "tcp"] },
  packet := l3Pkt, expected := .illTyped "alternation cannot be the first layer" }
vector altNoCheck := {
  id := "alt-nocheck-illtyped",
  ast := { layers := [P "eth", P "mpls", .alt [{ name := "eth" }, { name := "ipv4" }]] }, packet := mpls1,
  expected := .illTyped "alternative eth needs a field dispatch under mpls" }

-- Host (D-008) -----------------------------------------------------------------

-- bpf-ninja's tc host puts the outer tag back from skb metadata, so the
-- filter sees the wire frame: tags parse as at any other host.
def qinqVlanPkt : Packet := eth 0x88a8 ++ vlan 10 0x8100 ++ vlan 100 0x0800 ++ ipv4 6 ++ tcp 12345 80 ++ payload 5
def vlanTci (op : CmpOp) (v : Nat) : ProtoLayer := { name := "vlan", preds := [.cmp ⟨[("tci", none)]⟩ op (.int v)] }
vector hostTcWireVlanMandatory := {
  id := "host-tc-vlan-mandatory", host := .tc_entry, ast := { layers := [P "eth", P "vlan", P "ipv4", P "tcp"] },
  packet := vlanPkt, expected := .accept [], note := "D-008: the tc host hands the filter the wire frame" }
vector hostTcWireVlanMandatoryUntagged := {
  id := "host-tc-vlan-mandatory-untagged", host := .tc_entry, ast := { layers := [P "eth", P "vlan", P "ipv4", P "tcp"] },
  packet := eth 0x0800 ++ ipv4 6 ++ tcp 12345 80 ++ payload 5, expected := .reject }
vector hostTcWireVlanTci := {
  id := "host-tc-vlan-tci", host := .tc_entry, ast := { layers := [P "eth", .proto (vlanTci .eq 100), P "ipv4", P "tcp"] },
  packet := vlanPkt, expected := .accept [] }
vector hostTcWireVlanTciMiss := {
  id := "host-tc-vlan-tci-miss", host := .tc_entry, ast := { layers := [P "eth", .proto (vlanTci .eq 200), P "ipv4", P "tcp"] },
  packet := vlanPkt, expected := .reject }
vector hostTcWireVlanWhere := {
  id := "host-tc-vlan-where", host := .tc_exit, action := 0,
  ast := { layers := [P "eth", Pq "vlan" .opt, P "ipv4", P "tcp"],
           cond := some (.and (.arith (.field ⟨[("vlan", none), ("tci", none)]⟩) .eq (.const 100)) (.action "TC_ACT_OK")) },
  packet := vlanPkt, expected := .accept [] }
vector hostTcWireUntaggedChainOnTagged := {
  id := "host-tc-untagged-chain-on-tagged", host := .tc_entry, ast := { layers := chain3 }, packet := vlanPkt,
  expected := .reject, note := "eth/ipv4/tcp does not match a tagged frame at tc either" }
vector hostTcWireQinqVlan := {
  id := "host-tc-qinq-vlan", host := .tc_entry,
  ast := { layers := [P "eth", .proto { name := "qinq", preds := [.cmp ⟨[("tci", none)]⟩ .eq (.int 10)] }, .proto (vlanTci .eq 100), P "ipv4", P "tcp"] },
  packet := qinqVlanPkt, expected := .accept [],
  note := "the kernel moves only the 802.1ad tag to metadata; the 802.1Q tag stays in the bytes behind it" }
vector hostTcWireVlanAlt := {
  id := "host-tc-vlan-alt", host := .tc_entry,
  ast := { layers := [P "eth", .alt [{ name := "vlan" }, { name := "qinq" }], P "ipv4", P "tcp"] }, packet := vlanPkt,
  expected := .accept [] }

-- A tc host that does not put the tag back (tc_raw_entry) keeps the old rule.


vector hostTcRawVlanMandatory := {
  id := "host-tc-raw-vlan-mandatory", host := .tc_raw_entry,
  ast := { layers := [P "eth", P "vlan", P "ipv4", P "tcp"] }, packet := vlanPkt,
  expected := .illTyped "vlan is in metadata on this host; the layer must be optional" }
vector hostTcRawVlanAlt := {
  id := "host-tc-raw-vlan-alt", host := .tc_raw_entry,
  ast := { layers := [P "eth", .alt [{ name := "vlan" }, { name := "qinq" }], P "ipv4", P "tcp"] }, packet := vlanPkt,
  expected := .illTyped "vlan is in metadata on this host; the layer must be optional",
  note := "an alternation member is mandatory" }
vector hostTcRawVlanAltSecond := {
  id := "host-tc-raw-vlan-alt-second", host := .tc_raw_entry,
  ast := { layers := [P "eth", .alt [{ name := "qinq" }, { name := "vlan" }], P "ipv4", P "tcp"] }, packet := vlanPkt,
  expected := .illTyped "qinq is in metadata on this host; the layer must be optional" }
vector hostTcRawQinqVlan := {
  id := "host-tc-raw-qinq-vlan", host := .tc_raw_entry,
  ast := { layers := [P "eth", P "qinq", P "vlan", P "ipv4", P "tcp"] }, packet := vlanPkt,
  expected := .illTyped "qinq is in metadata on this host; the layer must be optional",
  note := "both tags are mandatory; the first is reported" }
vector hostTcRawQinqMandatory := {
  id := "host-tc-raw-qinq-mandatory", host := .tc_raw_entry,
  ast := { layers := [P "eth", P "qinq", P "ipv4", P "tcp"] }, packet := vlanPkt,
  expected := .illTyped "qinq is in metadata on this host; the layer must be optional",
  note := "the kernel moves an 802.1ad outer tag to metadata like an 802.1Q one" }
vector hostTcRawQinqOpt := {
  id := "host-tc-raw-qinq-optional", host := .tc_raw_entry,
  ast := { layers := [P "eth", Pq "qinq" .opt, Pq "vlan" .opt, P "ipv4", P "tcp"] }, packet := vlanPkt,
  expected := .accept [] }
def vxlanInnerVlanPkt (tci : Nat := 100) : Packet :=
  eth 0x0800 ++ ipv4 17 ++ udp 1234 4789 ++ vxlan 100 ++ eth 0x8100 ++ vlan tci 0x0800 ++ ipv4 6 ++ tcp 12345 80 ++ payload 5
def vxlanInnerVlanL : List Layer := [P "eth", P "ipv4", P "udp", P "vxlan", P "eth", P "vlan", P "ipv4", P "tcp"]
set_option maxRecDepth 16384 in
vector hostTcRawInnerVlan := {
  id := "host-tc-raw-inner-vlan", host := .tc_raw_entry, ast := { layers := vxlanInnerVlanL }, packet := vxlanInnerVlanPkt,
  expected := .accept [], note := "D-008: only the outer tag is moved to metadata; a tag inside a tunnel is in the packet bytes" }
set_option maxRecDepth 16384 in
vector hostTcRawInnerVlanTci := {
  id := "host-tc-raw-inner-vlan-tci", host := .tc_raw_entry,
  ast := { layers := vxlanInnerVlanL, cond := some (.arith (.field ⟨[("vlan", none), ("tci", none)]⟩) .eq (.const 100)) },
  packet := vxlanInnerVlanPkt, expected := .accept [] }
set_option maxRecDepth 16384 in
vector hostTcRawInnerVlanPred := {
  id := "host-tc-raw-inner-vlan-bracket", host := .tc_raw_entry,
  ast := { layers := [P "eth", P "ipv4", P "udp", P "vxlan", P "eth", .proto { name := "vlan", preds := [.cmp ⟨[("tci", none)]⟩ .eq (.int 200)] }, P "ipv4", P "tcp"] },
  packet := vxlanInnerVlanPkt, expected := .reject, note := "the inner tag is read: tci 100 ≠ 200" }
set_option maxRecDepth 16384 in
vector hostTcRawOuterAndInner := {
  id := "host-tc-raw-outer-optional-inner-bracket", host := .tc_raw_entry,
  ast := { layers := [P "eth", Pq "vlan" .opt, P "ipv4", P "udp", P "vxlan", P "eth",
                      .proto { name := "vlan", preds := [.cmp ⟨[("tci", none)]⟩ .eq (.int 100)] }, P "ipv4", P "tcp"] },
  packet := vxlanInnerVlanPkt, expected := .accept [],
  note := "the same protocol twice: the outer vlan follows the root eth (metadata rules), the inner one is in the tunnel (read freely)" }
set_option maxRecDepth 16384 in
vector hostTcRawInnerLabel := {
  id := "host-tc-raw-inner-labelled-where", host := .tc_raw_entry,
  ast := { layers := [P "eth", .proto { name := "vlan", label := some "o", quant := .opt }, P "ipv4", P "udp", P "vxlan", P "eth",
                      .proto { name := "vlan", label := some "i" }, P "ipv4", P "tcp"],
           cond := some (.arith (.field ⟨[("i", none), ("tci", none)]⟩) .eq (.const 100)) },
  packet := vxlanInnerVlanPkt, expected := .accept [] }
set_option maxRecDepth 16384 in
vector hostTcRawOuterLabelRead := {
  id := "host-tc-raw-outer-labelled-where", host := .tc_raw_entry,
  ast := { layers := [P "eth", .proto { name := "vlan", label := some "o", quant := .opt }, P "ipv4", P "udp", P "vxlan", P "eth",
                      .proto { name := "vlan", label := some "i" }, P "ipv4", P "tcp"],
           cond := some (.not (.arith (.field ⟨[("o", none), ("tci", none)]⟩) .eq (.const 100))) },
  packet := vxlanInnerVlanPkt, expected := .accept [], goStatus := .notImplemented,
  note := "Go: reading the outer tag at a metadata host is refused (the tag is not in the bytes this host hands the filter)" }
vector hostTcRawMixedAlt := {
  id := "host-tc-raw-mixed-alt", host := .tc_raw_entry,
  ast := { layers := [P "eth", .alt [{ name := "vlan" }, { name := "ipv4" }], P "tcp"] }, packet := vlanPkt,
  expected := .illTyped "vlan is in metadata on this host; the layer must be optional",
  note := "a tag member of an alternation right after the root eth is an outer tag" }
vector hostTcRawVlanRoot := {
  id := "host-tc-raw-vlan-root", host := .tc_raw_entry, ast := { layers := [P "vlan", P "vlan", P "ipv4", P "tcp"] }, packet := vlanPkt,
  expected := .reject, note := "D-008: the rule concerns tags after a root eth; a chain rooted elsewhere is well-typed (and does not match an Ethernet frame)" }
set_option maxRecDepth 16384 in
vector hostL3InnerVlan := {
  id := "host-l3-inner-vlan", host := .cgroup_skb_entry,
  ast := { layers := [P "ipv4", P "udp", P "vxlan", P "eth", P "vlan", P "ipv4", P "tcp"] },
  packet := ipv4 17 ++ udp 1234 4789 ++ vxlan 100 ++ eth 0x8100 ++ vlan 100 0x0800 ++ ipv4 6 ++ tcp 12345 80 ++ payload 5,
  expected := .accept [], note := "an L3-rooted host: no root eth, so the tunnel's vlan is an ordinary layer" }
vector hostTcRawQinqOptVlan := {
  id := "host-tc-raw-qinq-opt-then-vlan", host := .tc_raw_entry,
  ast := { layers := [P "eth", Pq "qinq" .opt, P "vlan", P "ipv4", P "tcp"] }, packet := vlanPkt,
  expected := .illTyped "vlan is in metadata on this host; the layer must be optional",
  note := "only tags stand between the root eth and vlan, so it is still an outer tag" }
vector hostTcRawVlanOpt := {
  id := "host-tc-raw-vlan-optional", host := .tc_raw_entry, ast := { layers := vlanOpt }, expected := .accept [] }
vector hostL3Root := {
  id := "host-l3-ipv4-root", host := .cgroup_skb_entry, ast := { layers := [P "ipv4", P "tcp"] },
  packet := l3Pkt, expected := .accept [] }
vector hostL3EthRoot := {
  id := "host-l3-eth-root", host := .cgroup_skb_entry, ast := { layers := chain3 },
  packet := l3Pkt, expected := .reject, note := "D-008: warning only; eth is parsed from the ipv4 bytes and ipv4 then misses" }

def chainVectors : List Vector := [
  chainAccept, chainUDPMiss, chainIPv6Miss, chainTruncIPv4, chainTruncTCP, chainExact, chainIHL6, chainIHL6Trunc,
  chainIHL4, chainVersion5, chainDoff8, chainDoff4, chainDoff8Trunc, chainVlan, chainVlanMissing, chainIPv6,
  chainVxlan, chainVxlanAlt, chainMplsSingle, chainMplsSingleOverrun,
  quantOptPresent, quantOptAbsent, quantOptPredHolds, quantOptPredFails, quantOptBounds, quantRangeMidTrunc, quantRange01Bounds,
  quantStarBounds, quantMplsRange, quantMplsPlus, quantMplsStarZero, quantMplsMinUnmet, quantChainEnd,
  quantGreedyOverrun, quantOverrunBounded, quantOverrunOpen, quantExactBound, quantOptMplsOverrun, quantOptMplsOne, quantGreedyUnreachable, quantPredMidFail, quantPredMidFailStatic, quantPredFirstFail,
  quantPredAllHold, quantSelfValidSkip, quantSelfValidPresent, quantSelfValidShortV4, quantSelfValidShortV6, quantSelfValidEmpty, quantSelfValidCascade, quantSelfValidCascadeEth, quantSelfValidBroken, quantOptIPv4Last, quantOptIPv4LastAbsent, quantOptIPIP, quantExactOneMachine, typAltExactOne, typRepeatNoSelfEdge, typRepeatNoSelfEdgeStar, quantOptIPIPAbsent, quantOptIPIPTwiceOne, quantOptIPIPTwiceNone, quantOptIPIPTwiceBoth, typOptionalAfterSkip, typOptionalNoCheck, chainMandatorySelfEdgeMiss, quantSelfEdgeStar, quantSelfEdgeOpt,
  absentConsecutiveEthertype, absentConsecutiveSelfValid, absentConsecutiveMplsOnly, absentConsecutiveNeither, absentConsecutiveArp, quantFirstOptional,
  altFirst, altSecond, altAfterVxlan6, altAfterVxlan4, altNone, altFirstPredFails, altRoot, altNoCheck,
  hostTcWireVlanMandatory, hostTcWireVlanMandatoryUntagged, hostTcWireVlanTci, hostTcWireVlanTciMiss, hostTcWireVlanWhere, hostTcWireUntaggedChainOnTagged, hostTcWireQinqVlan, hostTcWireVlanAlt, hostTcRawVlanMandatory, hostTcRawVlanAlt, hostTcRawVlanAltSecond, hostTcRawQinqVlan, hostTcRawQinqMandatory, hostTcRawQinqOpt, hostTcRawInnerVlan, hostTcRawInnerVlanTci, hostTcRawInnerVlanPred, hostTcRawQinqOptVlan, hostTcRawOuterAndInner, hostTcRawInnerLabel, hostTcRawOuterLabelRead,
  hostTcRawMixedAlt, hostTcRawVlanRoot, hostL3InnerVlan, hostTcRawVlanOpt, hostL3Root, hostL3EthRoot]

end Kunai
