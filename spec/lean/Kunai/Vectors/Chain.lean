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
  note := "D-017: no parent constant for ipv4 under mpls, so version = 6 is a dispatch miss and ipv4? skips; Go: self-validating optional not implemented", goStatus := .notImplemented }
vector quantSelfValidBroken := {
  id := "quant-selfvalidating-broken", ast := { layers := [P "eth", Pq "ipv4" .opt] },
  packet := eth 0x0800 ++ ipv4 6 (version := 5) ++ tcp 12345 80 ++ payload 5, expected := .reject, goStatus := .notImplemented,
  note := "D-017: eth.ethertype already says ipv4, so version = 5 is a broken header, not absence; Go: optional variable-length layer not implemented" }
vector typOptionalAfterSkip := {
  id := "typ-no-dispatch-after-skip", ast := { layers := [P "eth", Pq "ipv4" .opt, P "tcp"] },
  expected := .illTyped "no dispatch constant for tcp under eth",
  note := "if ipv4 is skipped, tcp sits under eth with no constant (the resolver rejects it too)" }
vector typOptionalNoCheck := {
  id := "typ-optional-nocheck", ast := { layers := [P "eth", P "ipv4", P "udp", P "vxlan", Pq "eth" .opt, P "ipv4", P "tcp"] },
  packet := vxlanPkt, expected := .illTyped "optional eth with no-check dispatch cannot detect absence" }
vector quantSelfEdgeStar := {
  id := "quant-self-edge-star", ast := { layers := [P "eth", P "mpls", Pq "mpls" .star, P "ipv4", P "tcp"] },
  packet := mpls3, expected := .accept [], goStatus := .notImplemented,
  note := "NO_CHECK self-edge with CHAIN_END: the s bit detects absence; Go has no peek for NO_CHECK" }
vector quantSelfEdgeOpt := {
  id := "quant-self-edge-opt", ast := { layers := [P "eth", P "mpls", Pq "mpls" .opt, P "ipv4", P "tcp"] },
  packet := mpls1, expected := .accept [], goStatus := .notImplemented,
  note := "skips on the s bit of the first label; Go has no peek path for NO_CHECK" }
vector absentConsecutiveEthertype := {
  id := "absent-consecutive-ethertype", ast := { layers := [P "eth", Pq "qinq" .opt, Pq "vlan" .opt, P "ipv4", P "tcp"] },
  packet := vlanPkt, expected := .accept [],
  note := "D-034: qinq absent, vlan present; ipv4 dispatches on vlan.ethertype (Go: same bytes as eth/qinq, static-parent read is sound)" }
vector absentConsecutiveSelfValid := {
  id := "absent-consecutive-selfvalidating", ast := { layers := [P "eth", Pq "vlan" .opt, Pq "mpls" .opt, P "ipv4", P "tcp"] },
  packet := vlanPkt, expected := .accept [], goStatus := .notImplemented,
  note := "D-034: vlan present, mpls absent; ipv4 dispatches on vlan.ethertype. Go: ipv4 self-validates under mpls but not under vlan, so the static-parent read is refused" }
vector quantFirstOptional := {
  id := "quant-first-optional", ast := { layers := [Pq "vlan" .opt, P "ipv4"] },
  expected := .illTyped "the first layer cannot be optional" }

-- Alternation (D-004, D-010) -----------------------------------------------

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

vector hostTcVlanMandatory := {
  id := "host-tc-vlan-mandatory", host := .tc_entry,
  ast := { layers := [P "eth", P "vlan", P "ipv4", P "tcp"] }, packet := vlanPkt,
  expected := .illTyped "vlan is in metadata on this host; the layer must be optional", goStatus := .notImplemented }
vector hostTcVlanOpt := {
  id := "host-tc-vlan-optional", host := .tc_entry, ast := { layers := vlanOpt }, expected := .accept [] }
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
  quantPredAllHold, quantSelfValidSkip, quantSelfValidBroken, typOptionalAfterSkip, typOptionalNoCheck, quantSelfEdgeStar, quantSelfEdgeOpt,
  absentConsecutiveEthertype, absentConsecutiveSelfValid, quantFirstOptional,
  altFirst, altSecond, altNone, altFirstPredFails, altRoot, altNoCheck,
  hostTcVlanMandatory, hostTcVlanOpt, hostL3Root, hostL3EthRoot]

end Kunai
