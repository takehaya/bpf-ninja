import Kunai.Vectors.Where

/-!
# Aux headers (Phase 5): TCP options, IPv6 extension headers, SRv6, GTP, IPv4 options
-/
namespace Kunai
open Pkt

-- Longer parser runs (SRv6 segments, GTP, IPv4 options) need more
-- elaboration depth than the default for `decide`.
set_option maxRecDepth 16384

/-- eth/ipv4/tcp with `opts` as TCP options (length a multiple of 4). -/
def tcpOpts (opts : Packet) : Packet :=
  eth 0x0800 ++ ipv4 6 ++ tcp 12345 80 (dataOffset := 5 + opts.length / 4) (options := opts) ++ payload 5

def mssOpt (v : Nat) : Packet := [2, 4] ++ be 2 v
def ipv6Ext (next : Nat) (len : Nat := 0) : Packet := [UInt8.ofNat next, UInt8.ofNat len] ++ List.replicate (6 + 8 * len) 0
def ipv6With (nh : Nat) (exts : Packet) (sport : Nat := 12345) : Packet := eth 0x86DD ++ ipv6 nh ++ exts ++ tcp sport 80 ++ payload 5
def srv6Hdr (next lastEntry : Nat) (segsLeft : Nat := 0) : Packet :=
  [UInt8.ofNat next, UInt8.ofNat (2 * (lastEntry + 1)), 4, UInt8.ofNat segsLeft, UInt8.ofNat lastEntry, 0, 0, 0]
def srv6Pkt (lastEntry : Nat) (segs : List Nat) (segsLeft : Nat := 0) : Packet :=
  eth 0x86DD ++ ipv6 43 ++ srv6Hdr 6 lastEntry segsLeft ++ (segs.map (be 16)).flatten ++ tcp 12345 80 ++ payload 5
def gtpHdr (flags : Nat) (msgType : Nat := 0xff) : Packet := [UInt8.ofNat (0x30 + flags), UInt8.ofNat msgType] ++ be 2 28 ++ be 4 1
def gtpOpt (nextExt : Nat) : Packet := be 2 7 ++ [0, UInt8.ofNat nextExt]
def gtpExt (extType nextExt : Nat) (extLength : Nat := 1) : Packet :=
  [UInt8.ofNat extLength] ++ be 2 extType ++ [UInt8.ofNat nextExt] ++ List.replicate (4 * (extLength - 1)) 0
def gtpPkt (gtp : Packet) : Packet :=
  eth 0x0800 ++ ipv4 17 ++ udp 2152 2152 ++ gtp ++ ipv4 6 ++ tcp 12345 80 ++ payload 5
def rrPkt : Packet :=
  eth 0x0800 ++ ipv4 6 (ihl := 8) (options := [7, 11, 4] ++ be 4 0x0a000009 ++ be 4 0x0a00000a ++ [1]) ++ tcp 12345 80 ++ payload 5

def mss := Arith.field ⟨[("tcp", none), ("options", none), ("MSS", none), ("value", none)]⟩
def tcpW (w : Where) (pkt : Packet) (id : String) (expected : Result) (goStatus : GoStatus := .ok) (note : String := "") : Vector :=
  { id, ast := { layers := chain3, cond := some w }, packet := pkt, expected, goStatus, note }

-- TCP options ----------------------------------------------------------------

vector tcpMss := tcpW (cmp mss .eq (k 1460)) (tcpOpts (mssOpt 1460)) "tcp-opt-mss-value" (.accept [])
vector tcpMssWide := tcpW (cmp mss .eq (.wide 1460)) (tcpOpts (mssOpt 1460)) "tcp-opt-mss-wide" (.accept [])
  (note := "an option value next to int<128>(…) compares at 128 bits")
vector tcpMssMiss := tcpW (cmp mss .eq (k 1460)) (tcpOpts (mssOpt 1400)) "tcp-opt-mss-mismatch" .reject
vector tcpMssAbsent := tcpW (cmp mss .eq (k 1460)) ethIPv4TCP "tcp-opt-mss-absent" .reject (note := "D-027: the atom is false")
vector tcpMssAbsentNot := tcpW (.not (cmp mss .eq (k 1460))) ethIPv4TCP "tcp-opt-mss-absent-not" (.accept [])
  (note := "D-027: absent option ⇒ atom false ⇒ not(false)")
vector tcpMssAfterNop := tcpW (cmp mss .eq (k 1460)) (tcpOpts ([1, 1] ++ mssOpt 1460 ++ [1, 1])) "tcp-opt-mss-after-nop" (.accept [])
vector tcpUnknownSkipped := tcpW (cmp mss .eq (k 1460)) (tcpOpts ([25, 4, 0, 0] ++ mssOpt 1460)) "tcp-opt-unknown-skipped" (.accept [])
vector tcpUnknownLen0 := tcpW (cmp mss .eq (k 1460)) (tcpOpts [25, 0, 0, 0]) "tcp-opt-unknown-len0" .reject (note := "D-028: no progress")
vector tcpUnknownLen1 := tcpW (cmp mss .eq (k 1460)) (tcpOpts [25, 1, 0, 0]) "tcp-opt-unknown-len1" .reject (note := "D-028: no progress")
vector tcpOptCross := tcpW (cmp mss .eq (k 1460)) (tcpOpts [1, 1, 2, 4]) "tcp-opt-crosses-region" .reject
  (note := "MSS declared in the last 2 bytes of the option region: the counter underflows")
vector tcpEol := tcpW (cmp dport .eq (k 80)) (tcpOpts [0, 0, 0, 0]) "tcp-opt-eol" (.accept [])
vector tcpMssDup := tcpW (cmp mss .eq (k 16)) (tcpOpts (mssOpt 1460 ++ mssOpt 16)) "tcp-opt-mss-duplicate-last-wins" (.accept []) (note := "D-030")
vector tcpMssBadLen := tcpW (cmp mss .eq (k 1460)) (tcpOpts [2, 3, 5, 0xb4]) "tcp-opt-mss-bad-length" .reject
vector tcpMssExists := tcpW (.fieldExists ⟨[("tcp", none), ("options", none), ("MSS", none)]⟩) (tcpOpts (mssOpt 1460)) "tcp-opt-mss-exists" (.accept [])
vector tcpMssExistsNot := tcpW (.fieldExists ⟨[("tcp", none), ("options", none), ("MSS", none)]⟩) ethIPv4TCP "tcp-opt-mss-exists-absent" .reject
def sackBlock := Arith.field ⟨[("tcp", none), ("options", none), ("SACK", none), ("blocks", some (.nat 0)), ("left", none)]⟩
def sackIter (f : String) := Arith.field ⟨[("tcp", none), ("options", none), ("SACK", none), ("blocks", none), (f, none)]⟩
def sackPkt : Packet := tcpOpts ([1, 1, 5, 10] ++ be 4 100 ++ be 4 200)
vector tcpSackBlock := tcpW (cmp sackBlock .eq (k 100)) sackPkt "tcp-opt-sack-block-static" (.accept []) (note := "D-030: sack is sighted by kind byte; blocks follow its 2-byte header")
vector tcpSackAny := tcpW (.any (cmp (sackIter "right") .eq (k 200))) sackPkt "tcp-opt-sack-any" (.accept [])
vector tcpSackAll := tcpW (.all (cmp (sackIter "left") .eq (k 1))) sackPkt "tcp-opt-sack-all-false" .reject
vector tcpSackAbsentAny := tcpW (.any (cmp (sackIter "right") .eq (k 200))) ethIPv4TCP "tcp-opt-sack-absent-any" .reject (note := "D-007: empty stack ⇒ any is false")
vector tcpMalformedNoQuery := {
  id := "tcp-opt-malformed-no-query", ast := { layers := chain3 }, packet := tcpOpts [25, 0, 0, 0],
  expected := .accept [], note := "D-029: a malformed option region leaves tcp with no options; the chain goes on" }

def mssExists := Where.fieldExists ⟨[("tcp", none), ("options", none), ("MSS", none)]⟩
def malformedOpts : Packet := tcpOpts [25, 0, 0, 0]
vector tcpMalformedNotQuery := tcpW (.not (cmp mss .eq (k 1460))) malformedOpts "tcp-opt-malformed-not"
  (.accept []) (note := "D-029: no options, so MSS is absent: the atom is false and its negation true")
vector tcpMalformedOrTrue := tcpW (.or (cmp dport .eq (k 80)) mssExists) malformedOpts "tcp-opt-malformed-or"
  (.accept []) (note := "D-029: a true disjunct accepts whatever the other reads")
vector tcpMalformedExists := tcpW mssExists malformedOpts "tcp-opt-malformed-exists" .reject
vector tcpMalformedAfterMss := tcpW (cmp mss .eq (k 1460)) (tcpOpts (mssOpt 1460 ++ [25, 0, 0, 0]))
  "tcp-opt-malformed-after-mss" .reject (note := "D-029: the region is malformed as a whole; an option sighted before the fault is gone too")
vector tcpMalformedChainOn := {
  id := "tcp-opt-malformed-chain-on", ast := { layers := chain3, cond := some (cmp dport .eq (k 80)) },
  packet := tcpOpts [1, 1, 2, 4], expected := .accept [],
  note := "data_offset 6: the MSS starting at the region's third byte crosses its end; malformed, not a bounds failure" }
def ipv4BadOptPkt : Packet :=
  eth 0x0800 ++ ipv4 6 (ihl := 6) (options := [0x99, 4, 0, 0]) ++ tcp 12345 80 ++ payload 5
vector ipv4MalformedOpts := {
  id := "ipv4-opt-malformed", ast := { layers := chain3, cond := some (cmp dport .eq (k 80)) },
  packet := ipv4BadOptPkt, expected := .accept [], note := "D-029: an unknown ipv4 option kind leaves ipv4 with no options" }
vector ipv4MalformedOptsQueried := {
  id := "ipv4-opt-malformed-queried",
  ast := { layers := chain3, cond := some (.or (cmp dport .eq (k 80)) (.fieldExists ⟨[("ipv4", none), ("router_alert", none)]⟩)) },
  packet := ipv4BadOptPkt, expected := .accept [] }

def raExists := Where.fieldExists ⟨[("ipv4", none), ("options", none), ("ROUTER_ALERT", none)]⟩
def ipv4Opt40 (opts : Packet) : Packet :=
  eth 0x0800 ++ ipv4 6 (ihl := 15) (options := opts ++ List.replicate (40 - opts.length) 0) ++ tcp 12345 80 ++ payload 5
vector ipv4OptDepthLastFault := {
  id := "ipv4-opt-depth-last-dispatch-fault",
  ast := { layers := chain3, cond := some raExists },
  packet := ipv4Opt40 ([0x94, 4, 0, 0] ++ List.replicate 7 1 ++ [0x99, 2]), expected := .reject,
  note := "D-026: MAX_DEPTH 8 back edges = 9 dispatches; the 9th reads the bad kind, so the region is malformed" }
vector ipv4OptDepthLastSighting := {
  id := "ipv4-opt-depth-last-dispatch-sighting",
  ast := { layers := chain3, cond := some raExists },
  packet := ipv4Opt40 (List.replicate 8 1 ++ [0x94, 4, 0, 0]), expected := .accept [],
  note := "D-026: the 9th dispatch sights the router alert" }

def tcpValid := Where.optionsValid ⟨[("tcp", none), ("options", none)]⟩
vector tcpOptsValid := tcpW tcpValid (tcpOpts (mssOpt 1460)) "tcp-opts-valid" (.accept [])
vector tcpOptsValidNone := tcpW tcpValid ethIPv4TCP "tcp-opts-valid-empty" (.accept [])
  (note := "an empty option region is well formed")
vector tcpOptsInvalid := tcpW tcpValid malformedOpts "tcp-opts-valid-malformed" .reject
vector tcpOptsInvalidNot := tcpW (.not tcpValid) malformedOpts "tcp-opts-valid-malformed-not" (.accept [])
  (note := "D-029: the way to keep only packets with malformed options")
vector tcpOptsValidWithMss := tcpW (.and tcpValid (cmp mss .eq (k 1460))) (tcpOpts (mssOpt 1460)) "tcp-opts-valid-and-mss" (.accept [])
vector tcpOptsValidAbsent := {
  id := "tcp-opts-valid-absent-layer",
  ast := { layers := [P "eth", P "ipv4", Pq "tcp" .opt], cond := some tcpValid }, packet := eth 0x0800 ++ ipv4 17 ++ udp 1234 53 ++ payload 5,
  expected := .reject, note := "D-003: an absent layer has no options to vouch for" }
vector ipv4OptsInvalid := {
  id := "ipv4-opts-valid-malformed", ast := { layers := chain3, cond := some (.not (.optionsValid ⟨[("ipv4", none), ("options", none)]⟩)) },
  packet := ipv4BadOptPkt, expected := .accept [] }
vector tcpOptsValidAltMember := {
  id := "tcp-opts-valid-alt-member",
  ast := { layers := [P "eth", P "ipv4", .alt [{ name := "tcp" }, { name := "udp" }]], cond := some (.not tcpValid) },
  packet := malformedOpts, expected := .accept [], note := "a member of an alternation has its own flag" }
vector tcpOptsValidAltOther := {
  id := "tcp-opts-valid-alt-other-member",
  ast := { layers := [P "eth", P "ipv4", .alt [{ name := "tcp" }, { name := "udp" }]], cond := some tcpValid },
  packet := eth 0x0800 ++ ipv4 17 ++ udp 1234 53 ++ payload 5, expected := .reject, note := "udp matched: tcp is absent" }
def wsShift := Arith.field ⟨[("tcp", none), ("options", none), ("WS", none), ("shift", none)]⟩
vector tcpMssWsWide := tcpW (.and (cmp mss .eq (.wide 1460)) (cmp wsShift .eq (k 7)))
  (tcpOpts (mssOpt 1460 ++ [3, 3, 7, 1])) "tcp-opt-mss-ws-wide" (.accept [])
  (note := "two option equalities, one against a small int<128>(…): the accumulator takes it")
vector tcpMssWsWideHigh := tcpW (.and (cmp mss .eq (.wide (2 ^ 64 + 1460))) (cmp wsShift .eq (k 7)))
  (tcpOpts (mssOpt 1460 ++ [3, 3, 7, 1])) "tcp-opt-mss-ws-wide-high" .reject
  (note := "a value the option field cannot hold makes its leaf false for every packet; the accumulator rejects outright")
vector tcpMssWsWideFits64 := tcpW (.and (cmp mss .eq (.wide 70000)) (cmp wsShift .eq (k 7)))
  (tcpOpts (mssOpt 4464 ++ [3, 3, 7, 1])) "tcp-opt-mss-ws-wide-fits64" .reject
  (note := "70000 fits 64 bits but not the 16-bit field: compared by value, it never equals an MSS (here 70000 mod 2^16)")
vector tcpOptsValidTwoOptions := tcpW (.and tcpValid (.and (cmp mss .eq (k 1460)) (cmp wsShift .eq (k 7))))
  (tcpOpts (mssOpt 1460 ++ [3, 3, 7, 1])) "tcp-opts-valid-with-two-options" (.accept [])
  (note := "the accumulator plan for two option equalities also checks the validity flag")
vector tcpOptsValidTwoOptionsLast := tcpW (.and (.and (cmp mss .eq (k 1460)) (cmp wsShift .eq (k 7))) tcpValid)
  (tcpOpts (mssOpt 1460 ++ [3, 3, 7, 1])) "tcp-opts-valid-with-two-options-last" (.accept [])
vector tcpOptsValidTwoOptionsMalformed := tcpW (.and tcpValid (.and (cmp mss .eq (k 1460)) (cmp wsShift .eq (k 7))))
  (tcpOpts (mssOpt 1460 ++ [3, 3, 7] ++ [25, 0, 0, 0, 0])) "tcp-opts-valid-with-two-options-malformed" .reject
  (note := "D-029: both options are sighted before the zero-length option faults the walk: no options, and not valid")
def twoOptsValid : Where := .and tcpValid (.and (cmp mss .eq (k 1460)) (cmp wsShift .eq (k 7)))
def twoOptsPkt : Packet := tcpOpts (mssOpt 1460 ++ [3, 3, 7, 1])
vector tcpOptsValidTwoOptionsOptional := {
  id := "tcp-opts-valid-with-two-options-optional",
  ast := { layers := [P "eth", P "ipv4", Pq "tcp" .opt], cond := some twoOptsValid },
  packet := eth 0x0800 ++ ipv4 17 ++ udp 1234 53 ++ payload 5, expected := .reject, note := "tcp absent: every atom is false" }
vector tcpOptsValidTwoOptionsAlt := {
  id := "tcp-opts-valid-with-two-options-alt",
  ast := { layers := [P "eth", P "ipv4", .alt [{ name := "udp" }, { name := "tcp" }]], cond := some twoOptsValid },
  packet := twoOptsPkt, expected := .accept [] }
vector tcpOptsValidTwoOptionsLabel := {
  id := "tcp-opts-valid-with-two-options-label",
  ast := { layers := [P "eth", P "ipv4", .proto { name := "tcp", label := some "t" }],
           cond := some (.and (.optionsValid ⟨[("t", none), ("options", none)]⟩)
                              (.and (cmp mss .eq (k 1460)) (cmp wsShift .eq (k 7)))) },
  packet := twoOptsPkt, expected := .accept [] }
vector tcpOptsValidTwoOptionsOtherLayer := {
  id := "tcp-opts-valid-with-two-options-other-layer",
  ast := { layers := chain3, cond := some (.and (.optionsValid ⟨[("ipv4", none), ("options", none)]⟩) twoOptsValid) },
  packet := twoOptsPkt, expected := .accept [],
  note := "another layer's validity flag is checked after the accumulator's mask, with that layer's absent guard" }
vector tcpOptsValidTwoOptionsMiss := tcpW (.and tcpValid (.and (cmp mss .eq (k 1460)) (cmp wsShift .eq (k 8))))
  (tcpOpts (mssOpt 1460 ++ [3, 3, 7, 1])) "tcp-opts-valid-with-two-options-miss" .reject
def tcpValidPred : Predicate := .optionsValid ⟨[("options", none)]⟩
def tcpValidL (q : Quant := .one) : List Layer :=
  [P "eth", P "ipv4", .proto { name := "tcp", preds := [tcpValidPred], quant := q }]
vector bracketValid := {
  id := "bracket-opts-valid", ast := { layers := tcpValidL }, packet := tcpOpts (mssOpt 1460), expected := .accept [] }
vector bracketValidMalformed := {
  id := "bracket-opts-valid-malformed", ast := { layers := tcpValidL }, packet := malformedOpts, expected := .reject }
vector bracketValidOptMalformed := {
  id := "bracket-opts-valid-optional-malformed", ast := { layers := tcpValidL .opt }, packet := malformedOpts, expected := .reject,
  note := "D-001: tcp dispatched, so a false bracket predicate rejects rather than skipping the layer" }
vector bracketValidWithCmp := {
  id := "bracket-opts-valid-and-cmp",
  ast := { layers := [P "eth", P "ipv4", .proto { name := "tcp", preds := [.cmp (f "dport") .eq (.int 80), tcpValidPred] }] },
  packet := tcpOpts (mssOpt 1460), expected := .accept [] }
def validMember (name : String) : ProtoLayer := { name, preds := [tcpValidPred] }
vector bracketValidAltFirst := {
  id := "bracket-opts-valid-alt-first", ast := { layers := [P "eth", P "ipv4", .alt [validMember "tcp", { name := "udp" }]] },
  packet := malformedOpts, expected := .reject }
vector bracketValidAltSecond := {
  id := "bracket-opts-valid-alt-second", ast := { layers := [P "eth", P "ipv4", .alt [{ name := "udp" }, validMember "tcp"]] },
  packet := malformedOpts, expected := .reject }
vector bracketValidAltOther := {
  id := "bracket-opts-valid-alt-other-member", ast := { layers := [P "eth", P "ipv4", .alt [validMember "tcp", { name := "udp" }]] },
  packet := eth 0x0800 ++ ipv4 17 ++ udp 1234 53 ++ payload 5, expected := .accept [] }
vector bracketValidFirst := {
  id := "bracket-opts-valid-first-in-list",
  ast := { layers := [P "eth", P "ipv4", .proto { name := "tcp", preds := [tcpValidPred, .cmp (f "dport") .eq (.int 80)] }] },
  packet := malformedOpts, expected := .reject }
vector bracketValidNoOpts := {
  id := "bracket-opts-valid-no-options", ast := { layers := tcpValidL }, expected := .accept [] }
vector bracketValidOptAbsent := {
  id := "bracket-opts-valid-optional-absent", ast := { layers := tcpValidL .opt },
  packet := eth 0x0800 ++ ipv4 17 ++ udp 1234 53 ++ payload 5, expected := .accept [],
  note := "tcp does not dispatch under protocol 17, so the optional layer is skipped and its predicate never runs" }
vector bracketValidIPv4 := {
  id := "bracket-opts-valid-ipv4",
  ast := { layers := [P "eth", .proto { name := "ipv4", preds := [tcpValidPred] }, P "tcp"] },
  packet := ipv4BadOptPkt, expected := .reject }
vector bracketValidTwoOptions := {
  id := "bracket-opts-valid-with-two-options",
  ast := { layers := [P "eth", P "ipv4", .proto { name := "tcp", preds := [tcpValidPred] }], cond := some (.and (cmp mss .eq (k 1460)) (cmp wsShift .eq (k 7))) },
  packet := tcpOpts (mssOpt 1460 ++ [3, 3, 7, 1]), expected := .accept [],
  note := "the bracket form next to the two-option accumulator; the where form joins the plan's mask check" }
vector bracketValidRepeated := {
  id := "bracket-opts-valid-repeated",
  ast := { layers := [P "eth", .proto { name := "ipv4", preds := [tcpValidPred], quant := .range 1 (some 2) }, P "tcp"] },
  expected := .accept [],
  note := "every matched instance runs its bracket predicates; here the one ipv4 has a well-formed (empty) option region" }
vector typBracketValidSegment := {
  id := "typ-bracket-opts-valid-segment",
  ast := { layers := [P "eth", P "ipv4", .proto { name := "tcp", preds := [.optionsValid ⟨[("opts", none)]⟩] }] },
  expected := .illTyped "unsupported: tcp[opts.valid]" }
vector typBracketValidSrv6 := {
  id := "typ-bracket-segments-valid-srv6",
  ast := { layers := [P "eth", P "ipv6", .proto { name := "srv6", preds := [.optionsValid ⟨[("segments", none)]⟩] }, P "tcp"] },
  expected := .illTyped "srv6 has no option region whose faults are skipped; segments.valid needs one (@kunai_option_region[on_fault=skip])" }
vector typBracketValidNoRegion := {
  id := "typ-bracket-opts-valid-no-region",
  ast := { layers := [P "eth", P "ipv4", .proto { name := "udp", preds := [tcpValidPred] }] },
  expected := .illTyped "udp has no option region whose faults are skipped; options.valid needs one (@kunai_option_region[on_fault=skip])" }
vector typOptsValidNoRegion := {
  id := "typ-opts-valid-no-region", ast := { layers := [P "eth", P "ipv4", P "udp"], cond := some (.optionsValid ⟨[("udp", none), ("options", none)]⟩) },
  expected := .illTyped "udp has no option region whose faults are skipped; udp.options.valid needs one (@kunai_option_region[on_fault=skip])" }

-- geneve options (D-029) ----------------------------------------------------

/-- geneve header with `optLen` 4-byte words of options, carrying an
Ethernet payload. -/
def geneveHdr (optLen : Nat) : Packet := [UInt8.ofNat optLen, 0] ++ be 2 0x6558 ++ be 3 100 ++ [0]
def geneveOvn (egress : Nat) : Packet := be 2 0x0102 ++ [0x80, 1] ++ be 2 1 ++ be 2 egress
def geneveUnknown : Packet := be 2 0x0000 ++ [0x01, 1] ++ be 4 0
def genevePkt (optLen : Nat) (opts : Packet) : Packet :=
  eth 0x0800 ++ ipv4 17 ++ udp 1234 6081 ++ geneveHdr optLen ++ opts ++ payload 5
def geneveL : List Layer := [P "eth", P "ipv4", P "udp", P "geneve"]
def ovnExists := Where.fieldExists ⟨[("geneve", none), ("options", none), ("OVN", none)]⟩
def geneveValid := Where.optionsValid ⟨[("geneve", none), ("options", none)]⟩
vector geneveOvnHit := {
  id := "geneve-opt-ovn", ast := { layers := geneveL, cond := some ovnExists },
  packet := genevePkt 2 (geneveOvn 42), expected := .accept [] }
vector geneveMalformedAfter := {
  id := "geneve-opt-malformed-after-ovn", ast := { layers := geneveL, cond := some ovnExists },
  packet := genevePkt 4 (geneveOvn 42 ++ geneveUnknown), expected := .reject,
  note := "D-029: an unknown option after OVN makes the region malformed; OVN is gone too" }
vector geneveMalformedBefore := {
  id := "geneve-opt-malformed-before-ovn", ast := { layers := geneveL, cond := some (.not geneveValid) },
  packet := genevePkt 4 (geneveUnknown ++ geneveOvn 42), expected := .accept [] }
vector geneveMalformedChainOn := {
  id := "geneve-opt-malformed-chain-on", ast := { layers := geneveL, cond := some (cmp (fld "udp" "dport") .eq (k 6081)) },
  packet := genevePkt 4 (geneveUnknown ++ geneveOvn 42), expected := .accept [],
  note := "D-029: the chain goes on whatever the options are" }
vector geneveRegionPastEnd := {
  id := "geneve-opt-region-past-end", ast := { layers := geneveL, cond := some (cmp (fld "udp" "dport") .eq (k 6081)) },
  packet := eth 0x0800 ++ ipv4 17 ++ udp 1234 6081 ++ geneveHdr 8 ++ geneveOvn 42, expected := .reject,
  note := "the declared region does not fit in the packet: a bounds failure, not a malformed region" }
vector geneveValidEmpty := {
  id := "geneve-opts-valid-empty", ast := { layers := geneveL, cond := some geneveValid },
  packet := genevePkt 0 [], expected := .accept [] }
vector bracketValidGeneve := {
  id := "bracket-opts-valid-geneve",
  ast := { layers := [P "eth", P "ipv4", P "udp", .proto { name := "geneve", preds := [tcpValidPred] }] },
  packet := genevePkt 4 (geneveUnknown ++ geneveOvn 42), expected := .reject }

-- IPv6 extension headers ---------------------------------------------------

def ipv6L : List Layer := [P "eth", P "ipv6", P "tcp"]
def exts0 := Arith.field ⟨[("ipv6", none), ("exts", some (.nat 0)), ("next_header", none)]⟩
def exts1 := Arith.field ⟨[("ipv6", none), ("exts", some (.nat 1)), ("next_header", none)]⟩
def extsIter := Arith.field ⟨[("ipv6", none), ("exts", none), ("next_header", none)]⟩
def hbhTcp : Packet := ipv6With 0 (ipv6Ext 6)
def twoExts : Packet := ipv6With 0 (ipv6Ext 60 ++ ipv6Ext 6)

vector ipv6Hbh := {
  id := "ipv6-ext-hbh", ast := { layers := ipv6L }, packet := hbhTcp, expected := .accept [],
  note := "@kunai_writeback: ipv6.next_header becomes 6 so tcp dispatches" }
vector ipv6TwoExts := {
  id := "ipv6-ext-two", ast := { layers := ipv6L }, packet := twoExts, expected := .accept [] }
vector ipv6ExtLong := {
  id := "ipv6-ext-hdr-ext-len", ast := { layers := ipv6L }, packet := ipv6With 0 (ipv6Ext 6 2), expected := .accept [],
  note := "hdr_ext_len = 2: a 24-byte extension" }
vector ipv6ExtTooLong := {
  id := "ipv6-ext-len-exceeds-packet", ast := { layers := ipv6L }, packet := ipv6With 0 ([6, 0xff] ++ List.replicate 6 0 ++ tcp 1 80), expected := .reject }
vector ipv6ExtsIndex := {
  id := "ipv6-exts-index", ast := { layers := ipv6L, cond := some (cmp exts0 .eq (k 60)) }, packet := twoExts, expected := .accept [] }
vector ipv6ExtsIndex1 := {
  id := "ipv6-exts-index-1", ast := { layers := ipv6L, cond := some (cmp exts1 .eq (k 6)) }, packet := twoExts, expected := .accept [] }
def longExts : Packet := ipv6With 0 (ipv6Ext 60 (len := 1) ++ ipv6Ext 6)
vector ipv6ExtsIndexAfterLong := {
  id := "ipv6-exts-index-after-long-ext", ast := { layers := ipv6L, cond := some (cmp exts1 .eq (k 6)) }, packet := longExts,
  expected := .accept [], note := "entry 1 starts after the 16-byte first ext (Go walks the entries before a static index at read time)" }
vector ipv6ExtsAnyAfterLong := {
  id := "ipv6-exts-any-after-long-ext", ast := { layers := ipv6L, cond := some (.any (cmp extsIter .eq (k 6))) }, packet := longExts,
  expected := .accept [] }
vector ipv6ExtsDynamicLong := {
  id := "ipv6-exts-dynamic-index-var-len",
  ast := { layers := ipv6L, cond := some (cmp (Arith.field ⟨[("ipv6", none), ("exts", some (.field ["ipv6", "hop_limit"])), ("next_header", none)]⟩) .eq (k 6)) },
  packet := eth 0x86DD ++ ipv6 0 (hopLimit := 0) ++ ipv6Ext 6 ++ tcp 12345 80 ++ payload 5, expected := .accept [],
  note := "a dynamic index into variable-length entries (Go walks the entries up to the push bound and stops at the indexed one)" }
vector ipv6ExtsDynamicLongSecond := {
  id := "ipv6-exts-dynamic-index-var-len-second",
  ast := { layers := ipv6L, cond := some (cmp (Arith.field ⟨[("ipv6", none), ("exts", some (.field ["ipv6", "hop_limit"])), ("next_header", none)]⟩) .eq (k 6)) },
  packet := eth 0x86DD ++ ipv6 0 (hopLimit := 1) ++ ipv6Ext 60 (len := 1) ++ ipv6Ext 6 ++ tcp 12345 80 ++ payload 5, expected := .accept [],
  note := "index 1 behind a 16-byte first ext" }
/-- `ipv6.exts[ipv6.hop_limit].next_header`: hop_limit doubles as the index. -/
def extsHop : Arith := Arith.field ⟨[("ipv6", none), ("exts", some (.field ["ipv6", "hop_limit"])), ("next_header", none)]⟩
vector ipv6ExtsDynamicLongAbsent := {
  id := "ipv6-exts-dynamic-index-var-len-absent",
  ast := { layers := ipv6L, cond := some (cmp extsHop .eq (k 6)) },
  packet := eth 0x86DD ++ ipv6 0 (hopLimit := 1) ++ ipv6Ext 6 ++ tcp 0x0600 80 ++ payload 5, expected := .reject,
  note := "D-031: index 1 with one entry pushed ⇒ absent ⇒ false (tcp.sport = 0x0600 would read as next_header 6 without the push count guard)" }
def fiveExts : Packet := ipv6Ext 60 ++ ipv6Ext 60 ++ ipv6Ext 60 ++ ipv6Ext 60 ++ ipv6Ext 6
vector ipv6ExtsDynamicLongLast := {
  id := "ipv6-exts-dynamic-index-var-len-last",
  ast := { layers := ipv6L, cond := some (cmp extsHop .eq (k 6)) },
  packet := eth 0x86DD ++ ipv6 0 (hopLimit := 4) ++ fiveExts ++ tcp 12345 80 ++ payload 5, expected := .accept [],
  note := "index 4 is the last entry the depth cap admits (Go: the unrolled walk's final step, reached by fall-through)" }
vector ipv6ExtsDynamicLongLastMiss := {
  id := "ipv6-exts-dynamic-index-var-len-last-miss",
  ast := { layers := ipv6L, cond := some (cmp extsHop .eq (k 60)) },
  packet := eth 0x86DD ++ ipv6 0 (hopLimit := 4) ++ fiveExts ++ tcp 12345 80 ++ payload 5, expected := .reject,
  note := "the walk lands on entry 4 (next_header 6), not on one of the earlier entries (60)" }
vector ipv6ExtsDynamicLongBeyond := {
  id := "ipv6-exts-dynamic-index-var-len-beyond",
  ast := { layers := ipv6L, cond := some (cmp extsHop .eq (k 60)) },
  packet := eth 0x86DD ++ ipv6 0 (hopLimit := 6) ++ fiveExts ++ tcp 12345 80 ++ payload 5, expected := .reject,
  note := "D-031: index 6 past the five pushed entries ⇒ absent, although the stack's capacity is 8" }
vector ipv6ExtsDynamicLongSlot := {
  id := "ipv6-exts-dynamic-index-var-len-slot",
  ast := { layers := [P "eth", Pq "vlan" .opt, P "ipv6", P "tcp"], cond := some (cmp extsHop .eq (k 6)) },
  packet := eth 0x8100 ++ vlan 100 0x86DD ++ ipv6 0 (hopLimit := 1) ++ ipv6Ext 60 (len := 1) ++ ipv6Ext 6 ++ tcp 12345 80 ++ payload 5, expected := .accept [],
  note := "ipv6 behind an optional layer: Go anchors the walk on the layer's runtime entry slot" }
vector ipv6ExtsDynamicLongSlotAbsent := {
  id := "ipv6-exts-dynamic-index-var-len-slot-absent",
  ast := { layers := [P "eth", Pq "vlan" .opt, P "ipv6", P "tcp"], cond := some (cmp extsHop .eq (k 6)) },
  packet := eth 0x8100 ++ vlan 100 0x86DD ++ ipv6 0 (hopLimit := 2) ++ ipv6Ext 60 (len := 1) ++ ipv6Ext 6 ++ tcp 0x0600 80 ++ payload 5, expected := .reject,
  note := "D-031 on the slot-anchored walk: index 2 with two entries pushed ⇒ absent" }
-- Bracket predicates on aux fields (issue 17): resolved like a where clause scoped to the layer.
def ipv6Br (ρ : Predicate) : List Layer := [P "eth", .proto { name := "ipv6", preds := [ρ] }, P "tcp"]
def extsBr (i : Nat) : FieldPath := ⟨[("exts", some (.nat i)), ("next_header", none)]⟩
vector ipv6ExtsBracket := {
  id := "ipv6-exts-bracket-index", ast := { layers := ipv6Br (.cmp (extsBr 1) .eq (.int 6)) }, packet := twoExts, expected := .accept [],
  note := "T-FieldStackStatic inside a bracket; Go guards the index by the push count after the walk (D-031)" }
vector ipv6ExtsBracketAbsent := {
  id := "ipv6-exts-bracket-index-absent", ast := { layers := ipv6Br (.cmp (extsBr 1) .eq (.int 6)) },
  packet := ipv6With 0 (ipv6Ext 6) (sport := 0x0600), expected := .reject, note := "D-031 in a bracket: entry 1 was not extracted ⇒ false" }
vector ipv6ExtsBracketLong := {
  id := "ipv6-exts-bracket-after-long-ext", ast := { layers := ipv6Br (.cmp (extsBr 1) .eq (.int 6)) }, packet := longExts, expected := .accept [] }
vector ipv6ExtsBracketDynamic := {
  id := "ipv6-exts-bracket-dynamic-index",
  ast := { layers := ipv6Br (.cmp ⟨[("exts", some (.field ["ipv6", "hop_limit"])), ("next_header", none)]⟩ .eq (.int 6)) },
  expected := .illTyped "stack ipv6.exts needs a constant index inside a bracket predicate (a dynamic index needs a where clause)" }
vector ipv6ExtsBracketIter := {
  id := "ipv6-exts-bracket-iterator", ast := { layers := ipv6Br (.cmp ⟨[("exts", none), ("next_header", none)]⟩ .eq (.int 6)) },
  expected := .illTyped "stack ipv6.exts needs a constant index inside a bracket predicate" }
vector ipv6ExtsBracketInAbsent := {
  id := "ipv6-exts-bracket-in-absent", ast := { layers := ipv6Br (.inList (extsBr 1) [.int 6, .int 60]) },
  packet := ipv6With 0 (ipv6Ext 6) (sport := 0x0600), expected := .reject, note := "D-031 for `in [...]` in a bracket: the entry is absent ⇒ false" }
vector ipv6ExtsBracketInLong := {
  id := "ipv6-exts-bracket-in-after-long-ext", ast := { layers := ipv6Br (.inList (extsBr 1) [.int 6, .int 60]) }, packet := longExts, expected := .accept [] }
vector ipv6ExtsSliceLong := {
  id := "ipv6-exts-index-slice-after-long-ext",
  ast := { layers := ipv6L, cond := some (cmp (Arith.field ⟨[("ipv6", none), ("exts", some (.nat 1)), ("next_header", some (.slice 4 8))]⟩) .eq (k 6)) },
  packet := longExts, expected := .accept [], note := "a bit slice of a walked entry's field: low nibble of next_header 6" }
vector ipv6ExtsBracketSliceLong := {
  id := "ipv6-exts-bracket-slice-after-long-ext",
  ast := { layers := ipv6Br (.cmp ⟨[("exts", some (.nat 1)), ("next_header", some (.slice 0 4))]⟩ .eq (.int 0)) },
  packet := longExts, expected := .accept [], note := "high nibble of next_header 6 is 0" }
vector gtpExtsBracket := {
  id := "gtp-exts-bracket",
  ast := { layers := [P "eth", P "ipv4", P "udp", .proto { name := "gtp", preds := [.cmp ⟨[("exts", some (.nat 0)), ("ext_type", none)]⟩ .eq (.int 1)] }, P "ipv4", P "tcp"] },
  packet := gtpPkt (gtpHdr 4 ++ gtpOpt 0x85 ++ gtpExt 1 0), expected := .accept [],
  note := "Go evaluates the bracket after the walk when it indexes a push-counted stack, as for a write-back protocol" }
vector gtpExtsBracketAbsent := {
  id := "gtp-exts-bracket-absent",
  ast := { layers := [P "eth", P "ipv4", P "udp", .proto { name := "gtp", preds := [.cmp ⟨[("exts", some (.nat 1)), ("ext_type", none)]⟩ .eq (.int 0)] }, P "ipv4", P "tcp"] },
  packet := gtpPkt (gtpHdr 4 ++ gtpOpt 0x85 ++ gtpExt 1 0), expected := .reject,
  note := "D-031: one ext pushed, entry 1 is absent; the inner ipv4 bytes there read as ext_type 0, so a missing count guard would accept" }
vector gtpExtsBracketNone := {
  id := "gtp-exts-bracket-none",
  ast := { layers := [P "eth", P "ipv4", P "udp", .proto { name := "gtp", preds := [.cmp ⟨[("exts", some (.nat 0)), ("ext_type", none)]⟩ .eq (.int 0)] }, P "ipv4", P "tcp"] },
  packet := gtpPkt (gtpHdr 0), expected := .reject,
  note := "D-031: no option block, so the walk pushes nothing and entry 0 is absent (Go: the count slot starts at 0; the inner ipv4 bytes would read as ext_type 0)" }
def gtpMixed (teid : Int) : List Layer :=
  [P "eth", P "ipv4", P "udp",
   .proto { name := "gtp", preds := [.cmp (f "teid") .eq (.int teid), .cmp ⟨[("exts", some (.nat 1)), ("ext_type", none)]⟩ .eq (.int 7)] },
   P "ipv4", .proto { name := "tcp", preds := [.cmp (f "dport") .eq (.int 80)] }]
vector gtpExtsBracketMixed := {
  id := "gtp-exts-bracket-mixed", ast := { layers := gtpMixed 1 },
  packet := gtpPkt (gtpHdr 4 ++ gtpOpt 0x85 ++ gtpExt 1 0x85 (extLength := 2) ++ gtpExt 7 0), expected := .accept [],
  note := "a primary-header predicate next to an index behind an 8-byte ext, and a predicate on a later layer (Go: teid before the walk, exts[1] after it, R4 restored for tcp)" }
vector gtpExtsBracketMixedMiss := {
  id := "gtp-exts-bracket-mixed-miss", ast := { layers := gtpMixed 2 },
  packet := gtpPkt (gtpHdr 4 ++ gtpOpt 0x85 ++ gtpExt 1 0x85 (extLength := 2) ++ gtpExt 7 0), expected := .reject,
  note := "the primary-header predicate fails" }
vector ipv6ExtsIndexAbsent := {
  id := "ipv6-exts-index-absent", ast := { layers := ipv6L, cond := some (cmp exts1 .eq (k 6)) }, packet := ipv6With 0 (ipv6Ext 6) (sport := 0x0600),
  expected := .reject, note := "D-031: entry 1 was not extracted ⇒ false (Go: the push count slot guards the static index; tcp.sport = 0x0600 would otherwise look like next_header 6)" }
vector ipv6NextHeaderWhere := {
  id := "ipv6-next-header-writeback-where", ast := { layers := ipv6L, cond := some (cmp (fld "ipv6" "next_header") .eq (k 6)) },
  packet := hbhTcp, expected := .accept [], note := "where sees the written-back next_header" }
vector ipv6NextHeaderBracket := {
  id := "ipv6-next-header-writeback-bracket",
  ast := { layers := [P "eth", .proto { name := "ipv6", preds := [.cmp (f "next_header") .eq (.int 6)] }, P "tcp"] }, packet := hbhTcp,
  expected := .accept [], note := "D-032: bracket predicates run after aux-extract (σ'), so they see the written-back next_header" }
def altV6L (last : String) : List Layer := [P "eth", .alt [{ name := "ipv4" }, { name := "ipv6" }], P last]
vector altIPv6MemberWriteBack := {
  id := "alt-ipv6-member-writeback", ast := { layers := altV6L "tcp" }, packet := hbhTcp, expected := .accept [],
  note := "the ipv6 member's dispatch of tcp sees the written-back next_header (6), not the wire byte (0)" }
vector altIPv6MemberWriteBackWhere := {
  id := "alt-ipv6-member-writeback-where", ast := { layers := altV6L "tcp", cond := some (cmp (fld "ipv6" "next_header") .eq (k 6)) },
  packet := hbhTcp, expected := .accept [] }
vector altIPv6MemberWriteBackMiss := {
  id := "alt-ipv6-member-writeback-udp-miss", ast := { layers := altV6L "udp" }, packet := hbhTcp, expected := .reject,
  note := "the written-back value is 6, so udp (17) misses" }
vector ipv6FiveExts := {
  id := "ipv6-ext-five-at-depth", ast := { layers := ipv6L }, packet := ipv6With 0 (ipv6Ext 60 ++ ipv6Ext 60 ++ ipv6Ext 60 ++ ipv6Ext 60 ++ ipv6Ext 6),
  expected := .accept [], note := "D-026: IPV6_MAX_DEPTH = 4 loop iterations after the first extension" }
vector ipv6SixExts := {
  id := "ipv6-ext-six-exceeds-depth", ast := { layers := ipv6L }, packet := ipv6With 0 (ipv6Ext 60 ++ ipv6Ext 60 ++ ipv6Ext 60 ++ ipv6Ext 60 ++ ipv6Ext 60 ++ ipv6Ext 6),
  expected := .reject, note := "D-026: the cap accepts after 5 extensions with next_header = 60, so tcp misses" }
vector ipv6AnyExts := {
  id := "ipv6-exts-any", ast := { layers := ipv6L, cond := some (.any (cmp extsIter .eq (k 60))) }, packet := twoExts,
  expected := .accept [], note := "any ranges over the 2 extracted entries (D-031); Go's unroll agrees here because a hit comes first" }
vector ipv6AllExts := {
  id := "ipv6-exts-all", ast := { layers := ipv6L, cond := some (.all (cmp extsIter .ne (k 1))) }, packet := twoExts,
  expected := .accept [], note := "D-031: all ranges over the 2 extracted entries (Go: the unroll skips entries past the push count)" }

-- SRv6 -----------------------------------------------------------------------

def srv6L : List Layer := [P "eth", P "ipv6", P "srv6", P "tcp"]
def seg (i : Index) := FieldPath.mk [("srv6", none), ("segments", some i), ("addr", none)]
def segIter := FieldPath.mk [("srv6", none), ("segments", none), ("addr", none)]
def s1 : Nat := 0xfc000000000000000000000000000001
def s2 : Nat := 0xfc000000000000000000000000000002
def srv6Two : Packet := srv6Pkt 1 [s1, s2]

vector srv6TruncatedFails := {
  id := "srv6-segments-truncated-fails", ast := { layers := [P "eth", P "ipv6", P "srv6"] },
  packet := eth 0x86DD ++ ipv6 43 ++ srv6Hdr 59 1 ++ be 16 s1 ++ be 8 0, expected := .reject,
  note := "D-029: srv6.p4 says @kunai_option_region[on_fault=fail]; a segment list cut short rejects, it does not become empty" }
vector typSrv6NoValid := {
  id := "typ-srv6-segments-valid", ast := { layers := srv6L, cond := some (.optionsValid ⟨[("srv6", none), ("segments", none)]⟩) },
  packet := srv6Two, expected := .illTyped "srv6 has no option region whose faults are skipped; srv6.segments.valid needs one (@kunai_option_region[on_fault=skip])",
  note := "on_fault=fail: a fault rejects the packet, so there is nothing for .valid to report" }
vector geneveVersionOne := {
  id := "geneve-version-one", ast := { layers := geneveL, cond := some (cmp (fld "udp" "dport") .eq (k 6081)) },
  packet := eth 0x0800 ++ ipv4 17 ++ udp 1234 6081 ++ [0x40 + 2, 0] ++ be 2 0x6558 ++ be 3 100 ++ [0] ++ geneveOvn 42 ++ payload 5,
  expected := .reject, note := "a fault in the header itself (version 1), before the option region: rejects" }
vector srv6SegWideLit := {
  id := "srv6-segments-wide-lit", ast := { layers := srv6L, cond := some (cmp (.field (seg (.nat 1))) .eq (.wide s2)) },
  packet := srv6Two, expected := .accept [],
  note := "a 16-byte segment is an Int<128> operand like ipv6.dst; the same value as srv6-segments-static, written as int<128>(…)" }
vector srv6Chain := {
  id := "srv6-chain", ast := { layers := srv6L }, packet := srv6Two, expected := .accept [] }
vector srv6Static := {
  id := "srv6-segments-static", ast := { layers := srv6L, cond := some (.litCmp (seg (.nat 1)) .eq (.ipv6 s2)) }, packet := srv6Two, expected := .accept [] }
vector srv6Dynamic := {
  id := "srv6-segments-dynamic", ast := { layers := srv6L, cond := some (.litCmp (seg (.field ["srv6", "last_entry"])) .eq (.ipv6 s2)) }, packet := srv6Two, expected := .accept [] }
vector srv6Any := {
  id := "srv6-segments-any", ast := { layers := srv6L, cond := some (.any (.litCmp segIter .eq (.ipv6 s1))) }, packet := srv6Two, expected := .accept [] }
vector srv6All := {
  id := "srv6-segments-all-false", ast := { layers := srv6L, cond := some (.all (.litCmp segIter .eq (.ipv6 s1))) }, packet := srv6Two, expected := .reject }
vector srv6AllCidr := {
  id := "srv6-segments-all-cidr", ast := { layers := srv6L, cond := some (.all (.litCmp segIter .eq (.cidr6 0xfc000000000000000000000000000000 8))) }, packet := srv6Two, expected := .accept [] }
vector srv6IndexAbsent := {
  id := "srv6-segments-index-absent", ast := { layers := srv6L, cond := some (.litCmp (seg (.nat 2)) .ne (.ipv6 s1)) }, packet := srv6Two,
  expected := .reject, note := "D-031: entry 2 was not extracted ⇒ false even for !=" }
def segLeft := seg (.field ["srv6", "segments_left"])
vector srv6DynamicAtCount := {
  id := "srv6-segments-dynamic-at-count", ast := { layers := srv6L, cond := some (.litCmp segLeft .ne (.ipv6 s1)) },
  packet := srv6Pkt 1 [s1, s2] (segsLeft := 2), expected := .reject,
  note := "D-031 for a dynamic index: segments_left = 2 = last_entry + 1 names an entry that was not extracted ⇒ false even for !=; the 16 bytes at that position belong to the tcp header" }
vector srv6DynamicLast := {
  id := "srv6-segments-dynamic-last", ast := { layers := srv6L, cond := some (.litCmp segLeft .eq (.ipv6 s2)) },
  packet := srv6Pkt 1 [s1, s2] (segsLeft := 1), expected := .accept [],
  note := "segments_left = 1 = last_entry is the last extracted entry: the index is in range" }
vector srv6OptDynamicAtCount := {
  id := "srv6-opt-segments-dynamic-at-count", ast := { layers := [P "eth", P "ipv6", Pq "srv6" .opt, P "tcp"], cond := some (.litCmp segLeft .ne (.ipv6 s1)) },
  packet := srv6Pkt 1 [s1, s2] (segsLeft := 2), expected := .reject,
  note := "the optional layer is present and the index is at the count: absent, false for != (the layer guard and the count guard share the verdict)" }
vector srv6OptDynamicLast := {
  id := "srv6-opt-segments-dynamic-last", ast := { layers := [P "eth", P "ipv6", Pq "srv6" .opt, P "tcp"], cond := some (.litCmp segLeft .ne (.ipv6 s1)) },
  packet := srv6Pkt 1 [s1, s2] (segsLeft := 1), expected := .accept [] }
def segLow (i : Nat) : FieldPath := ⟨[("srv6", none), ("segments", some (.nat i)), ("addr", some (.slice 64 128))]⟩
vector srv6StaticSlice := {
  id := "srv6-segments-static-slice", ast := { layers := srv6L, cond := some (cmp (.field (segLow 1)) .eq (k 2)) },
  packet := srv6Two, expected := .accept [], note := "the low 64 bits of segments[1] (fc00::2) behind a static index" }
vector srv6StaticSliceAbsent := {
  id := "srv6-segments-static-slice-absent", ast := { layers := srv6L, cond := some (cmp (.field (segLow 1)) .ne (k 2)) },
  packet := srv6Pkt 0 [s1], expected := .reject, note := "D-031: entry 1 was not extracted, the sliced read is absent too" }
def segBr (i : Nat) : FieldPath := ⟨[("segments", some (.nat i)), ("addr", none)]⟩
def srv6Br (ρ : Predicate) : List Layer := [P "eth", P "ipv6", .proto { name := "srv6", preds := [ρ] }, P "tcp"]
vector srv6BracketIndexAbsent := {
  id := "srv6-segments-bracket-index-absent", ast := { layers := srv6Br (.cmp (segBr 1) .ne (.ipv6 s1)) },
  packet := srv6Pkt 0 [s1], expected := .reject,
  note := "D-031 in a bracket on a stack with a count field: entry 1 was not extracted (last_entry = 0) ⇒ false even for !=" }
vector srv6BracketIndex := {
  id := "srv6-segments-bracket-index", ast := { layers := srv6Br (.cmp (segBr 1) .eq (.ipv6 s2)) },
  packet := srv6Two, expected := .accept [] }
vector srv6BracketSlice := {
  id := "srv6-segments-bracket-slice", ast := { layers := srv6Br (.cmp ⟨[("segments", some (.nat 1)), ("addr", some (.slice 64 128))]⟩ .eq (.int 2)) },
  packet := srv6Two, expected := .accept [] }
vector srv6OverCap := {
  id := "srv6-over-capacity", ast := { layers := srv6L }, packet := srv6Pkt 8 (List.replicate 9 s1), expected := .accept [],
  note := "9 segments, capacity 8: the walk keeps 8, steps over the 9th inside the declared region, and tcp follows" }
def nineSegs : Packet := srv6Pkt 8 (List.replicate 8 s1 ++ [s2])
vector srv6OverCapAnyKept := {
  id := "srv6-over-capacity-any-kept", ast := { layers := srv6L, cond := some (.any (.litCmp segIter .eq (.ipv6 s1))) },
  packet := nineSegs, expected := .accept [] }
vector srv6OverCapAnyDropped := {
  id := "srv6-over-capacity-any-dropped", ast := { layers := srv6L, cond := some (.any (.litCmp segIter .eq (.ipv6 s2))) },
  packet := nineSegs, expected := .reject, note := "the 9th segment was not kept, so any() cannot see it" }
vector srv6OverCapAll := {
  id := "srv6-over-capacity-all", ast := { layers := srv6L, cond := some (.all (.litCmp segIter .eq (.ipv6 s1))) },
  packet := srv6Pkt 8 (List.replicate 9 s1), expected := .reject,
  note := "all 9 segments are s1, but only 8 were kept: all() is false on a truncated stack" }
vector srv6OverCapNotAll := {
  id := "srv6-over-capacity-not-all", ast := { layers := srv6L, cond := some (.not (.all (.litCmp segIter .eq (.ipv6 s1)))) },
  packet := srv6Pkt 8 (List.replicate 9 s1), expected := .accept [] }
set_option maxRecDepth 65536 in
vector srv6PastScratch := {
  id := "srv6-past-scratch-window", ast := { layers := srv6L, cond := some (cmp (fld "tcp" "dport") .eq (k 80)) },
  packet := srv6Pkt 29 (List.replicate 30 s1), expected := .accept [], goStatus := .mismatch,
  note := "Go copies at most 512 bytes into its scratch window; the 30-segment SRH ends past it, so Go rejects (D-029 addendum 2)" }
set_option maxRecDepth 16384 in
vector srv6TenSegs := {
  id := "srv6-ten-segments", ast := { layers := srv6L, cond := some (cmp (fld "tcp" "dport") .eq (k 80)) },
  packet := srv6Pkt 9 (List.replicate 10 s1), expected := .accept [],
  note := "the walk stops at MAX_DEPTH, but the region ends at (last_entry + 1) × 16: tcp is where the header says" }
set_option maxRecDepth 16384 in
vector srv6TwelveSegs := {
  id := "srv6-twelve-segments", ast := { layers := srv6L, cond := some (cmp (fld "tcp" "dport") .eq (k 80)) },
  packet := srv6Pkt 11 (List.replicate 12 s1), expected := .accept [] }
vector srv6OverstatedLastEntry := {
  id := "srv6-last-entry-overstated", ast := { layers := srv6L },
  packet := srv6Pkt 9 (List.replicate 9 s1), expected := .reject,
  note := "last_entry says 10 segments, the packet has 9: tcp would start 16 bytes later and runs past the packet" }
vector srv6OverCapAllOrTrue := {
  id := "srv6-over-capacity-all-or-true", ast := { layers := srv6L, cond := some (.all (.or (.litCmp segIter .eq (.ipv6 s2)) (.boolLit true))) },
  packet := srv6Pkt 8 (List.replicate 9 s1), expected := .reject,
  note := "a true body does not make all() true on a truncated stack" }
vector srv6AbsentAllTrue := {
  id := "srv6-absent-all-true", ast := { layers := [P "eth", P "ipv6", Pq "srv6" .opt, P "tcp"], cond := some (.all (.or (.litCmp segIter .eq (.ipv6 s1)) (.boolLit true))) },
  packet := ipv6TCP, expected := .reject, note := "D-003: all() over the stack of an absent layer is false, even with a true body" }
vector srv6AtCapAll := {
  id := "srv6-at-capacity-all", ast := { layers := srv6L, cond := some (.all (.litCmp segIter .eq (.ipv6 s1))) },
  packet := srv6Pkt 7 (List.replicate 8 s1), expected := .accept [],
  note := "exactly as many segments as the stack holds: nothing truncated, all() decides" }
vector srv6OverCapIndex := {
  id := "srv6-over-capacity-index", ast := { layers := srv6L, cond := some (.litCmp (seg (.nat 7)) .eq (.ipv6 s1)) },
  packet := nineSegs, expected := .accept [] }
vector srv6OverCapLastEntry := {
  id := "srv6-over-capacity-last-entry", ast := { layers := srv6L, cond := some (cmp (fld "srv6" "last_entry") .eq (k 8)) },
  packet := nineSegs, expected := .accept [] }
vector srv6AtCap := {
  id := "srv6-at-capacity", ast := { layers := srv6L }, packet := srv6Pkt 7 (List.replicate 8 s1), expected := .accept [] }

-- GTP --------------------------------------------------------------------------

def gtpL : List Layer := [P "eth", P "ipv4", P "udp", P "gtp", P "ipv4", P "tcp"]
/-- `n` GTP extension headers, the last one ending the chain. -/
def gtpExtChain (n : Nat) : Packet :=
  ((List.range n).map fun i => gtpExt 1 (if i + 1 == n then 0 else 0x85)).flatten
set_option maxRecDepth 16384 in
vector gtpEightExts := {
  id := "gtp-eight-extensions", ast := { layers := gtpL },
  packet := gtpPkt (gtpHdr 4 ++ gtpOpt 0x85 ++ gtpExtChain 8), expected := .accept [] }
set_option maxRecDepth 16384 in
vector gtpNineExts := {
  id := "gtp-nine-extensions", ast := { layers := gtpL },
  packet := gtpPkt (gtpHdr 4 ++ gtpOpt 0x85 ++ gtpExtChain 9), expected := .accept [],
  note := "the walk can push 1 + GTP_MAX_DEPTH = 9 extensions and the stack holds 9 (the loader requires it outside a declared region)" }
set_option maxRecDepth 16384 in
vector gtpTenExts := {
  id := "gtp-ten-extensions", ast := { layers := gtpL },
  packet := gtpPkt (gtpHdr 4 ++ gtpOpt 0x85 ++ gtpExtChain 10), expected := .reject,
  note := "D-026: the walk stops after MAX_DEPTH; the tenth extension is read as the inner layer, which does not dispatch" }

def gtpExists := Where.fieldExists ⟨[("gtp", none), ("opt", none)]⟩
def gtpNextExt := Arith.field ⟨[("gtp", none), ("opt", none), ("next_ext", none)]⟩
def gtpExt0 := Arith.field ⟨[("gtp", none), ("exts", some (.nat 0)), ("ext_type", none)]⟩

vector gtpPlain := {
  id := "gtp-plain", ast := { layers := gtpL }, packet := gtpPkt (gtpHdr 0), expected := .accept [] }
vector gtpOptExists := {
  id := "gtp-opt-exists", ast := { layers := gtpL, cond := some gtpExists }, packet := gtpPkt (gtpHdr 2 ++ gtpOpt 0), expected := .accept [] }
vector gtpOptAbsent := {
  id := "gtp-opt-exists-absent", ast := { layers := gtpL, cond := some gtpExists }, packet := gtpPkt (gtpHdr 0), expected := .reject }
vector gtpOptField := {
  id := "gtp-opt-field", ast := { layers := gtpL, cond := some (cmp gtpNextExt .eq (k 0)) }, packet := gtpPkt (gtpHdr 2 ++ gtpOpt 0), expected := .accept [] }
vector gtpOptFieldAbsent := {
  id := "gtp-opt-field-absent", ast := { layers := gtpL, cond := some (cmp gtpNextExt .eq (k 0)) }, packet := gtpPkt (gtpHdr 0), expected := .reject, note := "D-027" }
vector gtpExtDynamicIndex := {
  id := "gtp-ext-dynamic-index",
  ast := { layers := gtpL, cond := some (cmp (Arith.field ⟨[("gtp", none), ("exts", some (.field ["gtp", "msg_type"])), ("ext_type", none)]⟩) .eq (k 2)) },
  packet := gtpPkt (gtpHdr 4 (msgType := 1) ++ gtpOpt 0x85 ++ gtpExt 1 0x85 (extLength := 2) ++ gtpExt 2 0), expected := .accept [],
  note := "msg_type = 1 indexes the second extension behind an 8-byte first one (variable-length walk, scale 4 with min_total)" }
vector gtpExtLongFirst := {
  id := "gtp-ext-after-long-ext",
  ast := { layers := gtpL, cond := some (cmp (Arith.field ⟨[("gtp", none), ("exts", some (.nat 1)), ("ext_type", none)]⟩) .eq (k 2)) },
  packet := gtpPkt (gtpHdr 4 ++ gtpOpt 0x85 ++ gtpExt 1 0x85 (extLength := 2) ++ gtpExt 2 0), expected := .accept [],
  note := "ext_length counts 4-byte units including the fixed part: an 8-byte first ext puts the second at +8" }
vector gtpExtLengthZero := {
  id := "gtp-ext-length-zero", ast := { layers := gtpL }, packet := gtpPkt (gtpHdr 4 ++ gtpOpt 0x85 ++ gtpExt 1 0 (extLength := 0)),
  expected := .reject, note := "ext_length 0 is below the 4-byte fixed part ⇒ malformed" }
vector gtpExtStack := {
  id := "gtp-ext-stack", ast := { layers := gtpL, cond := some (cmp gtpExt0 .eq (k 1)) }, packet := gtpPkt (gtpHdr 4 ++ gtpOpt 0x85 ++ gtpExt 1 0), expected := .accept [] }

-- IPv4 options -----------------------------------------------------------------

def rr (i : Index) := Arith.field ⟨[("ipv4", none), ("options", none), ("RR", none), ("addrs", some i), ("addr", none)]⟩
def rrIter := FieldPath.mk [("ipv4", none), ("options", none), ("RR", none), ("addrs", none), ("addr", none)]
vector ipv4RrStatic := {
  id := "ipv4-rr-static", ast := { layers := chain3, cond := some (.litCmp ⟨[("ipv4", none), ("options", none), ("RR", none), ("addrs", some (.nat 1)), ("addr", none)]⟩ .eq (.ipv4 0x0a00000a)) },
  packet := rrPkt, expected := .accept [], note := "D-030: rr is sighted by kind byte 7; addrs follow its 3-byte header, count (11-3)/4 = 2" }
vector ipv4RrAny := {
  id := "ipv4-rr-any", ast := { layers := chain3, cond := some (.any (.litCmp rrIter .eq (.ipv4 0x0a000009))) }, packet := rrPkt, expected := .accept [] }
vector ipv4RrArith := {
  id := "ipv4-rr-arith", ast := { layers := chain3, cond := some (cmp (rr (.nat 0)) .eq (k 0x0a000009)) }, packet := rrPkt, expected := .accept [] }

-- GRE flag-gated options ---------------------------------------------------------

/-- GRE header: flags/version then protocol type, plus one 4-byte word per set flag (C, K, S). -/
def greHdr (flags : Nat) (words : List Nat) : Packet := be 2 flags ++ be 2 0x0800 ++ (words.map (be 4)).flatten
def grePkt (gre : Packet) : Packet := eth 0x0800 ++ ipv4 47 ++ gre ++ ipv4 6 ++ tcp 12345 80 ++ payload 5
def greL : List Layer := [P "eth", P "ipv4", P "gre", P "ipv4", P "tcp"]

vector grePlain := {
  id := "gre-plain", ast := { layers := greL }, packet := grePkt (greHdr 0 []), expected := .accept [] }
vector greKey := {
  id := "gre-key", ast := { layers := greL }, packet := grePkt (greHdr 0x2000 [42]), expected := .accept [],
  note := "GRE_OPT_TRIGGER_K: the K flag adds a 4-byte key before the payload" }
vector greKeySeq := {
  id := "gre-key-seq", ast := { layers := greL, cond := some (cmp dport .eq (k 80)) }, packet := grePkt (greHdr 0x3000 [42, 7]), expected := .accept [] }
vector greAllFlags := {
  id := "gre-c-k-s", ast := { layers := greL }, packet := grePkt (greHdr 0xb000 [0, 42, 7]), expected := .accept [] }
vector greKeyTruncated := {
  id := "gre-key-truncated", ast := { layers := greL }, packet := eth 0x0800 ++ ipv4 47 ++ greHdr 0x2000 [], expected := .reject,
  note := "K set but the key word is missing" }
vector greAllTruncatedLast := {
  id := "gre-c-k-s-last-truncated", ast := { layers := [P "eth", P "ipv4", P "gre"] },
  packet := eth 0x0800 ++ ipv4 47 ++ greHdr 0xb000 [0, 42], expected := .reject,
  note := "D-005: C, K and S set, the S word missing; gre is the last layer, so only its own bounds check can reject" }
vector greAllLast := {
  id := "gre-c-k-s-last", ast := { layers := [P "eth", P "ipv4", P "gre"] },
  packet := eth 0x0800 ++ ipv4 47 ++ greHdr 0xb000 [0, 42, 7], expected := .accept [],
  note := "all three words present and nothing after them" }

-- Sightings only where the walk dispatched (review finding on D-030) -------------

vector rrNoSighting := {
  id := "ipv4-rr-no-options-sport-looks-like-rr",
  ast := { layers := chain3, cond := some (cmp (rr (.nat 0)) .ne (k 0)) },
  packet := eth 0x0800 ++ ipv4 6 ++ tcp 0x070b 80 ++ payload 5, expected := .reject,
  note := "ihl = 5: the walk's `(true, _)` lookahead reads tcp.sport (0x07) but does not dispatch on it, so RR is not sighted" }
vector sackNoSighting := {
  id := "tcp-opt-sack-payload-looks-like-sack",
  ast := { layers := chain3, cond := some (.any (cmp (sackIter "right") .eq (k 200))) },
  packet := eth 0x0800 ++ ipv4 6 ++ tcp 12345 80 (dataOffset := 6) (options := mssOpt 1460) ++ [5, 10] ++ be 4 100 ++ be 4 200, expected := .reject,
  note := "the payload after the option region starts with a SACK-shaped kind byte; the walk ended on the counter, so no sighting" }

-- Quantifier stack identity and absent layers (review findings) ------------------

vector srv6AnyLabel := {
  id := "srv6-segments-any-label",
  ast := { layers := [P "eth", P "ipv6", .proto { name := "srv6", label := some "sr" }, P "tcp"],
           cond := some (.any (.and (.litCmp ⟨[("sr", none), ("segments", none), ("addr", none)]⟩ .eq (.ipv6 s1))
                                   (.litCmp segIter .ne (.ipv6 s2)))) },
  packet := srv6Two, expected := .accept [], note := "`sr.segments` and `srv6.segments` are the same stack" }
vector srv6AllAbsent := {
  id := "srv6-all-absent-layer",
  ast := { layers := [P "eth", P "ipv6", Pq "srv6" .opt, P "tcp"], cond := some (.all (.litCmp segIter .ne (.ipv6 s1))) },
  packet := ipv6TCP, expected := .reject,
  note := "D-003: a quantifier over an absent layer is false, not vacuously true" }
-- An optional variable-length layer (`srv6?`, `gre?`): the parent's constant decides presence.
def srv6OptL : List Layer := [P "eth", P "ipv6", Pq "srv6" .opt, P "tcp"]
def dport80 : Where := .arith (fld "tcp" "dport") .eq (k 80)
vector srv6OptPresent := {
  id := "srv6-opt-present", ast := { layers := srv6OptL, cond := some dport80 }, packet := srv6Two, expected := .accept [],
  note := "tcp is read past the SRH (Go: runtime entry slot)" }
vector srv6OptAbsent := {
  id := "srv6-opt-absent", ast := { layers := srv6OptL, cond := some dport80 }, packet := ipv6TCP, expected := .accept [],
  note := "no SRH: tcp dispatches on ipv6.next_header (D-034)" }
vector srv6OptAnyPresent := {
  id := "srv6-opt-any-present", ast := { layers := srv6OptL, cond := some (.any (.litCmp segIter .eq (.ipv6 s2))) },
  packet := srv6Two, expected := .accept [] }
vector srv6OptAnyAbsent := {
  id := "srv6-opt-any-absent", ast := { layers := srv6OptL, cond := some (.any (.litCmp segIter .eq (.ipv6 s2))) },
  packet := ipv6TCP, expected := .reject, note := "D-003: a field of the absent layer is false" }
vector srv6OptBroken := {
  id := "srv6-opt-broken", ast := { layers := srv6OptL },
  packet := eth 0x86DD ++ ipv6 43 ++ [6, 2, 5, 0, 0, 0, 0, 0] ++ be 16 s1 ++ tcp 12345 80 ++ payload 5, expected := .reject,
  note := "D-017: ipv6.next_header = 43 names the routing header, so routing_type 5 is a broken SRH, not an absent one" }
vector srv6OptThenIPv4Opt := {
  id := "srv6-opt-then-ipv4-opt", ast := { layers := [P "eth", P "ipv6", Pq "srv6" .opt, Pq "ipv4" .opt] },
  packet := ipv6TCP, expected := .accept [],
  note := "D-017: srv6 absent, so ipv4? faces ipv6, which has no constant for it; the tcp bytes fail ipv4's self-validation, a miss" }
vector tcpOptAccAbsent := {
  id := "tcp-opt-acc-absent-layer",
  ast := { layers := [P "eth", P "ipv4", Pq "tcp" .opt],
           cond := some (.and (cmp mss .eq (k 1460)) (cmp (Arith.field ⟨[("tcp", none), ("options", none), ("WS", none), ("shift", none)]⟩) .eq (k 7))) },
  packet := eth 0x0800 ++ ipv4 17 ++ udp 53 53 ++ payload 5, expected := .reject,
  note := "D-003: tcp is absent, both option atoms are false (Go: the option accumulator slot is zeroed before the optional layer's dispatch)" }
def greOptL : List Layer := [P "eth", P "ipv4", Pq "gre" .opt, P "ipv4", P "tcp"]
vector greOptPresent := {
  id := "gre-opt-present", ast := { layers := greOptL }, packet := grePkt (greHdr 0x2000 [42]), expected := .accept [],
  note := "an optional flag-gated header: the inner ipv4 sits past the key word" }
vector greOptAbsent := {
  id := "gre-opt-absent", ast := { layers := greOptL },
  packet := eth 0x0800 ++ ipv4 4 ++ ipv4 6 ++ tcp 12345 80 ++ payload 5, expected := .accept [],
  note := "no gre: the inner ipv4 dispatches on the outer protocol = 4" }

def auxVectors : List Vector := [
  srv6AnyLabel, srv6AllAbsent, srv6OptPresent, srv6OptAbsent, srv6OptAnyPresent, srv6OptAnyAbsent, srv6OptBroken, srv6OptThenIPv4Opt, tcpOptAccAbsent, greOptPresent, greOptAbsent,
  rrNoSighting, sackNoSighting,
  grePlain, greKey, greKeySeq, greAllFlags, greKeyTruncated, greAllTruncatedLast, greAllLast,
  tcpMss, tcpMssWide, tcpMssWsWide, tcpMssWsWideHigh, tcpMssWsWideFits64, tcpMssMiss, tcpMssAbsent, tcpMssAbsentNot, tcpMssAfterNop, tcpUnknownSkipped, tcpUnknownLen0, tcpUnknownLen1,
  tcpOptCross, tcpEol, tcpMssDup, tcpMssBadLen, tcpMssExists, tcpMssExistsNot, tcpSackBlock, tcpSackAny, tcpSackAll,
  tcpSackAbsentAny, tcpMalformedNoQuery, tcpMalformedNotQuery, tcpMalformedOrTrue, tcpMalformedExists,
  tcpMalformedAfterMss, tcpMalformedChainOn, ipv4MalformedOpts, ipv4MalformedOptsQueried, ipv4OptDepthLastFault, ipv4OptDepthLastSighting,
  tcpOptsValid, tcpOptsValidNone, tcpOptsInvalid, tcpOptsInvalidNot, tcpOptsValidWithMss, tcpOptsValidAbsent, tcpOptsValidAltMember, tcpOptsValidAltOther, tcpOptsValidTwoOptions, tcpOptsValidTwoOptionsLast, tcpOptsValidTwoOptionsMalformed, tcpOptsValidTwoOptionsMiss, tcpOptsValidTwoOptionsOptional, tcpOptsValidTwoOptionsAlt, tcpOptsValidTwoOptionsLabel, tcpOptsValidTwoOptionsOtherLayer, bracketValid, bracketValidMalformed, bracketValidOptMalformed, bracketValidWithCmp, typBracketValidNoRegion, bracketValidAltFirst, bracketValidAltSecond, bracketValidAltOther, bracketValidFirst,
  bracketValidNoOpts, bracketValidOptAbsent, bracketValidIPv4, bracketValidGeneve, bracketValidTwoOptions, bracketValidRepeated, typBracketValidSegment, typBracketValidSrv6, ipv4OptsInvalid,
  geneveOvnHit, geneveMalformedAfter, geneveMalformedBefore, geneveMalformedChainOn, geneveRegionPastEnd, geneveValidEmpty, typOptsValidNoRegion,
  ipv6Hbh, ipv6TwoExts, ipv6ExtLong, ipv6ExtTooLong, ipv6ExtsIndex, ipv6ExtsIndex1, ipv6ExtsIndexAfterLong, ipv6ExtsAnyAfterLong, ipv6ExtsDynamicLong, ipv6ExtsDynamicLongSecond, ipv6ExtsDynamicLongAbsent, ipv6ExtsDynamicLongLast, ipv6ExtsDynamicLongLastMiss, ipv6ExtsDynamicLongBeyond, ipv6ExtsDynamicLongSlot, ipv6ExtsDynamicLongSlotAbsent,
  ipv6ExtsBracket, ipv6ExtsBracketAbsent, ipv6ExtsBracketLong, ipv6ExtsBracketDynamic, ipv6ExtsBracketIter, ipv6ExtsBracketInAbsent, ipv6ExtsBracketInLong, ipv6ExtsSliceLong, ipv6ExtsBracketSliceLong, gtpExtsBracket, gtpExtsBracketAbsent, gtpExtsBracketNone, gtpExtsBracketMixed, gtpExtsBracketMixedMiss, ipv6ExtsIndexAbsent,
  ipv6NextHeaderWhere, ipv6NextHeaderBracket, altIPv6MemberWriteBack, altIPv6MemberWriteBackWhere, altIPv6MemberWriteBackMiss, ipv6FiveExts, ipv6SixExts, ipv6AnyExts, ipv6AllExts,
  srv6TruncatedFails, typSrv6NoValid, geneveVersionOne, srv6SegWideLit, srv6Chain, srv6Static, srv6Dynamic, srv6Any, srv6All, srv6AllCidr, srv6IndexAbsent, srv6DynamicAtCount, srv6DynamicLast, srv6OptDynamicAtCount, srv6OptDynamicLast, srv6BracketIndexAbsent, srv6BracketIndex, srv6StaticSlice, srv6StaticSliceAbsent, srv6BracketSlice, srv6OverCap, srv6OverCapAnyKept, srv6OverCapAnyDropped, srv6OverCapAll, srv6OverCapNotAll,
  srv6OverCapIndex, srv6OverCapLastEntry, srv6AtCapAll, srv6PastScratch, srv6TenSegs, srv6TwelveSegs, srv6OverstatedLastEntry,
  srv6OverCapAllOrTrue, srv6AbsentAllTrue, srv6AtCap,
  gtpEightExts, gtpNineExts, gtpTenExts, gtpPlain, gtpOptExists, gtpOptAbsent, gtpOptField, gtpOptFieldAbsent, gtpExtDynamicIndex, gtpExtLongFirst, gtpExtLengthZero, gtpExtStack,
  ipv4RrStatic, ipv4RrAny, ipv4RrArith]

end Kunai
