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
def srv6Hdr (next lastEntry : Nat) : Packet :=
  [UInt8.ofNat next, UInt8.ofNat (2 * (lastEntry + 1)), 4, 0, UInt8.ofNat lastEntry, 0, 0, 0]
def srv6Pkt (lastEntry : Nat) (segs : List Nat) : Packet :=
  eth 0x86DD ++ ipv6 43 ++ srv6Hdr 6 lastEntry ++ (segs.map (be 16)).flatten ++ tcp 12345 80 ++ payload 5
def gtpHdr (flags : Nat) : Packet := [UInt8.ofNat (0x30 + flags), 0xff] ++ be 2 28 ++ be 4 1
def gtpOpt (nextExt : Nat) : Packet := be 2 7 ++ [0, UInt8.ofNat nextExt]
def gtpExt (extType nextExt : Nat) : Packet := [1] ++ be 2 extType ++ [UInt8.ofNat nextExt]
def gtpPkt (gtp : Packet) : Packet :=
  eth 0x0800 ++ ipv4 17 ++ udp 2152 2152 ++ gtp ++ ipv4 6 ++ tcp 12345 80 ++ payload 5
def rrPkt : Packet :=
  eth 0x0800 ++ ipv4 6 (ihl := 8) (options := [7, 11, 4] ++ be 4 0x0a000009 ++ be 4 0x0a00000a ++ [1]) ++ tcp 12345 80 ++ payload 5

def mss := Arith.field ⟨[("tcp", none), ("options", none), ("MSS", none), ("value", none)]⟩
def tcpW (w : Where) (pkt : Packet) (id : String) (expected : Result) (goStatus : GoStatus := .ok) (note : String := "") : Vector :=
  { id, ast := { layers := chain3, cond := some w }, packet := pkt, expected, goStatus, note }

-- TCP options ----------------------------------------------------------------

vector tcpMss := tcpW (cmp mss .eq (k 1460)) (tcpOpts (mssOpt 1460)) "tcp-opt-mss-value" (.accept [])
vector tcpMssMiss := tcpW (cmp mss .eq (k 1460)) (tcpOpts (mssOpt 1400)) "tcp-opt-mss-mismatch" .reject
vector tcpMssAbsent := tcpW (cmp mss .eq (k 1460)) ethIPv4TCP "tcp-opt-mss-absent" .reject (note := "D-027: the atom is false")
vector tcpMssAbsentNot := tcpW (.not (cmp mss .eq (k 1460))) ethIPv4TCP "tcp-opt-mss-absent-not" (.accept []) .mismatch
  "D-027: absent option ⇒ atom false ⇒ not(false); Go rejects the filter on the sentinel"
vector tcpMssAfterNop := tcpW (cmp mss .eq (k 1460)) (tcpOpts ([1, 1] ++ mssOpt 1460 ++ [1, 1])) "tcp-opt-mss-after-nop" (.accept [])
vector tcpUnknownSkipped := tcpW (cmp mss .eq (k 1460)) (tcpOpts ([25, 4, 0, 0] ++ mssOpt 1460)) "tcp-opt-unknown-skipped" (.accept [])
vector tcpUnknownLen0 := tcpW (cmp mss .eq (k 1460)) (tcpOpts [25, 0, 0, 0]) "tcp-opt-unknown-len0" .reject (note := "D-028: no progress")
vector tcpUnknownLen1 := tcpW (cmp mss .eq (k 1460)) (tcpOpts [25, 1, 0, 0]) "tcp-opt-unknown-len1" .reject (note := "D-028: no progress")
vector tcpOptCross := tcpW (cmp mss .eq (k 1460)) (tcpOpts [1, 1, 2, 4]) "tcp-opt-crosses-region" .reject
  (note := "MSS declared in the last 2 bytes of the option region: the counter underflows")
vector tcpEol := tcpW (cmp dport .eq (k 80)) (tcpOpts [0, 0, 0, 0]) "tcp-opt-eol" (.accept [])
vector tcpMssDup := tcpW (cmp mss .eq (k 16)) (tcpOpts (mssOpt 1460 ++ mssOpt 16)) "tcp-opt-mss-duplicate-last-wins" (.accept []) (note := "D-030")
vector tcpMssBadLen := tcpW (cmp mss .eq (k 1460)) (tcpOpts [2, 3, 5, 0xb4]) "tcp-opt-mss-bad-length" .reject
vector tcpMssExists := tcpW (.fieldExists ⟨[("tcp", none), ("options", none), ("MSS", none)]⟩) (tcpOpts (mssOpt 1460)) "tcp-opt-mss-exists" (.accept []) .mismatch
  "Go: `tcp.options.MSS.exists` is a resolver error (not yet implemented)"
vector tcpMssExistsNot := tcpW (.fieldExists ⟨[("tcp", none), ("options", none), ("MSS", none)]⟩) ethIPv4TCP "tcp-opt-mss-exists-absent" .reject .mismatch
  "Go: `tcp.options.MSS.exists` is a resolver error (not yet implemented)"
def sackBlock := Arith.field ⟨[("tcp", none), ("options", none), ("SACK", none), ("blocks", some (.nat 0)), ("left", none)]⟩
def sackIter (f : String) := Arith.field ⟨[("tcp", none), ("options", none), ("SACK", none), ("blocks", none), (f, none)]⟩
def sackPkt : Packet := tcpOpts ([1, 1, 5, 10] ++ be 4 100 ++ be 4 200)
vector tcpSackBlock := tcpW (cmp sackBlock .eq (k 100)) sackPkt "tcp-opt-sack-block-static" (.accept []) (note := "D-030: sack is sighted by kind byte; blocks follow its 2-byte header")
vector tcpSackAny := tcpW (.any (cmp (sackIter "right") .eq (k 200))) sackPkt "tcp-opt-sack-any" (.accept [])
vector tcpSackAll := tcpW (.all (cmp (sackIter "left") .eq (k 1))) sackPkt "tcp-opt-sack-all-false" .reject
vector tcpSackAbsentAny := tcpW (.any (cmp (sackIter "right") .eq (k 200))) ethIPv4TCP "tcp-opt-sack-absent-any" .reject (note := "D-007: empty stack ⇒ any is false")
vector tcpMalformedNoQuery := {
  id := "tcp-opt-malformed-no-query", ast := { layers := chain3 }, packet := tcpOpts [25, 0, 0, 0],
  expected := .reject, goStatus := .mismatch, note := "D-029: the parser always walks the options; Go only walks when an option is queried" }

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
vector ipv6ExtsIndexAbsent := {
  id := "ipv6-exts-index-absent", ast := { layers := ipv6L, cond := some (cmp exts1 .eq (k 6)) }, packet := ipv6With 0 (ipv6Ext 6) (sport := 0x0600),
  expected := .reject, goStatus := .mismatch, note := "D-031: entry 1 was not extracted ⇒ false; Go reads the bytes at the slot (tcp.sport = 0x0600 makes them look like next_header 6)" }
vector ipv6NextHeaderWhere := {
  id := "ipv6-next-header-writeback-where", ast := { layers := ipv6L, cond := some (cmp (fld "ipv6" "next_header") .eq (k 6)) },
  packet := hbhTcp, expected := .accept [], note := "where sees the written-back next_header" }
vector ipv6NextHeaderBracket := {
  id := "ipv6-next-header-writeback-bracket",
  ast := { layers := [P "eth", .proto { name := "ipv6", preds := [.cmp (f "next_header") .eq (.int 6)] }, P "tcp"] }, packet := hbhTcp,
  expected := .accept [], goStatus := .mismatch, note := "D-032: bracket predicates run after aux-extract (σ'); Go evaluates them on the original header" }
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
  expected := .accept [], goStatus := .mismatch, note := "D-031: all ranges over the 2 extracted entries; Go unrolls 8 capacity slots and fails on the ones past the packet" }

-- SRv6 -----------------------------------------------------------------------

def srv6L : List Layer := [P "eth", P "ipv6", P "srv6", P "tcp"]
def seg (i : Index) := FieldPath.mk [("srv6", none), ("segments", some i), ("addr", none)]
def segIter := FieldPath.mk [("srv6", none), ("segments", none), ("addr", none)]
def s1 : Nat := 0xfc000000000000000000000000000001
def s2 : Nat := 0xfc000000000000000000000000000002
def srv6Two : Packet := srv6Pkt 1 [s1, s2]

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
  expected := .reject, goStatus := .mismatch, note := "D-031: entry 2 was not extracted ⇒ false even for !=; Go's != reads the bytes past the list" }
vector srv6OverCap := {
  id := "srv6-over-capacity", ast := { layers := srv6L }, packet := srv6Pkt 8 (List.replicate 9 s1), expected := .reject,
  note := "P-Extract-Stack-Full: capacity 8" }
vector srv6AtCap := {
  id := "srv6-at-capacity", ast := { layers := srv6L }, packet := srv6Pkt 7 (List.replicate 8 s1), expected := .accept [] }

-- GTP --------------------------------------------------------------------------

def gtpL : List Layer := [P "eth", P "ipv4", P "udp", P "gtp", P "ipv4", P "tcp"]
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

def auxVectors : List Vector := [
  tcpMss, tcpMssMiss, tcpMssAbsent, tcpMssAbsentNot, tcpMssAfterNop, tcpUnknownSkipped, tcpUnknownLen0, tcpUnknownLen1,
  tcpOptCross, tcpEol, tcpMssDup, tcpMssBadLen, tcpMssExists, tcpMssExistsNot, tcpSackBlock, tcpSackAny, tcpSackAll,
  tcpSackAbsentAny, tcpMalformedNoQuery,
  ipv6Hbh, ipv6TwoExts, ipv6ExtLong, ipv6ExtTooLong, ipv6ExtsIndex, ipv6ExtsIndex1, ipv6ExtsIndexAbsent,
  ipv6NextHeaderWhere, ipv6NextHeaderBracket, ipv6FiveExts, ipv6SixExts, ipv6AnyExts, ipv6AllExts,
  srv6Chain, srv6Static, srv6Dynamic, srv6Any, srv6All, srv6AllCidr, srv6IndexAbsent, srv6OverCap, srv6AtCap,
  gtpPlain, gtpOptExists, gtpOptAbsent, gtpOptField, gtpOptFieldAbsent, gtpExtStack,
  ipv4RrStatic, ipv4RrAny, ipv4RrArith]

end Kunai
