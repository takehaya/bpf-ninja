import Kunai.Vectors.Chain

/-!
# `where`, predicate, capture, and typing vectors
-/
namespace Kunai
open Pkt

def W (w : Where) : Filter := { layers := chain3, cond := some w }
def cmp (l : Arith) (op : CmpOp) (r : Arith) : Where := .arith l op r
def dport := fld "tcp" "dport"
def ttl := fld "ipv4" "ttl"

-- Comparisons and literals ---------------------------------------------------

vector whereCmpOps := {
  id := "where-cmp-ops",
  ast := W (.and (cmp dport .gt (k 79)) (.and (cmp dport .le (k 80)) (.and (cmp (k 80) .ge dport) (cmp (fld "tcp" "sport") .ne (k 80))))),
  expected := .accept [] }
vector whereLitIPv4 := {
  id := "where-litcmp-ipv4", ast := W (.litCmp (ff "ipv4" "src") .eq (.ipv4 0x0a000001)), expected := .accept [] }
vector whereCIDRIn := {
  id := "where-cidr-member", ast := W (.litCmp (ff "ipv4" "dst") .eq (.cidr4 0x0a000000 8)), expected := .accept [] }
vector whereCIDRNe := {
  id := "where-cidr-not-member", ast := W (.litCmp (ff "ipv4" "dst") .ne (.cidr4 0x0a000000 8)), expected := .reject }
vector whereCIDR0 := {
  id := "where-cidr-zero", ast := W (.litCmp (ff "ipv4" "dst") .eq (.cidr4 0 0)), expected := .accept [],
  note := "/0 matches everything" }
vector whereMAC := {
  id := "where-mac", ast := W (.litCmp (ff "eth" "dst") .eq (.mac 0x001122334455)), expected := .accept [] }
vector whereIPv6CIDR := {
  id := "where-ipv6-cidr",
  ast := { layers := [P "eth", P "ipv6", P "tcp"], cond := some (.litCmp (ff "ipv6" "src") .eq (.cidr6 0xfc000000000000000000000000000000 8)) },
  packet := ipv6TCP, expected := .accept [] }
vector whereIPv6Eq := {
  id := "where-ipv6-eq",
  ast := { layers := [P "eth", P "ipv6", P "tcp"], cond := some (.litCmp (ff "ipv6" "dst") .eq (.ipv6 0xfc000000000000000000000000000002)) },
  packet := ipv6TCP, expected := .accept [] }
vector whereNegLitMiss := {
  id := "where-negative-literal-miss", ast := W (cmp dport .eq (k (-1))), expected := .reject,
  note := "-1 ⤳ 0xffff (Int<16> narrow), dport = 80" }
vector whereNegLitHit := {
  id := "where-negative-literal-hit", ast := W (cmp dport .eq (k (-1))),
  packet := ethIPv4TCP (dport := 65535), expected := .accept [] }
vector whereConstFold := {
  id := "where-const-fold", ast := W (cmp (k 300) .gt (k 200)), expected := .accept [], note := "D-009: 64-bit" }

-- Arithmetic (§13.9, D-014, D-015) ------------------------------------------

vector whereArithOps := {
  id := "where-arith-ops",
  ast := W (cmp (.bin .mod (.bin .div (.bin .sub (.bin .mul dport (k 2)) (k 60)) (k 10)) (k 7)) .eq (k 3)),
  expected := .accept [], note := "((80*2)-60)/10 % 7 = 3" }
vector whereBitwise := {
  id := "where-bitwise",
  ast := W (.and (cmp (.bin .band (fld "tcp" "flags") (k 2)) .eq (k 2))
                 (.and (cmp (.bin .bor ttl (k 1)) .eq (k 65)) (cmp (.bin .bxor ttl (k 64)) .eq (k 0)))),
  expected := .accept [] }
vector whereShiftMasked := {
  id := "where-shift-masked", ast := W (cmp (.bin .shl ttl (k 65)) .eq (k 128)),
  expected := .accept [], note := "D-014: shift amount is masked to 6 bits, so << 65 is << 1" }
vector whereNoWrap := {
  id := "where-arith-no-wrap", ast := W (cmp (.bin .add ttl (k 1)) .gt (k 200)),
  packet := eth 0x0800 ++ ipv4 6 (ttl := 255) ++ tcp 12345 80 ++ payload 5, expected := .accept [],
  note := "D-015: 255 + 1 = 256 in Int<64>; §13.9 as written would give 0" }
vector whereDivZero := {
  id := "where-div-by-zero-dynamic", ast := W (cmp (.bin .div dport ttl) .eq (k 0)),
  packet := eth 0x0800 ++ ipv4 6 (ttl := 0) ++ tcp 12345 80 ++ payload 5, expected := .accept [], note := "§13.9: n₂ = 0 ⇒ 0" }
vector whereModZero := {
  id := "where-mod-by-zero-dynamic", ast := W (cmp (.bin .mod dport ttl) .eq (k 80)),
  packet := eth 0x0800 ++ ipv4 6 (ttl := 0) ++ tcp 12345 80 ++ payload 5, expected := .accept [],
  note := "D-022: BPF MOD by zero leaves the dividend; §13.9 says 0" }
vector whereMixedWidth := {
  id := "where-mixed-width", ast := W (cmp (.bin .add ttl dport) .eq (k 144)),
  expected := .accept [], note := "Int<8> + Int<16>: 64 + 80" }

-- Booleans (§12.4, §13.8) ---------------------------------------------------

vector whereTrue := {
  id := "where-true", ast := W (.boolLit true), expected := .accept [] }
vector whereFalse := {
  id := "where-false", ast := W (.boolLit false), expected := .reject }
vector whereDecay := {
  id := "where-int-decay", ast := W (cmp dport .ne (k 0)), expected := .accept [],
  note := "`where tcp.dport` parses to `tcp.dport != 0` [T-Where-Bool-Decay]" }
vector whereNot := {
  id := "where-not", ast := W (.not (cmp dport .eq (k 80))), expected := .reject }
vector whereOr := {
  id := "where-or", ast := W (.or (cmp dport .eq (k 1)) (cmp ttl .eq (k 64))), expected := .accept [] }
vector whereBoolEqIff := {
  id := "where-booleq-iff", ast := W (.boolEq (cmp dport .eq (k 80)) .eq (cmp ttl .eq (k 64))), expected := .accept [] }
vector whereBoolEqXor := {
  id := "where-booleq-xor", ast := W (.boolEq (cmp dport .eq (k 80)) .ne (.boolLit true)), expected := .reject }

-- Layer references (D-003, D-013, D-018) --------------------------------------

def vlanOptTci (w : Where) : Filter := { layers := vlanOpt, cond := some w }

vector whereAbsentFalse := {
  id := "where-absent-layer-false", ast := vlanOptTci (cmp (fld "vlan" "tci") .eq (k 1)),
  expected := .reject, goStatus := .notImplemented, note := "D-003 (a): atom on an absent layer is false" }
vector whereAbsentNot := {
  id := "where-absent-layer-not", ast := vlanOptTci (.not (cmp (fld "vlan" "tci") .eq (k 1))),
  expected := .accept [], goStatus := .notImplemented, note := "D-003 (a): not(false)" }
vector whereOptPresent := {
  id := "where-optional-present", ast := vlanOptTci (cmp (fld "vlan" "tci") .eq (k 100)),
  packet := vlanPkt, expected := .accept [], goStatus := .notImplemented }
vector wherePastQuantified := {
  id := "where-past-quantified-ok", ast := vlanOptTci (cmp dport .eq (k 80)),
  packet := vlanPkt, expected := .accept [], note := "Go compiles this one: ipv4 is a runtime-offset layer" }
vector whereLabels := {
  id := "where-label-inner-outer",
  ast := { layers := [P "eth", .proto { name := "ipv4", label := some "outer" }, .proto { name := "ipv4", label := some "inner" }, P "tcp"],
           cond := some (.and (cmp (fld "inner" "ttl") .eq (k 64)) (cmp (fld "outer" "ttl") .eq (k 32))) },
  packet := ipipPkt, expected := .accept [] }
vector whereAmbiguous := {
  id := "where-ambiguous",
  ast := { layers := [P "eth", P "ipv4", P "ipv4", P "tcp"], cond := some (cmp ttl .eq (k 1)) },
  packet := ipipPkt, expected := .illTyped "protocol ipv4 is ambiguous; qualify with an @label" }

-- Actions ----------------------------------------------------------------------

vector actionEntry := {
  id := "where-action-entry-host", ast := W (.action "XDP_DROP"),
  expected := .illTyped "`action ==` is not available on this host" }
vector actionHit := {
  id := "host-xdp-exit-action-hit", host := .xdp_exit, action := 1, ast := W (.action "XDP_DROP"), expected := .accept [] }
vector actionMiss := {
  id := "host-xdp-exit-action-miss", host := .xdp_exit, action := 2, ast := W (.action "XDP_DROP"), expected := .reject }
vector actionUnknown := {
  id := "host-xdp-exit-action-unknown", host := .xdp_exit, action := 1, ast := W (.action "TC_ACT_OK"),
  expected := .illTyped "unknown action TC_ACT_OK" }

-- Bracket predicates (§13.7, D-011) -------------------------------------------

def tcpPred (p : Predicate) : Filter := { layers := [P "eth", P "ipv4", .proto { name := "tcp", preds := [p] }] }

vector predCmp := {
  id := "pred-cmp", ast := tcpPred (.cmp (f "dport") .lt (.int 1024)), expected := .accept [] }
vector predCmpMiss := {
  id := "pred-cmp-miss", ast := tcpPred (.cmp (f "dport") .gt (.int 1024)), expected := .reject }
vector predInList := {
  id := "pred-in-list", ast := tcpPred (.inList (f "dport") [.int 22, .int 80, .int 443]), expected := .accept [] }
vector predInListMiss := {
  id := "pred-in-list-miss", ast := tcpPred (.inList (f "dport") [.int 22, .int 443]), expected := .reject }
vector predInRange := {
  id := "pred-in-range", ast := tcpPred (.inList (f "dport") [.range 79 81]), expected := .accept [],
  goStatus := .notImplemented, note := "D-011: lo ≤ n ≤ hi" }
vector predNegative := {
  id := "pred-negative-literal", ast := tcpPred (.cmp (f "dport") .eq (.int (-1))),
  packet := ethIPv4TCP (dport := 65535), expected := .accept [] }
vector predIPv4 := {
  id := "pred-ipv4-literal",
  ast := { layers := [P "eth", .proto { name := "ipv4", preds := [.cmp (f "dst") .eq (.cidr4 0x0a000000 24), .cmp (f "src") .ne (.ipv4 0x0a000002)] }, P "tcp"] },
  expected := .accept [] }

-- Captures (§13.6) ---------------------------------------------------------------

vector capAll := {
  id := "cap-specs",
  ast := { layers := chain3, captures := [{ spec := .all }, { spec := .headers }, { spec := .headersPlus 16 },
    { spec := .absolute 32 }, { spec := .toLayer "ipv4" 4 }, { spec := .toLayer "tcp" 0 }] },
  expected := .accept [(0, 59), (0, 54), (0, 59), (0, 32), (14, 38), (34, 54)] }
vector capWhereFalse := {
  id := "cap-where-false-rejects",
  ast := { layers := chain3, captures := [{ spec := .all, cond := some (cmp dport .eq (k 80)) }, { spec := .headers, cond := some (cmp dport .eq (k 1)) }] },
  expected := .reject, note := "D-021: per-capture where is ANDed into the verdict" }
vector capWhereTrue := {
  id := "cap-where-true",
  ast := { layers := chain3, cond := some (cmp ttl .eq (k 64)),
           captures := [{ spec := .all, cond := some (cmp dport .eq (k 80)) }, { spec := .headers, cond := some (cmp dport .ne (k 1)) }] },
  expected := .accept [(0, 59), (0, 54)] }
vector capLabel := {
  id := "cap-label",
  ast := { layers := [P "eth", .proto { name := "ipv4", label := some "ip" }, P "tcp"], captures := [{ spec := .toLayer "ip" 0 }] },
  expected := .accept [(14, 34)] }
vector capAbsent := {
  id := "cap-absent-layer",
  ast := { layers := vlanOpt, captures := [{ spec := .toLayer "vlan" 0 }] },
  expected := .accept [], goStatus := .notImplemented, note := "D-020" }

-- Typing (§12) ------------------------------------------------------------------

vector typUnknownProto := {
  id := "typ-unknown-proto", ast := { layers := [P "eth", P "foo"] }, expected := .illTyped "unknown protocol foo" }
vector typNoDispatch := {
  id := "typ-no-dispatch", ast := { layers := [P "eth", P "udp"] },
  expected := .illTyped "no dispatch constant for udp under eth" }
vector typNotInChain := {
  id := "typ-field-not-in-chain", ast := W (cmp (fld "udp" "dport") .eq (k 1)),
  expected := .illTyped "protocol udp is not in the chain" }
vector typUnknownField := {
  id := "typ-unknown-field", ast := W (cmp (fld "ipv4" "foo") .eq (k 1)), expected := .illTyped "unknown field ipv4.foo" }
vector typFit := {
  id := "typ-literal-fit", ast := W (cmp ttl .eq (k 300)), expected := .illTyped "literal 300 does not fit Int<8>" }
vector typFitArith := {
  id := "typ-literal-fit-arith", ast := W (cmp (.bin .add ttl (k 256)) .eq (k 0)),
  expected := .illTyped "literal 256 does not fit Int<8>", note := "D-009: the constant takes its sibling's width" }
vector typWidthIPv6 := {
  id := "typ-ipv6-literal-width", ast := W (.litCmp (ff "ipv4" "src") .eq (.ipv6 1)),
  expected := .illTyped "ipv6 literal requires an Int<128> field" }
vector typCIDRWidth := {
  id := "typ-cidr-width", ast := W (.litCmp (ff "tcp" "dport") .eq (.cidr4 0 8)),
  expected := .illTyped "cidr literal requires an Int<32> field" }
vector typPredIdent := {
  id := "typ-pred-ident", ast := tcpPred (.cmp (f "flags") .eq (.ident "SYN")),
  expected := .illTyped "unsupported: identifier literal SYN" }
vector typInSet := {
  id := "typ-pred-inset", ast := tcpPred (.inSet (f "dport") "ports"), expected := .illTyped "unsupported: in @set", goStatus := .notImplemented }
vector typAny := {
  id := "typ-any-unsupported", ast := W (.any (cmp dport .eq (k 1))), expected := .illTyped "unsupported: aux stacks (Phase 5)" }
vector typExists := {
  id := "typ-exists-unsupported", ast := W (.fieldExists (ff "tcp" "options")), expected := .illTyped "unsupported: aux exists (Phase 5)" }
vector typAuxPath := {
  id := "typ-aux-path-unsupported", ast := W (cmp (.field ⟨[("tcp", none), ("options", none), ("mss", none)]⟩) .eq (k 1)),
  expected := .illTyped "unsupported: field path tcp.options.mss (aux, index, or slice)" }
vector typArith128 := {
  id := "typ-arith-128",
  ast := { layers := [P "eth", P "ipv6", P "tcp"], cond := some (cmp (.bin .add (fld "ipv6" "src") (k 1)) .eq (k 1)) },
  packet := ipv6TCP, expected := .illTyped "unsupported: arithmetic on fields wider than 64 bits",
  goStatus := .mismatch, note := "Go compiles 128-bit arithmetic; not modelled here" }

def whereVectors : List Vector := [
  whereCmpOps, whereLitIPv4, whereCIDRIn, whereCIDRNe, whereCIDR0, whereMAC, whereIPv6CIDR, whereIPv6Eq,
  whereNegLitMiss, whereNegLitHit, whereConstFold,
  whereArithOps, whereBitwise, whereShiftMasked, whereNoWrap, whereDivZero, whereModZero, whereMixedWidth,
  whereTrue, whereFalse, whereDecay, whereNot, whereOr, whereBoolEqIff, whereBoolEqXor,
  whereAbsentFalse, whereAbsentNot, whereOptPresent, wherePastQuantified, whereLabels, whereAmbiguous,
  actionEntry, actionHit, actionMiss, actionUnknown,
  predCmp, predCmpMiss, predInList, predInListMiss, predInRange, predNegative, predIPv4,
  capAll, capWhereFalse, capWhereTrue, capLabel, capAbsent,
  typUnknownProto, typNoDispatch, typNotInChain, typUnknownField, typFit, typFitArith, typWidthIPv6, typCIDRWidth,
  typPredIdent, typInSet, typAny, typExists, typAuxPath, typArith128]

end Kunai
