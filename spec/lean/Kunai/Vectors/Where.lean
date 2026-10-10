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
  expected := .reject, note := "D-003 (a): atom on an absent layer is false (Go: the layer's entry slot holds the absent sentinel)" }
vector whereAbsentNot := {
  id := "where-absent-layer-not", ast := vlanOptTci (.not (cmp (fld "vlan" "tci") .eq (k 1))),
  expected := .accept [], note := "D-003 (a): not(false)" }
vector whereAbsentNe := {
  id := "where-absent-layer-ne", ast := vlanOptTci (cmp (fld "vlan" "tci") .ne (k 1)),
  expected := .reject, note := "D-003: != on an absent layer is false too; `not (==)` is the \"absent or different\" form" }
vector whereOptPresent := {
  id := "where-optional-present", ast := vlanOptTci (cmp (fld "vlan" "tci") .eq (k 100)),
  packet := vlanPkt, expected := .accept [] }
vector whereAfterOptional := {
  id := "where-after-optional", ast := vlanOptTci (cmp ttl .eq (k 64)), packet := vlanPkt, expected := .accept [],
  note := "a mandatory layer after `?` is always present; only its offset is runtime" }
vector whereAfterOptionalAbsent := {
  id := "where-after-optional-absent", ast := vlanOptTci (cmp ttl .eq (k 64)), expected := .accept [] }
def mplsLabelled : List Layer :=
  [P "eth", .proto { name := "mpls", label := some "m", quant := .range 1 (some 3) }, P "ipv4", P "tcp"]
vector whereLabelRepeatedLast := {
  id := "where-label-repeated-last", ast := { layers := mplsLabelled, cond := some (cmp (fld "m" "label") .eq (k 7)) },
  packet := mpls3, expected := .accept [], note := "D-018: a label on a repeated layer binds the last matched instance (labels 5, 6, 7)" }
vector whereLabelRepeatedFirstMiss := {
  id := "where-label-repeated-first-miss", ast := { layers := mplsLabelled, cond := some (cmp (fld "m" "label") .eq (k 5)) },
  packet := mpls3, expected := .reject, note := "D-018: the first instance is not what the label names" }
vector whereRepeatedUnlabelled := {
  id := "where-repeated-unlabelled", ast := { layers := mplsRange 1 (some 3), cond := some (cmp (fld "mpls" "label") .eq (k 7)) },
  packet := mpls3, expected := .illTyped "protocol mpls is ambiguous; qualify with an @label", note := "D-013: a quantifier whose upper bound is not 1 counts as several instances" }
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
  note := "D-011: lo ≤ n ≤ hi" }
vector typPredInRangeWide := {
  id := "typ-pred-in-range-wide", ast := tcpPred (.inList (f "dport") [.range 0 70000]),
  expected := .illTyped "range 0..70000 exceeds bit<16> (tcp.dport)", note := "T-PredIn: both bounds must fit the field" }
vector typPredCmpRange := {
  id := "typ-pred-cmp-range", ast := tcpPred (.cmp (f "dport") .eq (.range 79 81)),
  expected := .illTyped "range literal is only valid in `in [...]` (tcp.dport)",
  note := "a range is an `in` alternative, not a comparison operand" }
vector predInRangeMiss := {
  id := "pred-in-range-miss", ast := tcpPred (.inList (f "dport") [.int 443, .range 8000 8080]), expected := .reject,
  note := "D-011: 80 is neither 443 nor in 8000..8080" }
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
  expected := .accept [], note := "D-020: the clause is dropped; Go captures its compile-time upper bound (18 bytes) instead, the verdict agrees" }
vector capPresent := {
  id := "cap-present-layer",
  ast := { layers := vlanOpt, captures := [{ spec := .toLayer "vlan" 0 }] }, packet := vlanPkt,
  expected := .accept [(14, 18)] }
def capAltL3 (target : String) : Filter :=
  { layers := [P "eth", .alt [{ name := "ipv4", label := some "a" }, { name := "ipv6" }], P "tcp"],
    captures := [{ spec := .toLayer target 0 }] }
vector capAltMemberPresent := {
  id := "cap-alt-member-present", ast := capAltL3 "a", expected := .accept [(14, 34)],
  note := "a label on an alternation member names that member's instance" }
vector capAltMemberAbsent := {
  id := "cap-alt-member-absent", ast := capAltL3 "a", packet := ipv6TCP, expected := .accept [],
  note := "D-020: ipv6 matched, so a is absent and the clause is dropped; Go captures the member's compile-time upper bound (34 bytes), the verdict agrees" }
vector capAltMemberByName := {
  id := "cap-alt-member-by-name", ast := capAltL3 "ipv6", packet := ipv6TCP, expected := .accept [(14, 54)] }

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
vector typLabelCollides := {
  id := "typ-label-collides", ast := { layers := [P "eth", P "ipv4", .proto { name := "tcp", label := some "ipv4" }] },
  expected := .illTyped "label ipv4 collides with protocol name",
  note := "a label never shadows a protocol name" }
vector typLabelCollidesAlt := {
  id := "typ-label-collides-alt",
  ast := { layers := [P "eth", P "ipv4", .alt [{ name := "tcp", label := some "ipv4" }, { name := "udp" }]],
           cond := some (cmp (fld "ipv4" "ttl") .eq (k 64)) },
  expected := .illTyped "label ipv4 collides with protocol name",
  note := "on an alternation member the label would be bound at run time and hide the ipv4 layer" }
vector typLabelDuplicate := {
  id := "typ-label-duplicate",
  ast := { layers := [P "eth", .proto { name := "ipv4", label := some "x" }, .proto { name := "tcp", label := some "x" }] },
  expected := .illTyped "duplicate label x" }
vector typFitArith := {
  id := "typ-literal-fit-arith", ast := W (cmp (.bin .add ttl (k 256)) .eq (k 0)),
  expected := .illTyped "literal 256 does not fit Int<8>", note := "D-009: the constant takes its sibling's width" }
vector whereArithRight := {
  id := "where-arith-binop-right", ast := W (cmp dport .eq (.bin .add ttl (k 16))),
  expected := .accept [], note := "a binary node on the right of a comparison: 64 + 16 = 80" }
vector whereArithRightMiss := {
  id := "where-arith-binop-right-miss", ast := W (cmp dport .eq (.bin .add ttl (k 17))), expected := .reject }
vector typFitArithSibling := {
  id := "typ-literal-fit-arith-sibling", ast := W (cmp (.bin .add ttl (k 300)) .eq dport),
  expected := .illTyped "literal 300 does not fit Int<8>",
  note := "D-009: the sibling's width, not the comparison's (Int<16> here)" }
vector whereNegLitSibling := {
  id := "where-negative-literal-sibling", ast := W (cmp (fld "tcp" "seq") .eq (.bin .add dport (k (-1)))),
  packet := eth 0x0800 ++ ipv4 6 ++ tcp 12345 80 (seq := 65615) ++ payload 5, expected := .accept [],
  note := "-1 next to dport is 0xffff: 80 + 65535, not 80 - 1" }
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
  id := "typ-pred-inset-undeclared", ast := tcpPred (.inSet (f "dport") "ports"), expected := .illTyped "undeclared set @ports",
  note := "D-036: a set the host did not declare" }
-- `in @set` (D-036): membership in a host-declared set. Go only checks these
-- at compile time (the lookup is the host's, after the filter).
def ports (members : List Nat) : SetDecl := { name := "ports", width := 16, members }
vector predInSetMember := {
  id := "pred-inset-member", ast := tcpPred (.inSet (f "dport") "ports"), sets := [ports [80, 443]], expected := .accept [],
  note := "dport 80 is a key of @ports" }
vector predInSetMiss := {
  id := "pred-inset-miss", ast := tcpPred (.inSet (f "dport") "ports"), sets := [ports [443]], expected := .reject,
  note := "the host's lookup misses: the verdict is reject" }
vector typPredInSetWidth := {
  id := "typ-pred-inset-width", ast := tcpPred (.inSet (f "dport") "ports"), sets := [{ name := "ports", width := 32, members := [80] }],
  expected := .illTyped "set @ports keys are bit<32>, tcp.dport extracts bit<16>", note := "D-036: key and field widths must match" }
vector predInSetSubByte := {
  id := "pred-inset-subbyte", ast := { layers := [P "eth", .proto { name := "ipv4", preds := [.inSet (f "ihl") "ihls"] }, P "tcp"] },
  sets := [{ name := "ihls", width := 8, members := [5] }], expected := .accept [],
  note := "a 4-bit field is extracted as one byte, so the key is bit<8>" }
vector predInSetWindow := {
  id := "pred-inset-window", ast := { layers := [P "eth", .proto { name := "ipv6", preds := [.inSet (f "traffic_class") "tc"] }, P "tcp"] },
  sets := [{ name := "tc", width := 16, members := [0] }], packet := ipv6TCP, expected := .accept [],
  note := "traffic_class is 8 bits starting at bit 4: the filter loads the 2-byte window, so the key is bit<16>" }
vector typPredInSetWindow := {
  id := "typ-pred-inset-window", ast := { layers := [P "eth", .proto { name := "ipv6", preds := [.inSet (f "traffic_class") "tc"] }, P "tcp"] },
  sets := [{ name := "tc", width := 8, members := [0] }], packet := ipv6TCP,
  expected := .illTyped "set @tc keys are bit<8>, ipv6.traffic_class extracts bit<16>" }
vector typPredInSetTwice := {
  id := "typ-pred-inset-twice",
  ast := { layers := [P "eth", .proto { name := "ipv4", preds := [.inSet (f "src") "hosts", .inSet (f "dst") "hosts"] }, P "tcp"] },
  sets := [{ name := "hosts", width := 32, members := [0x0a000001] }],
  expected := .illTyped "set @hosts is referenced twice: the host holds one key per set",
  note := "D-036: the host keeps one key per set and looks it up once; two references would share the slot" }
vector typPredInSetBudget := {
  id := "typ-pred-inset-budget",
  ast := { layers := [P "eth", .proto { name := "ipv6", preds := [.inSet (f "src") "a", .inSet (f "dst") "b"] }, P "tcp"] },
  sets := [{ name := "a", width := 128, members := [1] }, { name := "b", width := 128, members := [2] }],
  packet := ipv6TCP, expected := .illTyped "packet keys take 32 bytes; the host's key buffer holds 16",
  note := "D-036: the host's packet-key buffer is 16 bytes" }
vector typPredInSetOptional := {
  id := "typ-pred-inset-optional",
  ast := { layers := [P "eth", .proto { name := "vlan", preds := [.inSet (f "tci") "vlans"], quant := .opt }, P "ipv4", P "tcp"] },
  sets := [{ name := "vlans", width := 16, members := [100] }],
  expected := .illTyped "in @vlans on an optional, repeated, or alternative layer: the key is only written when the layer is present" }
vector typPredInSetAlt := {
  id := "typ-pred-inset-alt",
  ast := { layers := [P "eth", .alt [{ name := "ipv4", preds := [.inSet (f "src") "hosts"] }, { name := "ipv6" }], P "tcp"] },
  sets := [{ name := "hosts", width := 32, members := [0x0a000001] }],
  expected := .illTyped "in @hosts on an optional, repeated, or alternative layer: the key is only written when the layer is present" }
vector typAny := {
  id := "typ-any-unsupported", ast := W (.any (cmp dport .eq (k 1))), expected := .illTyped "any/all needs exactly one index-less stack reference" }
vector typExists := {
  id := "typ-exists-unsupported", ast := W (.fieldExists (ff "tcp" "options")), expected := .illTyped "unknown auxiliary header tcp.options" }
vector typAuxPath := {
  id := "typ-aux-path-unsupported", ast := W (cmp (.field ⟨[("tcp", none), ("options", none), ("mss", none)]⟩) .eq (k 1)),
  expected := .illTyped "tcp.options needs an option name and a field" }
-- 128-bit arithmetic (D-035): `+` and `-` modulo 2^128, comparisons at 128 bits,
-- every other operator ill-typed.
def v6pkt (src dst : Nat) : Packet := eth 0x86DD ++ ipv6 6 (src := src) (dst := dst) ++ tcp 12345 80 ++ payload 5
def W6 (w : Where) : Filter := { layers := [P "eth", P "ipv6", P "tcp"], cond := some w }
def src6 : Arith := fld "ipv6" "src"
def dst6 : Arith := fld "ipv6" "dst"
def lowOnes : Nat := 2 ^ 64 - 1
-- A network literal is typed against the field's width after its slice
-- (T-FieldSlice, then T-IPv4Lit / T-IPv6Lit): a 64-bit half is not an
-- Int<128>, the low 32 bits are an Int<32>.
def dst6Half : FieldPath := ⟨[("ipv6", none), ("dst", some (.slice 64 128))]⟩
def dst6Low : FieldPath := ⟨[("ipv6", none), ("dst", some (.slice 96 128))]⟩
def v6Src1 : Nat := 0xfc000000000000000000000000000001
def v6LowTen : Nat := 0xfc00000000000000000000000a000001
vector typWidthIPv6Slice := {
  id := "typ-ipv6-literal-slice-width", ast := W6 (.litCmp dst6Half .eq (.ipv6 2)), packet := ipv6TCP,
  expected := .illTyped "ipv6 literal requires an Int<128> field", note := "the slice makes the field an Int<64>" }
vector typWidthIPv6SliceBracket := {
  id := "typ-ipv6-literal-slice-width-bracket",
  ast := { layers := [P "eth", .proto { name := "ipv6", preds := [.cmp ⟨[("dst", some (.slice 64 128))]⟩ .eq (.ipv6 2)] }, P "tcp"] },
  packet := ipv6TCP, expected := .illTyped "ipv6 literal requires an Int<128> field" }
vector ipv6DstLow32IPv4 := {
  id := "ipv6-dst-low32-ipv4-literal", ast := W6 (.litCmp dst6Low .eq (.ipv4 0x0a000001)), packet := v6pkt v6Src1 v6LowTen,
  expected := .accept [], note := "the low 32 bits of fc00::a00:1 are 10.0.0.1" }
vector ipv6DstLow32IPv4Miss := {
  id := "ipv6-dst-low32-ipv4-literal-miss", ast := W6 (.litCmp dst6Low .eq (.ipv4 0x0a000002)), packet := v6pkt v6Src1 v6LowTen,
  expected := .reject }
vector ipv6DstLow32Cidr := {
  id := "ipv6-dst-low32-cidr-literal", ast := W6 (.litCmp dst6Low .eq (.cidr4 0x0a000000 8)), packet := v6pkt v6Src1 v6LowTen,
  expected := .accept [], note := "a /8 over the sliced word" }
vector ipv6DstLow32IPv4Unaligned := {
  id := "ipv6-dst-unaligned-slice-ipv4-literal", ast := W6 (.litCmp ⟨[("ipv6", none), ("dst", some (.slice 92 124))]⟩ .eq (.ipv4 0x0a000001)),
  packet := v6pkt v6Src1 (0xfc00000000000000000000000a000001 * 16), expected := .accept [], goStatus := .notImplemented,
  note := "well-typed (width 32); Go's literal readers compare whole bytes and refuse a slice that does not end on a byte boundary" }
vector ipv6DstLow32IPv4Ne := {
  id := "ipv6-dst-low32-ipv4-literal-ne", ast := W6 (.litCmp dst6Low .ne (.ipv4 0x0a000002)), packet := v6pkt v6Src1 v6LowTen,
  expected := .accept [] }
vector ipv6DstLow32IPv4NeMiss := {
  id := "ipv6-dst-low32-ipv4-literal-ne-miss", ast := W6 (.litCmp dst6Low .ne (.ipv4 0x0a000001)), packet := v6pkt v6Src1 v6LowTen,
  expected := .reject }
vector ipv6DstLow48Mac := {
  id := "ipv6-dst-low48-mac-literal", ast := W6 (.litCmp ⟨[("ipv6", none), ("dst", some (.slice 80 128))]⟩ .eq (.mac 0x00000a000001)),
  packet := v6pkt v6Src1 v6LowTen, expected := .accept [], note := "the low 48 bits of fc00::a00:1 as a MAC literal (width 48 after the slice)" }
vector ipv6DstFullSliceIPv6 := {
  id := "ipv6-dst-full-slice-ipv6-literal", ast := W6 (.litCmp ⟨[("ipv6", none), ("dst", some (.slice 0 128))]⟩ .eq (.ipv6 v6LowTen)),
  packet := v6pkt v6Src1 v6LowTen, expected := .accept [], note := "a full-width slice is the field" }
vector ipv6DstFullSliceCidr6 := {
  id := "ipv6-dst-full-slice-cidr6-literal", ast := W6 (.litCmp ⟨[("ipv6", none), ("dst", some (.slice 0 128))]⟩ .eq (.cidr6 0xfc000000000000000000000000000000 16)),
  packet := v6pkt v6Src1 v6LowTen, expected := .accept [] }
vector ipv6DstLow32IPv4Bracket := {
  id := "ipv6-dst-low32-ipv4-literal-bracket",
  ast := { layers := [P "eth", .proto { name := "ipv6", preds := [.cmp ⟨[("dst", some (.slice 96 128))]⟩ .eq (.ipv4 0x0a000001)] }, P "tcp"] },
  packet := v6pkt v6Src1 v6LowTen, expected := .accept [] }
vector arith128AddConst := {
  id := "arith-128-add-const", ast := W6 (cmp (.bin .add src6 (k 1)) .eq dst6), packet := ipv6TCP,
  expected := .accept [], note := "fc00::1 + 1 = fc00::2" }
vector arith128SubConst := {
  id := "arith-128-sub-const", ast := W6 (cmp (.bin .sub dst6 (k 1)) .eq src6), packet := ipv6TCP, expected := .accept [] }
vector arith128AddCarry := {
  id := "arith-128-add-carry", ast := W6 (cmp (.bin .add src6 (k 1)) .eq dst6),
  packet := v6pkt (0xfc00 * 2 ^ 112 + lowOnes) (0xfc00 * 2 ^ 112 + 2 ^ 64), expected := .accept [],
  note := "the carry crosses from the low 64-bit half into the high one" }
vector arith128AddWrap := {
  id := "arith-128-add-wrap", ast := W6 (cmp (.bin .add src6 (k 1)) .eq dst6), packet := v6pkt (2 ^ 128 - 1) 0,
  expected := .accept [], note := "D-035: 2^128 - 1 + 1 wraps to 0" }
vector arith128SubBorrow := {
  id := "arith-128-sub-borrow", ast := W6 (cmp (.bin .sub src6 (k 1)) .eq dst6),
  packet := v6pkt (0xfc00 * 2 ^ 112 + 2 ^ 64) (0xfc00 * 2 ^ 112 + lowOnes), expected := .accept [],
  note := "the borrow crosses from the low half into the high one" }
vector arith128SubWrap := {
  id := "arith-128-sub-wrap", ast := W6 (cmp (.bin .sub src6 (k 1)) .eq dst6), packet := v6pkt 0 (2 ^ 128 - 1),
  expected := .accept [], note := "0 - 1 wraps to 2^128 - 1" }
vector arith128AddMiss := {
  id := "arith-128-add-miss", ast := W6 (cmp (.bin .add src6 (k 1)) .eq dst6), packet := v6pkt 1 3, expected := .reject }
vector arith128FieldAddField := {
  id := "arith-128-field-add-field", ast := W6 (cmp (.bin .add src6 dst6) .eq (k 3)), packet := v6pkt 1 2, expected := .accept [] }
vector arith128FieldAddFieldCarry := {
  id := "arith-128-field-add-field-carry", ast := W6 (cmp (.bin .add src6 dst6) .gt src6), packet := v6pkt lowOnes 1,
  expected := .accept [], note := "2^64 - 1 + 1 = 2^64: the carry reaches the high half, so the sum exceeds src" }
vector arith128FieldSubField := {
  id := "arith-128-field-sub-field", ast := W6 (cmp (.bin .sub src6 dst6) .eq (k 2)), packet := v6pkt 3 1, expected := .accept [] }
vector arith128FieldSubFieldBorrow := {
  id := "arith-128-field-sub-field-borrow", ast := W6 (cmp (.bin .sub src6 dst6) .eq (k lowOnes)), packet := v6pkt (2 ^ 64) 1,
  expected := .accept [], note := "2^64 - 1 borrows from the high half" }
vector arith128AddWideConst := {
  id := "arith-128-add-wide-const", ast := W6 (cmp (.bin .add src6 (k (2 ^ 32))) .eq dst6), packet := v6pkt 1 (2 ^ 32 + 1),
  expected := .accept [], note := "a constant above int32 as the addend" }
vector arith128SubWideConstBorrow := {
  id := "arith-128-sub-wide-const-borrow", ast := W6 (cmp (.bin .sub src6 (k (2 ^ 32))) .eq dst6), packet := v6pkt (2 ^ 64) (2 ^ 64 - 2 ^ 32),
  expected := .accept [], note := "a constant above int32 as the subtrahend, with a borrow from the high half" }
vector arith128AddNegConst := {
  id := "arith-128-add-neg-const", ast := W6 (cmp (.bin .add src6 (k (-1))) .eq dst6),
  packet := v6pkt 0xfc000000000000000000000000000002 0xfc000000000000000000000000000001, expected := .accept [],
  note := "-1 narrows to 2^128 - 1 (§7.3), so src + -1 is src - 1" }
vector arith128SubNegConst := {
  id := "arith-128-sub-neg-const", ast := W6 (cmp (.bin .sub src6 (k (-1))) .eq dst6), packet := ipv6TCP,
  expected := .accept [], note := "src - -1 is src + 1" }
vector arith128CmpNegConst := {
  id := "arith-128-cmp-neg-const", ast := W6 (cmp src6 .eq (k (-1))), packet := v6pkt (2 ^ 128 - 1) 0,
  expected := .accept [], note := "a negative literal compared at 128 bits is all ones in both halves" }
vector arith128MixedWidthAdd := {
  id := "arith-128-mixed-width-add", ast := W6 (cmp (.bin .add src6 (fld "tcp" "dport")) .eq (k 80)), packet := v6pkt 0 0,
  expected := .accept [],
  note := "Int<128> + Int<16> widens to 128 bits (§5.2): the narrower field joins zero-extended" }
vector arith128MixedWidthMul := {
  id := "arith-128-mixed-width-mul", ast := W6 (cmp src6 .eq (.bin .mul (fld "tcp" "dport") (k 2))), packet := v6pkt 160 0,
  expected := .accept [],
  note := "the * node is 16 bits wide and computes in 64 bits; only the comparison is 128 bits wide" }
def dport6 : Arith := fld "tcp" "dport"
vector arith128MixedCarry := {
  id := "arith-128-mixed-width-carry", ast := W6 (cmp (.bin .add src6 dport6) .eq dst6),
  packet := v6pkt lowOnes (2 ^ 64 + 79), expected := .accept [],
  note := "2^64 - 1 + 80: the narrow addend carries into the high half" }
vector arith128MixedBorrow := {
  id := "arith-128-mixed-width-borrow", ast := W6 (cmp (.bin .sub src6 dport6) .eq dst6),
  packet := v6pkt (2 ^ 64) (2 ^ 64 - 80), expected := .accept [] }
vector arith128MixedWrap64 := {
  id := "arith-128-mixed-width-wrap64", ast := W6 (cmp src6 .eq (.bin .sub dport6 (k 100))),
  packet := v6pkt (2 ^ 64 - 20) 0, expected := .accept [],
  note := "80 - 100 wraps at 64 bits (D-015), and that value is what the 128-bit comparison sees" }
vector arith128MixedSlice := {
  id := "arith-128-mixed-width-slice",
  ast := W6 (cmp (.bin .add (.field ⟨[("ipv6", none), ("src", some (.slice 64 128))]⟩) dst6) .eq src6),
  packet := v6pkt (2 ^ 64 + 5) (2 ^ 64), expected := .accept [],
  note := "a 64-bit slice next to the full field" }
vector arith128MixedNested := {
  id := "arith-128-mixed-width-nested", ast := W6 (cmp (.bin .add src6 (.bin .mul dport6 (k 2))) .eq dst6),
  packet := v6pkt 1 161, expected := .accept [], note := "a sub-64-bit expression on the right of +" }
vector arith128MixedNeg := {
  id := "arith-128-mixed-width-neg", ast := W6 (cmp src6 .eq (.bin .add dport6 (k (-1)))),
  packet := v6pkt 65615 0, expected := .accept [],
  note := "-1 next to an Int<16> field is 0xffff (§7.3): 80 + 65535" }
vector arith128ConstBinop := {
  id := "arith-128-const-binop", ast := W6 (cmp src6 .eq (.bin .mul (k 2) (k 3))), packet := v6pkt 6 0,
  expected := .accept [], note := "a node of literals only computes in 64 bits (D-009)" }
vector arith128MixedAux := {
  id := "arith-128-mixed-width-aux",
  ast := { layers := [P "eth", P "ipv6", P "tcp"],
           cond := some (cmp (.bin .add src6 (.field ⟨[("ipv6", none), ("exts", some (.nat 0)), ("next_header", none)]⟩)) .eq (.bin .add dst6 (k 5))) },
  packet := eth 0x86DD ++ ipv6 0 ++ [6, 0, 0, 0, 0, 0, 0, 0] ++ tcp 12345 80 ++ payload 5, expected := .accept [],
  note := "an 8-bit extension header field next to the address: fc00::1 + 6 = fc00::2 + 5" }
vector typArith128NarrowFitNested := {
  id := "typ-arith-128-narrow-fit-nested",
  ast := W6 (cmp src6 .eq (.bin .add (.bin .mul dport6 (k 70000)) (fld "tcp" "seq"))), packet := ipv6TCP,
  expected := .illTyped "literal 70000 does not fit Int<16>" }
vector arith128WideRight := {
  id := "arith-128-wide-right", ast := W6 (cmp (.bin .add src6 (.bin .add dst6 (k 1))) .eq (k 4)),
  packet := v6pkt 1 2, expected := .accept [],
  note := "a 128-bit expression on the right of +: 1 + (2 + 1)" }
vector arith128WideRightSub := {
  id := "arith-128-wide-right-sub", ast := W6 (cmp (.bin .sub src6 (.bin .sub dst6 src6)) .eq (k 7)),
  packet := v6pkt 5 3, expected := .accept [],
  note := "5 - (3 - 5): the inner difference wraps to 2^128 - 2, the outer one back to 7" }
vector arith128WideRightDeep := {
  id := "arith-128-wide-right-deep",
  ast := W6 (cmp (.bin .add src6 (.bin .add dst6 (.bin .add src6 (fld "tcp" "dport")))) .eq (k 84)),
  packet := v6pkt 1 2, expected := .accept [], note := "1 + (2 + (1 + 80))" }
vector arith128WideRightConstLeft := {
  id := "arith-128-wide-right-const-left",
  ast := W6 (cmp (.bin .sub (.bin .add src6 (k 10)) (.bin .add dst6 src6)) .eq (k 4)),
  packet := v6pkt 5 6, expected := .accept [], note := "(5 + 10) - (6 + 5): the left side is itself an expression" }
vector arith128WideRightBorrow := {
  id := "arith-128-wide-right-borrow", ast := W6 (cmp (.bin .sub (k 1) (.bin .add src6 dst6)) .eq (k (-2))),
  packet := v6pkt 1 2, expected := .accept [], note := "1 - (1 + 2) borrows through the high half: 2^128 - 2" }
vector arith128WideRightNarrowLeft := {
  id := "arith-128-wide-right-narrow-left",
  ast := W6 (cmp (.bin .sub (fld "tcp" "dport") (.bin .add src6 dst6)) .eq (k 77)),
  packet := v6pkt 1 2, expected := .accept [], note := "80 - (1 + 2), a 16-bit left operand" }
vector arith128WideRightNarrowLeftRej := {
  id := "arith-128-wide-right-narrow-left-rej",
  ast := W6 (cmp (.bin .sub src6 (.bin .sub (fld "tcp" "dport") (.bin .add src6 dst6))) .eq (k 76)),
  packet := v6pkt 1 2, expected := .reject, note := "1 - (80 - (1 + 2)) wraps below zero to 2^128 - 76, not 76" }
vector arith128WideBoth := {
  id := "arith-128-wide-both", ast := W6 (cmp (.bin .sub (.bin .add src6 dst6) (.bin .add dst6 src6)) .eq (k 0)),
  packet := v6pkt 1 2, expected := .accept [], note := "(1 + 2) - (2 + 1)" }
vector arith128WideBothBorrow := {
  id := "arith-128-wide-both-borrow",
  ast := W6 (cmp (.bin .sub (.bin .add src6 (k 1)) (.bin .add dst6 dst6)) .eq (k (-2))),
  packet := v6pkt 1 2, expected := .accept [], note := "(1 + 1) - (2 + 2) borrows through the high half: 2^128 - 2" }
vector arith128WideBothNested := {
  id := "arith-128-wide-both-nested",
  ast := W6 (cmp (.bin .add (.bin .sub (.bin .add src6 dst6) (.bin .add dst6 (k 1)))
                            (.bin .add (.bin .add src6 dst6) (.bin .sub dst6 src6))) .eq (k 4)),
  packet := v6pkt 1 2, expected := .accept [], note := "((1 + 2) - (2 + 1)) + ((1 + 2) + (2 - 1)): two holds deep" }
vector arith128WideBothNarrow := {
  id := "arith-128-wide-both-narrow",
  ast := W6 (cmp (.bin .sub (.bin .add src6 dst6) (.bin .add src6 (.bin .mul (fld "tcp" "dport") (k 2)))) .eq (k (-158))),
  packet := v6pkt 1 2, expected := .accept [], note := "(1 + 2) - (1 + 80 * 2): a sub-64-bit expression under the held left side" }
vector arith128WideBothRej := {
  id := "arith-128-wide-both-rej", ast := W6 (cmp (.bin .sub (.bin .add src6 dst6) (.bin .add dst6 src6)) .eq (k 1)),
  packet := v6pkt 1 2, expected := .reject }
/-- `S - (S - (… S))` with `n` both-sides nodes, `S = src + dst`. -/
def bothParkChain : Nat → Arith
  | 0 => .bin .add src6 dst6
  | n + 1 => .bin .sub (.bin .add src6 dst6) (bothParkChain n)
/-- `dport + (dport + (… dport))` nested `n` levels. -/
def narrowChain : Nat → Arith
  | 0 => dport6
  | n + 1 => .bin .add dport6 (narrowChain n)
def dport6Is80 : Where := cmp dport6 .eq (k 80)
vector arith128BoolEqBothPark := {
  id := "arith-128-booleq-both-park",
  ast := W6 (.boolEq (.boolEq (cmp (bothParkChain 4) .eq (k 3)) .eq dport6Is80) .eq dport6Is80),
  packet := v6pkt 1 2, expected := .accept [],
  note := "four both-sides nodes inside two `==`, the deepest Go compiles: the hold slots stay below the parked truth values" }
vector arith128BoolEqBothParkRej := {
  id := "arith-128-booleq-both-park-rej",
  ast := W6 (.boolEq (.boolEq (cmp (bothParkChain 4) .eq (k 0)) .eq dport6Is80) .eq dport6Is80),
  packet := v6pkt 1 2, expected := .reject, note := "the chain is 3, so the innermost atom is false" }
vector arith128BoolEqNarrow := {
  id := "arith-128-booleq-narrow",
  ast := W6 (.boolEq (cmp src6 .eq (narrowChain 10)) .eq dport6Is80),
  packet := v6pkt 880 2, expected := .accept [],
  note := "a sub-64-bit expression nested ten levels inside `==`, the deepest Go compiles: 11 × 80" }
vector arith128BoolEqNarrowRej := {
  id := "arith-128-booleq-narrow-rej",
  ast := W6 (.boolEq (cmp src6 .eq (narrowChain 10)) .eq dport6Is80),
  packet := v6pkt 881 2, expected := .reject }
def dport6Is81 : Where := cmp dport6 .eq (k 81)
/-- `b == (b == … (b == atom))` with `d` bool-eqs: the atom on the right, so
it runs while the truth values of the left operands are parked. -/
def boolEqRight (b : Where) : Nat → Where → Where
  | 0, a => a
  | d + 1, a => .boolEq b .eq (boolEqRight b d a)
vector arith128BoolEqRightBoth5 := {
  id := "arith-128-booleq-right-both5",
  ast := W6 (boolEqRight dport6Is80 1 (cmp (bothParkChain 5) .eq (k 0))),
  packet := v6pkt 1 2, expected := .accept [],
  note := "five both-sides nodes on the right of one `==`, the deepest Go compiles: the holds run with the left truth value parked" }
vector arith128BoolEqRightBoth5False := {
  id := "arith-128-booleq-right-both5-false",
  ast := W6 (boolEqRight dport6Is81 1 (cmp (bothParkChain 5) .eq (k 0))),
  packet := v6pkt 1 2, expected := .reject, note := "a parked false next to a true atom" }
vector arith128BoolEqRightBoth5BothFalse := {
  id := "arith-128-booleq-right-both5-both-false",
  ast := W6 (boolEqRight dport6Is81 1 (cmp (bothParkChain 5) .eq (k 3))),
  packet := v6pkt 1 2, expected := .accept [] }
vector arith128BoolEqRightBoth4Deep := {
  id := "arith-128-booleq-right-both4-deep",
  ast := W6 (boolEqRight dport6Is80 3 (cmp (bothParkChain 4) .eq (k 3))),
  packet := v6pkt 1 2, expected := .accept [], note := "four both-sides nodes under three parked truth values" }
vector arith128BoolEqRightBoth4DeepFalse := {
  id := "arith-128-booleq-right-both4-deep-false",
  ast := W6 (boolEqRight dport6Is81 3 (cmp (bothParkChain 4) .eq (k 3))),
  packet := v6pkt 1 2, expected := .reject, note := "false == (false == (false == true))" }
vector arith128BoolEqRightBoth4DeepBothFalse := {
  id := "arith-128-booleq-right-both4-deep-both-false",
  ast := W6 (boolEqRight dport6Is81 3 (cmp (bothParkChain 4) .eq (k 0))),
  packet := v6pkt 1 2, expected := .accept [], note := "false == (false == (false == false))" }
vector arith128BoolEqRightNarrow := {
  id := "arith-128-booleq-right-narrow",
  ast := W6 (boolEqRight dport6Is80 1 (cmp src6 .eq (narrowChain 10))),
  packet := v6pkt 880 2, expected := .accept [] }
vector arith128BoolEqRightNarrowFalse := {
  id := "arith-128-booleq-right-narrow-false",
  ast := W6 (boolEqRight dport6Is81 1 (cmp src6 .eq (narrowChain 10))),
  packet := v6pkt 880 2, expected := .reject }
vector arith128BoolEqRightNarrowBothFalse := {
  id := "arith-128-booleq-right-narrow-both-false",
  ast := W6 (boolEqRight dport6Is81 1 (cmp src6 .eq (narrowChain 10))),
  packet := v6pkt 881 2, expected := .accept [] }
/-- `dport + (dport + (… dport))` nested `n` levels on the IPv4 chain. -/
def dportChain : Nat → Arith
  | 0 => dport
  | n + 1 => .bin .add dport (dportChain n)
vector arithDepth16Left := {
  id := "arith-depth-16-left", ast := W (cmp (dportChain 16) .eq (k 1360)), expected := .accept [],
  note := "sixteen nested binary nodes, the deepest Go compiles: 17 × 80" }
vector arithDepth16Right := {
  id := "arith-depth-16-right", ast := W (cmp (k 1360) .eq (dportChain 16)), expected := .accept [],
  note := "the deeper side is computed first, so the shallow left side parks in a free slot" }
vector arithDepth16RightRej := {
  id := "arith-depth-16-right-rej", ast := W (cmp (k 1361) .eq (dportChain 16)), expected := .reject }
vector arithDepthBothDeep := {
  id := "arith-depth-both-deep", ast := W (cmp (dportChain 15) .lt (dportChain 16)), expected := .accept [],
  note := "16 × 80 < 17 × 80: the 15-deep side goes second and leaves slot 15 for the parked 16-deep side; the operator order is kept" }
vector arithDepthBothDeepRej := {
  id := "arith-depth-both-deep-rej", ast := W (cmp (dportChain 16) .lt (dportChain 15)), expected := .reject }
vector arithDepth15InBoolEq := {
  id := "arith-depth-15-booleq", ast := W (.boolEq (cmp dport .eq (k 80)) .eq (cmp (dportChain 15) .eq (k 1280))),
  expected := .accept [], note := "fifteen nodes on the right of `==`, under the parked truth value" }
def wide (n : Nat) : Arith := .wide n
vector arith128WideLit := {
  id := "arith-128-wide-lit", ast := W6 (cmp (.bin .add src6 (wide (2 ^ 64))) .eq dst6),
  packet := v6pkt 1 (2 ^ 64 + 1), expected := .accept [], note := "int<128>(2^64): a literal above 64 bits" }
vector arith128WideLitHigh := {
  id := "arith-128-wide-lit-high", ast := W6 (cmp src6 .eq (wide (2 ^ 127 + 5))),
  packet := v6pkt (2 ^ 127 + 5) 2, expected := .accept [] }
vector arith128WideLitHighRej := {
  id := "arith-128-wide-lit-high-rej", ast := W6 (cmp src6 .eq (wide (2 ^ 127 + 5))),
  packet := v6pkt 5 2, expected := .reject, note := "the low halves agree, the high halves do not" }
vector arith128WideLitSmall := {
  id := "arith-128-wide-lit-small", ast := W6 (cmp (.bin .add src6 (wide 1)) .eq dst6),
  packet := v6pkt 1 2, expected := .accept [], note := "a small value inside int<128>(…) is the same as the plain literal next to Int<128>" }
vector arith128WideLitNarrow := {
  id := "arith-128-wide-lit-narrow", ast := W6 (cmp (.bin .sub dport6 (wide 100)) .eq (k (-20))),
  packet := v6pkt 1 2, expected := .accept [],
  note := "int<128>(…) makes the node 128 bits wide: 80 - 100 wraps to 2^128 - 20, which -20 also is at that width" }
vector arith128WideLitNarrowRej := {
  id := "arith-128-wide-lit-narrow-rej", ast := W6 (cmp (.bin .sub dport6 (wide 100)) .eq (k (2 ^ 64 - 20))),
  packet := v6pkt 1 2, expected := .reject, note := "not the 64-bit wrap" }
vector arith128WideLitLeft := {
  id := "arith-128-wide-lit-left", ast := W6 (cmp (.bin .sub (wide (2 ^ 64 + 3)) src6) .eq dst6),
  packet := v6pkt 1 (2 ^ 64 + 2), expected := .accept [], note := "int<128>(…) on the left of -, borrowing from the high half" }
vector arith128WideLitCmpLeft := {
  id := "arith-128-wide-lit-cmp-left", ast := W6 (cmp (wide (2 ^ 127)) .eq src6),
  packet := v6pkt (2 ^ 127) 2, expected := .accept [] }
vector arith128WideLitRightNested := {
  id := "arith-128-wide-lit-right-nested", ast := W6 (cmp (.bin .add src6 (.bin .add dst6 (wide (2 ^ 64)))) .eq (wide (2 ^ 64 + 3))),
  packet := v6pkt 1 2, expected := .accept [], note := "a high constant inside the right operand: the right side parks first" }
vector arith128WideLitRightNestedSub := {
  id := "arith-128-wide-lit-right-nested-sub", ast := W6 (cmp (.bin .sub src6 (.bin .add dst6 (wide (2 ^ 64)))) .eq (wide (2 ^ 128 - 2 ^ 64 + 3))),
  packet := v6pkt 5 2, expected := .accept [], note := "5 - (2 + 2^64) wraps below zero" }
vector arith128WideLitSubHigh := {
  id := "arith-128-wide-lit-sub-high", ast := W6 (cmp (.bin .sub src6 (wide (2 ^ 64))) .eq (wide (2 ^ 128 - 2 ^ 64 + 1))),
  packet := v6pkt 1 2, expected := .accept [], note := "a high constant on the right of -" }
vector arith128WideLitNarrowFit := {
  id := "arith-128-wide-lit-narrow-fit", ast := W6 (cmp (.bin .add dport6 (wide 70000)) .eq (wide 70080)),
  packet := v6pkt 1 2, expected := .accept [], note := "int<128>(70000) next to a 16-bit field is not fit-checked against 16 bits" }
vector typArith128WideMod := {
  id := "typ-arith-128-wide-mod", ast := W6 (cmp (.bin .mod dport6 (wide (2 ^ 64))) .eq (k 80)), packet := ipv6TCP,
  expected := .illTyped "unsupported: only + and - are defined on fields wider than 64 bits",
  note := "a divisor of 2^64 is not zero" }
vector typArith128PlainTooNegative := {
  id := "typ-arith-128-plain-too-negative", ast := W6 (cmp src6 .eq (k (-(2 ^ 63) - 1))), packet := ipv6TCP,
  expected := .illTyped "literal -9223372036854775809 is below -2^63" }
vector typArith128WideTooWide := {
  id := "typ-arith-128-wide-too-wide", ast := W6 (cmp src6 .eq (wide (2 ^ 128))), packet := ipv6TCP,
  expected := .illTyped "int<128>(340282366920938463463374607431768211456) does not fit Int<128>" }
vector typArith128WideMul := {
  id := "typ-arith-128-wide-mul", ast := W6 (cmp (.bin .mul dport6 (wide 2)) .eq (k 160)), packet := ipv6TCP,
  expected := .illTyped "unsupported: only + and - are defined on fields wider than 64 bits" }
vector typArith128PlainTooWide := {
  id := "typ-arith-128-plain-too-wide", ast := W6 (cmp src6 .eq (k (2 ^ 64))), packet := ipv6TCP,
  expected := .illTyped "literal 18446744073709551616 exceeds 64 bits; write int<128>(18446744073709551616) for a wider value",
  note := "a plain literal is at most 64 bits (§11.2)" }
vector typArith128NarrowFit := {
  id := "typ-arith-128-narrow-fit", ast := W6 (cmp src6 .eq (.bin .mul dport6 (k 70000))), packet := ipv6TCP,
  expected := .illTyped "literal 70000 does not fit Int<16>",
  note := "a literal fits the width of the node it sits in, not the comparison's" }
vector arith128CmpWideConst := {
  id := "arith-128-cmp-wide-const", ast := W6 (cmp (.bin .add src6 dst6) .eq (k (2 ^ 32))), packet := v6pkt (2 ^ 32 - 1) 1,
  expected := .accept [], note := "a constant above int32 on the comparison side" }
vector arith128Lt := {
  id := "arith-128-lt", ast := W6 (cmp src6 .lt dst6), packet := ipv6TCP, expected := .accept [] }
vector arith128GeMiss := {
  id := "arith-128-ge-miss", ast := W6 (cmp src6 .ge dst6), packet := ipv6TCP, expected := .reject }
vector arith128LtHighHalf := {
  id := "arith-128-lt-high-half", ast := W6 (cmp src6 .lt dst6), packet := v6pkt lowOnes (2 ^ 64),
  expected := .accept [], note := "the high half decides before the low half" }
vector typPathDeep := {
  id := "typ-path-unsupported-deep",
  ast := W (cmp (.field ⟨[("tcp", none), ("a", none), ("b", none), ("c", none), ("d", none), ("e", none)]⟩) .eq (k 1)),
  expected := .illTyped "unsupported: field path tcp.a.b.c.d.e",
  note := "the message names the protocol the path resolved under" }
vector typPathDeepLabel := {
  id := "typ-path-unsupported-deep-label",
  ast := { layers := [P "eth", P "ipv4", .proto { name := "tcp", label := some "t" }],
           cond := some (cmp (.field ⟨[("t", none), ("a", none), ("b", none), ("c", none), ("d", none), ("e", none)]⟩) .eq (k 1)) },
  expected := .illTyped "unsupported: field path tcp.a.b.c.d.e",
  note := "a label head is reported as its protocol" }
vector typPathDeepBracket := {
  id := "typ-path-unsupported-deep-bracket",
  ast := tcpPred (.cmp ⟨[("a", none), ("b", none), ("c", none), ("d", none), ("e", none)]⟩ .eq (.int 1)),
  expected := .illTyped "unsupported: field path tcp.a.b.c.d.e",
  note := "a bracket path is reported under its layer's protocol" }
vector typArith128Mul := {
  id := "typ-arith-128-mul", ast := W6 (cmp (.bin .mul src6 (k 2)) .eq dst6), packet := ipv6TCP,
  expected := .illTyped "unsupported: only + and - are defined on fields wider than 64 bits",
  note := "D-035: Go dropped * on Int<128> (F5); the spec makes it ill-typed" }
vector typArith128Band := {
  id := "typ-arith-128-band", ast := W6 (cmp (.bin .band src6 (k 1)) .eq (k 1)), packet := ipv6TCP,
  expected := .illTyped "unsupported: only + and - are defined on fields wider than 64 bits",
  note := "D-035: bitwise operators too; a CIDR literal covers prefix tests" }

-- Alternation members in `where` (D-023 label note) --------------------------

def qinqPkt (tci : Nat := 100) : Packet := eth 0x88a8 ++ vlan tci 0x0800 ++ ipv4 6 ++ tcp 12345 80 ++ payload 5
def tagAlt (label : Option String) (w : Where) : Filter :=
  { layers := [P "eth", .alt [{ name := "vlan", label }, { name := "qinq" }], P "ipv4", P "tcp"], cond := some w }
def l4Alt (w : Where) : Filter :=
  { layers := [P "eth", P "ipv4", .alt [{ name := "tcp", label := some "x" }, { name := "udp" }]], cond := some w }

vector whereAltLabelHit := {
  id := "where-alt-label-hit", ast := tagAlt (some "v") (cmp (fld "v" "tci") .eq (k 100)), packet := vlanPkt,
  expected := .accept [], note := "a label on an alternation member names that member" }
vector whereAltLabelOther := {
  id := "where-alt-label-other-member", ast := tagAlt (some "v") (cmp (fld "v" "tci") .eq (k 100)), packet := qinqPkt,
  expected := .reject, note := "qinq matched, so v is absent and its atom false (D-003), whatever qinq's tci is" }
vector whereAltLabelOtherNot := {
  id := "where-alt-label-other-member-not", ast := tagAlt (some "v") (.not (cmp (fld "v" "tci") .eq (k 100))),
  packet := qinqPkt, expected := .accept [] }
vector whereAltNameHit := {
  id := "where-alt-name-hit", ast := tagAlt none (cmp (fld "vlan" "tci") .eq (k 100)), packet := vlanPkt,
  expected := .accept [] }
vector whereAltNameOther := {
  id := "where-alt-name-other-member", ast := tagAlt none (cmp (fld "vlan" "tci") .eq (k 100)), packet := qinqPkt,
  expected := .reject, note := "the protocol name of a member that did not match is absent too" }
vector whereAltNameOtherNot := {
  id := "where-alt-name-other-member-not", ast := tagAlt none (.not (cmp (fld "vlan" "tci") .eq (k 100))),
  packet := qinqPkt, expected := .accept [] }
def udpPkt : Packet := eth 0x0800 ++ ipv4 17 ++ udp 12345 80 ++ payload 5
def l3Alt (pre : List Layer) (w : Where) : Filter :=
  { layers := pre ++ [.alt [{ name := "ipv4" }, { name := "ipv6" }], P "tcp"], cond := some w }

vector whereAltLabelHet := {
  id := "where-alt-label-het", ast := l4Alt (cmp (fld "x" "dport") .eq (k 80)),
  expected := .accept [], note := "members of different sizes" }
vector whereAltLabelHetOther := {
  id := "where-alt-label-het-other-member", ast := l4Alt (cmp (fld "x" "dport") .eq (k 80)), packet := udpPkt,
  expected := .reject, note := "udp matched; its dport is 80 at the same offset, but x is absent" }
vector whereAltLabelHetOtherNot := {
  id := "where-alt-label-het-other-member-not", ast := l4Alt (.not (cmp (fld "x" "dport") .eq (k 80))),
  packet := udpPkt, expected := .accept [] }
vector whereAltL3Hit := {
  id := "where-alt-l3-hit", ast := l3Alt [P "eth"] (.and (cmp ttl .eq (k 64)) (cmp dport .eq (k 80))),
  expected := .accept [], note := "a member of a variable-size alternation, and a layer after it" }
vector whereAltL3Other := {
  id := "where-alt-l3-other-member", ast := l3Alt [P "eth"] (cmp ttl .eq (k 64)), packet := ipv6TCP,
  expected := .reject }
vector whereAltL3OtherOr := {
  id := "where-alt-l3-other-member-or", packet := ipv6TCP,
  ast := l3Alt [P "eth"] (.or (cmp ttl .eq (k 64)) (cmp (fld "ipv6" "hop_limit") .gt (k 0))),
  expected := .accept [], note := "one atom per member: the absent one is false, the present one decides" }
vector whereAltL3AfterOpt := {
  id := "where-alt-l3-after-optional", ast := l3Alt [P "eth", Pq "vlan" .opt] (cmp ttl .eq (k 64)), packet := vlanPkt,
  expected := .accept [], note := "the member's start is a runtime offset" }
vector whereAltL3AfterOptOther := {
  id := "where-alt-l3-after-optional-other-member", ast := l3Alt [P "eth", Pq "vlan" .opt] (cmp ttl .eq (k 64)),
  packet := ipv6TCP, expected := .reject }

vector whereAltNameAmbiguous := {
  id := "where-alt-name-ambiguous",
  ast := { layers := [P "eth", .alt [{ name := "ipv4", label := some "a" }, { name := "ipv4", label := some "b" }], P "tcp"],
           cond := some (cmp ttl .eq (k 64)) },
  expected := .illTyped "protocol ipv4 is ambiguous; qualify with an @label",
  note := "two members of one protocol: the name does not say which" }
def twoAlts (w : Option Where) : Filter :=
  { layers := [P "eth", .alt [{ name := "ipv4" }, { name := "ipv6" }], .alt [{ name := "tcp" }, { name := "udp" }]], cond := w }
vector altTwoGroups := {
  id := "alt-two-groups", ast := twoAlts none, packet := ipv6TCP, expected := .accept [],
  note := "the second group's members dispatch under whichever member of the first matched" }
vector altTwoGroupsUdp := {
  id := "alt-two-groups-udp", ast := twoAlts none, packet := udpPkt, expected := .accept [] }
vector whereAltTwoGroups := {
  id := "where-alt-two-groups", ast := twoAlts (some (.and (cmp ttl .eq (k 64)) (cmp dport .eq (k 80)))),
  expected := .accept [] }
vector whereAltTwoGroupsOther := {
  id := "where-alt-two-groups-other-member", ast := twoAlts (some (cmp dport .eq (k 80))), packet := udpPkt,
  expected := .reject }
def sackRight := Arith.field ⟨[("tcp", none), ("options", none), ("SACK", none), ("blocks", none), ("right", none)]⟩
def sackPkt' : Packet :=
  eth 0x0800 ++ ipv4 6 ++ tcp 12345 80 (dataOffset := 8) (options := [1, 1, 5, 10] ++ be 4 100 ++ be 4 200) ++ payload 5
vector whereQuantOtherAbsent := {
  id := "where-quant-other-layer-absent",
  ast := { layers := vlanOpt, cond := some (.all (.or (cmp sackRight .eq (k 200)) (cmp (fld "vlan" "tci") .eq (k 5)))) },
  packet := sackPkt', expected := .accept [],
  note := "the absent vlan makes its atom false in each iteration, not the quantifier" }
vector whereQuantOtherAbsentEmpty := {
  id := "where-quant-other-layer-absent-empty-stack",
  ast := { layers := vlanOpt, cond := some (.all (.or (cmp sackRight .eq (k 200)) (cmp (fld "vlan" "tci") .eq (k 5)))) },
  expected := .accept [],
  note := "no SACK blocks: all over an empty stack of a present layer is true, whatever else the body reads" }
vector whereQuantOtherMember := {
  id := "where-quant-other-member",
  ast := { layers := [P "eth", P "ipv4", .alt [{ name := "tcp" }, { name := "udp" }]],
           cond := some (.any (.or (cmp sackRight .eq (k 200)) (cmp (fld "udp" "dport") .eq (k 80)))) },
  packet := sackPkt', expected := .accept [] }

def whereVectors : List Vector := [
  whereAltNameAmbiguous, altTwoGroups, altTwoGroupsUdp, whereAltTwoGroups, whereAltTwoGroupsOther,
  whereQuantOtherAbsent, whereQuantOtherAbsentEmpty, whereQuantOtherMember,
  whereAltLabelHit, whereAltLabelOther, whereAltLabelOtherNot, whereAltNameHit, whereAltNameOther, whereAltNameOtherNot,
  whereAltLabelHet, whereAltLabelHetOther, whereAltLabelHetOtherNot, whereAltL3Hit, whereAltL3Other, whereAltL3OtherOr,
  whereAltL3AfterOpt, whereAltL3AfterOptOther,
  whereCmpOps, whereLitIPv4, whereCIDRIn, whereCIDRNe, whereCIDR0, whereMAC, whereIPv6CIDR, whereIPv6Eq,
  whereNegLitMiss, whereNegLitHit, whereConstFold,
  whereArithOps, whereBitwise, whereShiftMasked, whereNoWrap, whereDivZero, whereModZero, whereMixedWidth,
  whereTrue, whereFalse, whereDecay, whereNot, whereOr, whereBoolEqIff, whereBoolEqXor,
  whereAbsentFalse, whereAbsentNot, whereAbsentNe, whereOptPresent, whereAfterOptional, whereAfterOptionalAbsent,
  whereLabelRepeatedLast, whereLabelRepeatedFirstMiss, whereRepeatedUnlabelled, wherePastQuantified, whereLabels, whereAmbiguous,
  actionEntry, actionHit, actionMiss, actionUnknown,
  predCmp, predCmpMiss, predInList, predInListMiss, predInRange, typPredInRangeWide, typPredCmpRange, predInRangeMiss, predNegative, predIPv4,
  capAll, capWhereFalse, capWhereTrue, capLabel, capAbsent, capPresent, capAltMemberPresent, capAltMemberAbsent, capAltMemberByName,
  typUnknownProto, typNoDispatch, typNotInChain, typUnknownField, typFit, typLabelCollides, typLabelCollidesAlt, typLabelDuplicate, typFitArith, whereArithRight, whereArithRightMiss, typFitArithSibling, whereNegLitSibling, typWidthIPv6, typCIDRWidth,
  typWidthIPv6Slice, typWidthIPv6SliceBracket, ipv6DstLow32IPv4, ipv6DstLow32IPv4Miss, ipv6DstLow32Cidr, ipv6DstLow32IPv4Unaligned, ipv6DstLow32IPv4Ne, ipv6DstLow32IPv4NeMiss, ipv6DstLow48Mac, ipv6DstFullSliceIPv6, ipv6DstFullSliceCidr6, ipv6DstLow32IPv4Bracket,
  typPredIdent, typInSet, predInSetMember, predInSetMiss, typPredInSetWidth, predInSetSubByte, predInSetWindow, typPredInSetWindow, typPredInSetTwice, typPredInSetBudget, typPredInSetOptional, typPredInSetAlt, typAny, typExists, typAuxPath,
  arith128AddConst, arith128SubConst, arith128AddCarry, arith128AddWrap, arith128SubBorrow, arith128SubWrap, arith128AddMiss,
  arith128FieldAddField, arith128FieldAddFieldCarry, arith128FieldSubField, arith128FieldSubFieldBorrow, arith128AddWideConst, arith128SubWideConstBorrow,
  arith128AddNegConst, arith128SubNegConst, arith128CmpNegConst,
  arith128MixedWidthAdd, arith128MixedWidthMul, arith128MixedCarry, arith128MixedBorrow, arith128MixedWrap64, arith128MixedSlice,
  arith128MixedNested, arith128MixedNeg, arith128ConstBinop, arith128MixedAux, typArith128NarrowFitNested,
  arith128WideRight, arith128WideRightSub, arith128WideRightDeep, arith128WideRightConstLeft, arith128WideRightBorrow, arith128WideRightNarrowLeft, arith128WideRightNarrowLeftRej, arith128WideBoth, arith128WideBothBorrow, arith128WideBothNested, arith128WideBothNarrow, arith128WideBothRej, arith128BoolEqBothPark, arith128BoolEqBothParkRej, arith128BoolEqNarrow, arith128BoolEqNarrowRej, arith128BoolEqRightBoth5, arith128BoolEqRightBoth5False, arith128BoolEqRightBoth5BothFalse, arith128BoolEqRightBoth4Deep, arith128BoolEqRightBoth4DeepFalse, arith128BoolEqRightBoth4DeepBothFalse, arith128BoolEqRightNarrow, arith128BoolEqRightNarrowFalse, arith128BoolEqRightNarrowBothFalse, arithDepth16Left, arithDepth16Right, arithDepth16RightRej, arithDepthBothDeep, arithDepthBothDeepRej, arithDepth15InBoolEq, arith128WideLit, arith128WideLitHigh, arith128WideLitHighRej, arith128WideLitSmall, arith128WideLitNarrow, arith128WideLitNarrowRej, arith128WideLitLeft, arith128WideLitCmpLeft, arith128WideLitRightNested, arith128WideLitRightNestedSub, arith128WideLitSubHigh, arith128WideLitNarrowFit, typArith128WideMod, typArith128PlainTooNegative, typArith128WideTooWide, typArith128WideMul, typArith128PlainTooWide, typArith128NarrowFit, arith128CmpWideConst,
  arith128Lt, arith128GeMiss, arith128LtHighHalf, typArith128Mul, typArith128Band, typPathDeep, typPathDeepLabel, typPathDeepBracket]

end Kunai
