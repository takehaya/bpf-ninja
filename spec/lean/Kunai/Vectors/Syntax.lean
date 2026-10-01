import Kunai.Vectors.Base

/-!
# Syntax coverage

Every constructor of `Syntax.lean` appears at least once; these drive the Go
round-trip test as well as `eval`.
-/
namespace Kunai

vector synChain := {
  id := "syn-chain", ast := { layers := chain3 },
  expected := .accept [] }

vector synLabelPreds := {
  id := "syn-label-preds",
  ast := { layers := [P "eth",
        .proto { name := "ipv4", label := some "outer",
                 preds := [.cmp (f "ttl") .gt (.int 1), .cmp (f "dst") .eq (.ipv4 0x0a000002)] },
        P "tcp"] },
  expected := .accept [] }

vector synQuantOpt := {
  id := "syn-quant-opt", ast := { layers := [P "eth", .proto { name := "vlan", quant := .opt }, P "ipv4"] },
  expected := .accept [] }

vector synQuantPlus := {
  id := "syn-quant-plus", ast := { layers := [P "eth", .proto { name := "mpls", quant := .plus }, P "ipv4"] },
  expected := .reject }

vector synQuantStar := {
  id := "syn-quant-star", ast := { layers := [P "eth", .proto { name := "vlan", quant := .star }, P "ipv4"] },
  expected := .accept [] }

vector synQuantRange := {
  id := "syn-quant-range",
  ast := { layers := [P "eth", .proto { name := "mpls", quant := .range 1 (some 8) }, P "ipv4"] },
  expected := .reject }

vector synQuantOpen := {
  id := "syn-quant-open",
  ast := { layers := [P "eth", .proto { name := "mpls", quant := .range 2 none }, P "ipv4"] },
  expected := .reject }

vector synPredQuantOrder := {
  id := "syn-pred-quant-order",
  ast := { layers := [P "eth",
        .proto { name := "vlan", preds := [.cmp (f "tci") .eq (.int 100)], quant := .opt },
        P "ipv4"] },
  expected := .accept [] }

vector synPredIn := {
  id := "syn-pred-in",
  ast := { layers := [P "eth", P "ipv4",
        .proto { name := "tcp", preds := [.inList (f "dport") [.int 80, .int 443, .range 8000 8080]] }] },
  expected := .accept [], goStatus := .notImplemented }

vector synPredInset := {
  id := "syn-pred-inset",
  ast := { layers := [P "eth", .proto { name := "ipv4", preds := [.inSet (f "src") "blocklist"] }] },
  expected := .illTyped "unsupported: in @set", goStatus := .notImplemented }

vector synPredValues := {
  id := "syn-pred-values",
  ast := { layers := [
        .proto { name := "eth", preds := [.cmp (f "dst") .ne (.mac 0x001122aabbcc)] },
        .proto { name := "ipv6",
                 preds := [.cmp (f "src") .eq (.ipv6 0xfc000000000000000000000000000001),
                           .cmp (f "dst") .eq (.cidr6 0x20010db8000000000000000000000000 32)] },
        .proto { name := "tcp", preds := [.cmp (f "flags") .eq (.ident "SYN"), .cmp (f "window") .le (.int (-1))] }] },
  expected := .illTyped "unsupported: identifier literal SYN" }

vector synAlt := {
  id := "syn-alt", ast := { layers := [P "eth", .alt [{ name := "ipv4" }, { name := "ipv6" }], P "tcp"] },
  expected := .accept [] }

vector synWhereLogic := {
  id := "syn-where-logic",
  ast := {
      layers := chain3,
      cond := some (.or (.and (.arith (.field (ff "tcp" "dport")) .eq (.const 80))
                              (.not (.arith (.field (ff "ipv4" "ttl")) .lt (.const 5))))
                        (.boolLit false)) },
  expected := .accept [] }

vector synWhereArithOps := {
  id := "syn-where-arith-ops",
  ast := {
      layers := chain3,
      cond := some (.arith
        (.bin .shr (.bin .shl (.bin .bxor (.bin .bor (.bin .band (.bin .mod (.bin .div (.bin .mul (.bin .sub
          (.bin .add (.field (ff "tcp" "sport")) (.const 1)) (.const 2)) (.const 3)) (.const 4)) (.const 5))
          (.const 0xff)) (.const 1)) (.const 2)) (.const 1)) (.const 1))
        .ge (.const (-7))) },
  expected := .reject, note := "12345 ⟶ 1; -7 ⤳ 65529 in Int<16>" }

vector synWhereLitcmp := {
  id := "syn-where-litcmp",
  ast := {
      layers := [P "eth", P "ipv4"],
      cond := some (.and (.litCmp (ff "ipv4" "src") .eq (.cidr4 0x0a000000 8))
                         (.and (.litCmp (ff "ipv4" "dst") .ne (.ipv4 0xc0a80101))
                               (.litCmp (ff "eth" "src") .eq (.mac 0xaabbccddeeff)))) },
  expected := .reject, note := "eth.src differs" }

vector synWhereAction := {
  id := "syn-where-action",
  ast := { layers := [P "eth", P "ipv4"], cond := some (.action "XDP_DROP") },
  expected := .illTyped "`action ==` is not available on this host" }

vector synWhereAnyAll := {
  id := "syn-where-any-all",
  ast := {
      layers := [P "eth", P "ipv6", P "srv6"],
      cond := some (.and
        (.any (.arith (.field ⟨[("srv6", none), ("segments", some (.field ["x"])), ("addr", none)]⟩) .ne (.const 0)))
        (.all (.arith (.field ⟨[("srv6", none), ("segments", some (.nat 0)), ("addr", some (.slice 0 32))]⟩)
                      .eq (.const 1)))) },
  expected := .illTyped "dynamic index x must be <proto>.<field>", note := "Go rejects it too (field path x must be qualified)" }

vector synWhereBool := {
  id := "syn-where-bool",
  ast := {
      layers := chain3,
      cond := some (.boolEq (.fieldExists (ff "tcp" "options")) .ne
                            (.boolEq (.boolLit true) .eq (.arith (.field (ff "tcp" "dport")) .ne (.const 0)))) },
  expected := .illTyped "unknown auxiliary header tcp.options" }

vector synCapture := {
  id := "syn-capture",
  ast := {
      layers := [P "eth", .proto { name := "ipv4", label := some "inner" }, P "tcp"],
      captures := [{ spec := .all }, { spec := .headers }, { spec := .headersPlus 16 },
                   { spec := .toLayer "inner" 0 }, { spec := .toLayer "tcp" 8 },
                   { spec := .absolute 128, cond := some (.arith (.field (ff "tcp" "dport")) .eq (.const 80)) }] },
  expected := .accept [(0, 59), (0, 54), (0, 59), (14, 34), (34, 59), (0, 59)] }

def syntaxVectors : List Vector := [
  synChain, synLabelPreds, synQuantOpt, synQuantPlus, synQuantStar, synQuantRange, synQuantOpen, synPredQuantOrder, synPredIn, synPredInset, synPredValues, synAlt, synWhereLogic, synWhereArithOps, synWhereLitcmp, synWhereAction, synWhereAnyAll, synWhereBool, synCapture]

end Kunai
