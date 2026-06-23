package codegen

import (
	"errors"
	"testing"
	"testing/fstest"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/xdp-ninja/pkg/kunai/dslvocab"
	"github.com/takehaya/xdp-ninja/pkg/kunai/parser"
	"github.com/takehaya/xdp-ninja/pkg/kunai/resolve"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// compileBundled drives the full kunai.Compile pipeline (parser →
// resolve → codegen) against the bundled vocab, but stays in the
// codegen package so tests can inspect emitted instructions and
// reach private symbols. Mirrors kunai.Compile minus the Capabilities
// gymnastics — sufficient for codegen-level pinning.
func compileBundled(t *testing.T, expr string) Output {
	t.Helper()
	v, err := dslvocab.Bundled()
	if err != nil {
		t.Fatalf("dslvocab.Bundled: %v", err)
	}
	f, err := parser.Parse(expr, "", nil)
	if err != nil {
		t.Fatalf("parser.Parse(%q): %v", expr, err)
	}
	prog, err := resolve.ResolveWithOptions(f, v, nil, resolve.Options{})
	if err != nil {
		t.Fatalf("resolve(%q): %v", expr, err)
	}
	out, err := Gen(prog, Capabilities{})
	if err != nil {
		t.Fatalf("Gen(%q): %v", expr, err)
	}
	return out
}

// callbackKindBytes scans a callback instruction stream for the
// kind-byte JNE.Imm immediates the TLV-walk dispatch cascade emits.
// The set of kind bytes present pins which dispatch arms survived
// elision: a queried option's kind appears, an elided option's kind
// does not. Vocab-independent — works for any TLV walk that uses
// `JNE.Imm reg, kind, skip` in the cascade.
func callbackKindBytes(insns asm.Instructions) map[int64]bool {
	want := asm.JNE.Imm(asm.R0, 0, "").OpCode
	kinds := map[int64]bool{}
	for _, ins := range insns {
		if ins.OpCode == want {
			kinds[ins.Constant] = true
		}
	}
	return kinds
}

// TestTLVWalkCascadeElidesUnqueriedKinds pins B-2a-2 mitigation (d).
// Compiling with one queried option (MSS) must elide the cascade
// arms for the four unqueried kinds (WS, SACK_PERM, SACK, TS) — they
// fall through to the parse_unknown_opt-equivalent default, which
// the verifier on kernel 6.12 can coalesce. See
// docs/ja/dsl-followups.md mitigation (d).
//
// The earlier ordinal `len(one.Callbacks) < len(all.Callbacks)`
// metric was too weak: it would pass even if caseRedundantWithDefault
// were stubbed to `return false` (no elision at all), because the
// per-option slot-store prelude grows with the queried set
// independently of dispatch elision. The kind-byte JNE.Imm scan
// here pins both directions atomically (queried kind present, elided
// kinds absent).
func TestTLVWalkCascadeElidesUnqueriedKinds(t *testing.T) {
	out := compileBundled(t, "eth/ipv4/tcp where tcp.options.MSS.value == 1460")
	kinds := callbackKindBytes(out.Callbacks)

	// Elision predicate (caseRedundantWithDefault) requires the case
	// target to have ≥1 ExtractOp + zero manual advances. Kind cases:
	//   MSS (2)       — queried, must emit
	//   WS (3)        — extract+no-advance, unqueried → ELIDED
	//   SACK_PERM (4) — extract+no-advance, unqueried → ELIDED
	//   SACK (5)      — no extract + lookahead advance → NOT elided
	//                   (rule 3 fails on len(Extracts) == 0; the
	//                   conservative guard preserves the dispatched-
	//                   but-not-extracted shape that B-4 R1 relies on,
	//                   pinned by owner_bound_invariant_test.go)
	//   TS (8)        — extract+no-advance, unqueried → ELIDED
	const (
		mssKind  int64 = 2
		wsKind   int64 = 3
		sackPerm int64 = 4
		sackKind int64 = 5
		tsKind   int64 = 8
	)
	if !kinds[mssKind] {
		t.Errorf("MSS kind=%d JNE missing — queried kind must always emit", mssKind)
	}
	if !kinds[sackKind] {
		t.Errorf("SACK kind=%d JNE missing — no-extract sibling must stay (rule 3 failure preserves dispatched-but-not-extracted shape)", sackKind)
	}
	for _, k := range []int64{wsKind, sackPerm, tsKind} {
		if kinds[k] {
			t.Errorf("kind=%d JNE present — extract-only unqueried kind should be elided", k)
		}
	}
}

// TestTLVWalkCascadeMultiOptionAccumulator pins the multi-option
// boundary after the accumulator lowering landed. A pure conjunction of
// `<option>.<field> == <const>` equalities over >=2 distinct queried TCP
// options now COMPILES: the per-iteration callback collects one result
// bit per leaf into a single accumulator slot (one recorded slot, not N
// option positions), so the walk converges. Shapes the accumulator does
// not cover still reject at compile time:
//   - `!=` (or any non-eq op) on an option field,
//   - mixing a non-option atom (e.g. tcp.dport == 443) into the AND.
func TestTLVWalkCascadeMultiOptionAccumulator(t *testing.T) {
	v, err := dslvocab.Bundled()
	if err != nil {
		t.Fatalf("dslvocab.Bundled: %v", err)
	}
	cases := []struct {
		name   string
		expr   string
		reject bool
	}{
		{
			name: "pure_and_eq_2opt",
			expr: "eth/ipv4/tcp where " +
				"tcp.options.MSS.value == 1460 " +
				"and tcp.options.WS.shift == 7",
			reject: false,
		},
		{
			name: "pure_and_eq_3opt",
			expr: "eth/ipv4/tcp where " +
				"tcp.options.MSS.value == 1460 " +
				"and tcp.options.WS.shift == 7 " +
				"and tcp.options.SACK_PERM.kind == 4",
			reject: false,
		},
		{
			// Four atoms lower via the N-walks path (one single-option walk
			// per atom): the combined callback caps at combinedAccMaxAtoms
			// (=3) matrix-wide, so the fourth splits the plan into separate
			// walks with the accumulator canonicalized between them.
			name: "pure_and_eq_4opt_nwalks",
			expr: "eth/ipv4/tcp where " +
				"tcp.options.MSS.value == 1460 " +
				"and tcp.options.WS.shift == 7 " +
				"and tcp.options.SACK_PERM.kind == 4 " +
				"and tcp.options.TS.tsval == 1",
			reject: false,
		},
		{
			// Fourteen atoms = every field of every TCP option type, TCP's
			// maximum constructible query. With the wide (u64) accumulator
			// forget the N-walks cost stays linear, so it loads; accMaxAtoms
			// (=16) sits above it, so no realistic TCP query is rejected for
			// exceeding the cap (the numeric over-cap reject is therefore
			// unconstructible for TCP; the shape rejects below still exercise
			// the reject path).
			name: "pure_and_eq_14opt_max",
			expr: "eth/ipv4/tcp where " +
				"tcp.options.MSS.kind == 2 " +
				"and tcp.options.MSS.length == 4 " +
				"and tcp.options.MSS.value == 1460 " +
				"and tcp.options.WS.kind == 3 " +
				"and tcp.options.WS.length == 3 " +
				"and tcp.options.WS.shift == 7 " +
				"and tcp.options.SACK_PERM.kind == 4 " +
				"and tcp.options.SACK_PERM.length == 2 " +
				"and tcp.options.TS.kind == 8 " +
				"and tcp.options.TS.length == 10 " +
				"and tcp.options.TS.tsval == 1 " +
				"and tcp.options.TS.tsecr == 2 " +
				"and tcp.options.SACK.kind == 5 " +
				"and tcp.options.SACK.length == 10",
			reject: false,
		},
		{
			// A `!=` leaf breaks the pure-AND-equality shape, so the
			// accumulator is not built and the >=2 reject stands.
			name: "ne_leaf_rejects",
			expr: "eth/ipv4/tcp where " +
				"tcp.options.MSS.value == 1460 " +
				"and tcp.options.WS.shift != 7",
			reject: true,
		},
		{
			// Mixing a non-option (primary-header) atom into the AND
			// leaves both options queried but not all covered by eq-leaves,
			// so the accumulator is not built and the >=2 reject stands.
			name: "non_option_atom_rejects",
			expr: "eth/ipv4/tcp where " +
				"tcp.dport == 443 " +
				"and tcp.options.MSS.value == 1460 " +
				"and tcp.options.WS.shift == 7",
			reject: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := parser.Parse(tc.expr, "", nil)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			prog, err := resolve.ResolveWithOptions(f, v, nil, resolve.Options{})
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			_, err = Gen(prog, Capabilities{})
			if tc.reject {
				if !errors.Is(err, ErrNotImplemented) {
					t.Fatalf("expected ErrNotImplemented, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected success, got %v", err)
			}
		})
	}
}

// TestTLVWalkCascadeElides2KeyDispatch pins the 2-key
// (counter+kind) variant of the elision (= IPv4 options shape via
// emitMultiStateCounterKindDispatch). The bundled `ipv4.p4` puts a
// `pc.decrement(...)` counter op on every dispatch arm, so its
// elision predicate is `false` for every case in production today
// — the 2-key code path's pre-scan + skip is structurally inert
// against the bundled vocab. To exercise it, build a synthetic
// vocab via fstest.MapFS that mimics the IPv4 options shape but
// omits `pc.decrement` from the elidable arms (extract-only
// siblings). The codegen result is what we assert against; runtime
// semantics (counter would not progress on the elided arm in a
// real packet trace) are out of scope.
//
// The `(false, _)` wildcard sits before the concrete kinds in the
// case list, so the pre-scan in emitMultiStateCounterKindDispatch
// has to find it ahead of the main loop — exactly the OCR Round-3
// 2KEY-UNTESTED concern.
func TestTLVWalkCascadeElides2KeyDispatch(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/eth.p4": &fstest.MapFile{Data: []byte(`
header eth_h { bit<48> dst; bit<48> src; bit<16> ethertype; }
parser EthParser(packet_in pkt, out eth_h hdr) {
    state start { pkt.extract(hdr); transition accept; }
}
`)},
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h     { bit<8> ihl; bit<24> _pad; }
header foo_mss_h { bit<8> kind; bit<8> length; bit<16> value; }
header foo_ws_h  { bit<8> kind; bit<8> length; bit<8> shift;  bit<8> _pad; }
const bit<16> FOO_ETH_ETHERTYPE = 0x0800;
const bit<8>  FOO_PARSER_MAX_DEPTH = 8;

extern ParserCounter {
    ParserCounter();
    void set(in bit<8> value);
    void decrement(in bit<8> value);
    bool is_zero();
}

parser F(packet_in pkt, out foo_h hdr, out foo_mss_h mss, out foo_ws_h ws) {
    ParserCounter() pc;
    state start {
        pkt.extract(hdr);
        pc.set(((bit<8>)(hdr.ihl - 1)) << 5);
        transition select(hdr.ihl) {
            1:       accept;
            default: walk;
        }
    }
    state walk {
        transition select(pc.is_zero(), pkt.lookahead<bit<8>>()) {
            (true,  _):  accept;
            (false, _):  parse_unknown;
            (false, 2):  parse_mss;
            (false, 3):  parse_ws;
        }
    }
    state parse_mss     { pkt.extract(mss); transition walk; }
    state parse_ws      { pkt.extract(ws);  transition walk; }
    state parse_unknown {
        pkt.advance(((bit<32>)pkt.lookahead<bit<16>>()[7:0]) << 3);
        pc.decrement(1);
        transition walk;
    }
}
`)},
	}
	specs, err := vocab.Load(fsys, "vocab")
	if err != nil {
		t.Fatalf("vocab.Load: %v", err)
	}

	// Compile a filter that queries MSS but not WS. With the elision
	// predicate active on the 2-key dispatch, kind=3 (WS) should be
	// elided because parse_ws has extract+no-advance+no-counter and
	// is unqueried; the `(false, _)` wildcard targets parse_unknown
	// which is parse_unknown_opt-equivalent (default-side check
	// passes).
	expr := "eth/foo where foo.options.MSS.value == 1460"
	f, err := parser.Parse(expr, "", nil)
	if err != nil {
		t.Fatalf("parser.Parse: %v", err)
	}
	prog, err := resolve.ResolveWithOptions(f, specs, nil, resolve.Options{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	out, err := Gen(prog, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}

	kinds := callbackKindBytes(out.Callbacks)
	if !kinds[2] {
		t.Errorf("MSS kind=2 JNE missing — queried kind must always emit (2-key path)")
	}
	if kinds[3] {
		t.Errorf("WS kind=3 JNE present — extract-only unqueried kind should be elided in 2-key path")
	}
}

// countFnLoop returns the number of bpf_loop helper calls in an
// instruction stream — the structural signature of how many distinct
// walk subprograms the program drives.
func countFnLoop(insns asm.Instructions) int {
	want := asm.FnLoop.Call().OpCode
	n := 0
	for _, ins := range insns {
		if ins.OpCode == want {
			n++
		}
	}
	return n
}

// TestTLVWalkMultiOptionAccumulatorStructure pins the accumulator
// lowering's structural shape for a pure-AND multi-option TCP query:
//
//   - exactly ONE bpf_loop drives the whole TLV walk (the accumulator
//     keeps the single self-loop — no extra subprogram per option), and
//   - the residual where clause reduces to a single `(acc & mask) ==
//     mask` test, i.e. an And.Imm by the full bitmask immediately
//     followed by a JNE.Imm against the same mask.
//
// For two queried options the mask is 0b11 = 3.
func TestTLVWalkMultiOptionAccumulatorStructure(t *testing.T) {
	out := compileBundled(t, "eth/ipv4/tcp where tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7")

	all := append(append(asm.Instructions{}, out.Main...), out.Callbacks...)
	if got := countFnLoop(all); got != 1 {
		t.Fatalf("multi-option accumulator must use exactly 1 bpf_loop, got %d", got)
	}

	const wantMask = int64(0b11) // two leaves → bits 0 and 1
	andOp := asm.And.Imm(asm.R3, 0).OpCode
	jneOp := asm.JNE.Imm(asm.R3, 0, "").OpCode
	foundMaskCheck := false
	for i := 0; i+1 < len(out.Main); i++ {
		a, b := out.Main[i], out.Main[i+1]
		if a.OpCode == andOp && a.Constant == wantMask &&
			b.OpCode == jneOp && b.Constant == wantMask {
			foundMaskCheck = true
			break
		}
	}
	if !foundMaskCheck {
		t.Fatalf("accumulator mask check (And.Imm %d ; JNE.Imm %d) not found in Main", wantMask, wantMask)
	}
}
