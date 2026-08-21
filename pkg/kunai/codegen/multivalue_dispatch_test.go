package codegen

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/parser"
	"github.com/takehaya/bpf-ninja/pkg/kunai/resolve"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// genMultiValueVocab compiles expr against a synthetic two-protocol
// vocab: an eth-like parent and a fixed 4-byte child `foo` whose
// dispatch consts are supplied by the caller.
func genMultiValueVocab(t *testing.T, fooConsts, expr string) (Output, error) {
	t.Helper()
	fsys := fstest.MapFS{
		"vocab/eth.p4": &fstest.MapFile{Data: []byte(`
header eth_h { bit<48> dst; bit<48> src; bit<16> ethertype; }
parser EthParser(packet_in pkt, out eth_h hdr) {
    state start { pkt.extract(hdr); transition accept; }
}
`)},
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<16> kind; bit<16> body; }
` + fooConsts + `
parser FooParser(packet_in pkt, out foo_h hdr) {
    state start { pkt.extract(hdr); transition accept; }
}
`)},
	}
	specs, err := vocab.Load(fsys, "vocab")
	if err != nil {
		t.Fatalf("vocab.Load: %v", err)
	}
	f, err := parser.Parse(expr, "", nil)
	if err != nil {
		t.Fatalf("parser.Parse: %v", err)
	}
	prog, err := resolve.Resolve(f, specs, nil)
	if err != nil {
		t.Fatalf("resolve.Resolve: %v", err)
	}
	return Gen(prog, Capabilities{})
}

// countDispatchMatchShape counts the JEq→multiok / JNE pairs of the
// multi-value dispatch tail in an instruction stream.
func countDispatchMatchShape(insns asm.Instructions) (jeqToMultiok, landings int) {
	for _, ins := range insns {
		if ins.OpCode.JumpOp() == asm.JEq && strings.HasPrefix(ins.Reference(), "dsl_altdisp_multiok_") {
			jeqToMultiok++
		}
		if strings.HasPrefix(ins.Symbol(), "dsl_altdisp_multiok_") {
			landings++
		}
	}
	return
}

// TestGenSelfLoopMultiValueDispatch pins the bpf_loop self-dispatch
// peek (chainFieldPeek) with AltValues: a `foo+` chain whose self-
// dispatch const carries an alternate value must emit the JEq→multiok
// chain inside the callback subprogram, not just in Main.
func TestGenSelfLoopMultiValueDispatch(t *testing.T) {
	out, err := genMultiValueVocab(t, `
const bit<16> KUNAI_FOO_ETH_ETHERTYPE = 0x1234;
const bit<16> KUNAI_FOO_FOO_KIND = 1;
const bit<16> KUNAI_FOO_FOO_KIND_ALT = 2;
`, "eth/foo+")
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	if len(out.Callbacks) == 0 {
		t.Fatal("expected a bpf_loop callback subprogram for foo+")
	}
	jeq, landings := countDispatchMatchShape(out.Callbacks)
	if jeq == 0 || landings == 0 {
		t.Errorf("callback stream: JEq-to-multiok = %d, landings = %d; want both >= 1", jeq, landings)
	}
}

// TestGenRejectsHighBitDispatchValue pins the immediate-range guard:
// a dispatch value whose byte-swapped form exceeds MaxInt32 (0x80
// over a 4-byte field swaps to 0x80000000) must fail codegen loudly
// instead of emitting a sign-extended compare that can never match.
func TestGenRejectsHighBitDispatchValue(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/bar.p4": &fstest.MapFile{Data: []byte(`
header bar_h { bit<32> tag; }
parser BarParser(packet_in pkt, out bar_h hdr) {
    state start { pkt.extract(hdr); transition accept; }
}
`)},
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<16> kind; }
const bit<32> KUNAI_FOO_BAR_TAG = 0x80;
parser FooParser(packet_in pkt, out foo_h hdr) {
    state start { pkt.extract(hdr); transition accept; }
}
`)},
	}
	specs, err := vocab.Load(fsys, "vocab")
	if err != nil {
		t.Fatalf("vocab.Load: %v", err)
	}
	f, err := parser.Parse("bar/foo", "", nil)
	if err != nil {
		t.Fatalf("parser.Parse: %v", err)
	}
	prog, err := resolve.Resolve(f, specs, nil)
	if err != nil {
		t.Fatalf("resolve.Resolve: %v", err)
	}
	if _, err := Gen(prog, Capabilities{}); err == nil || !strings.Contains(err.Error(), "byte-swaps") {
		t.Errorf("expected immediate-range error, got %v", err)
	}
}
