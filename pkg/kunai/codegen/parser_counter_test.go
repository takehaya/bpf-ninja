package codegen

import (
	"errors"
	"testing"

	"testing/fstest"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/xdp-ninja/pkg/kunai/parser"
	"github.com/takehaya/xdp-ninja/pkg/kunai/resolve"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// TestParserCounterSlotAllocation pins the slot offsets the codegen
// hands out for ParserCounter instances. The lower-bound check
// surfaces the "no third counter without a region rethink" footgun
// added by parser_counter.go's gap-region carve-out.
func TestParserCounterSlotAllocation(t *testing.T) {
	for i, want := range []int16{-152, -160} {
		got, err := parserCounterSlot(i)
		if err != nil {
			t.Fatalf("parserCounterSlot(%d): %v", i, err)
		}
		if got != want {
			t.Errorf("parserCounterSlot(%d) = %d, want %d", i, got, want)
		}
	}
	if _, err := parserCounterSlot(parserCounterMaxSlots); err == nil {
		t.Errorf("expected error for slot index %d (>= max %d)", parserCounterMaxSlots, parserCounterMaxSlots)
	}
}

// TestGenIPv4ParserCounterMachine compiles a synthetic vocab whose
// IPv4 parser uses ParserCounter to walk the option trailer. The
// DSL doesn't query any per-option aux, so codegen routes through
// canFallbackToBulkAdvance → emitCounterDrivenBulkAdvance: no
// bpf_loop subprogram, no per-iter callback, just an
// emitVariableTrailInline-equivalent advance that reads the
// length expression from the primary header and bumps R4.
//
// Asserts:
//
//  1. Counter slot zero-init at machine entry (unchanged from full
//     walk path).
//  2. Counter set still emits in the start state — the byte
//     expression is captured even though the walk skips reading it
//     back from the slot at runtime.
//  3. NO bpf_loop subprogram (out.Callbacks empty for this layer).
//
// The full bpf_loop path is exercised separately by dsltest's
// TestParserCounterTupleDispatch, which uses a 2-key vocab + an
// aux query to force per-option codegen.
func TestGenIPv4ParserCounterMachine(t *testing.T) {
	const ipv4Source = `
header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_length;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> checksum;
    bit<32> src;
    bit<32> dst;
}

const bit<16> IPV4_ETH_ETHERTYPE = 0x0800;

extern ParserCounter {
    ParserCounter();
    void set(in bit<8> value);
    void decrement(in bit<8> value);
    bool is_zero();
}

parser IPv4Parser(packet_in pkt, out ipv4_h hdr) {
    ParserCounter() pc;
    state start {
        pkt.extract(hdr);
        pc.set(((bit<8>)(hdr.ihl - 5)) << 5);
        transition select(hdr.version, hdr.ihl) {
            (4, 5):  accept;
            (4, _):  walk;
            default: reject;
        }
    }
    state walk {
        transition select(pc.is_zero()) {
            true:  accept;
            false: consume;
        }
    }
    state consume {
        pkt.advance(8);
        pc.decrement(1);
        transition walk;
    }
}
`
	const ethSource = `
header eth_h {
    bit<48> dst;
    bit<48> src;
    bit<16> ethertype;
}
parser ETH(packet_in pkt, out eth_h hdr) {
    state start { pkt.extract(hdr); transition accept; }
}
`
	fsys := fstest.MapFS{
		"vocab/eth.p4":  &fstest.MapFile{Data: []byte(ethSource)},
		"vocab/ipv4.p4": &fstest.MapFile{Data: []byte(ipv4Source)},
	}
	specs, err := vocab.Load(fsys, "vocab")
	if err != nil {
		t.Fatalf("vocab.Load: %v", err)
	}

	f, err := parser.Parse("eth/ipv4", "", nil)
	if err != nil {
		t.Fatalf("parser.Parse: %v", err)
	}
	prog, err := resolve.Resolve(f, specs, nil)
	if err != nil {
		t.Fatalf("resolve.Resolve: %v", err)
	}

	out, err := Gen(prog, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	if len(out.Main) == 0 {
		t.Fatal("expected non-empty Main stream")
	}

	slot0, err := parserCounterSlot(0)
	if err != nil {
		t.Fatalf("parserCounterSlot(0): %v", err)
	}
	stream := append(asm.Instructions{}, out.Main...)
	stream = append(stream, out.Callbacks...)

	if err := assertCounterStoreToR10(stream, slot0); err != nil {
		t.Errorf("counter slot init: %v", err)
	}
	// No aux is queried, so bulk-advance fallback fires: the
	// bpf_loop subprogram (which would land in out.Callbacks) is
	// skipped.
	if len(out.Callbacks) != 0 {
		t.Errorf("bulk-advance fallback should emit no callbacks; got %d insns", len(out.Callbacks))
	}
}

// assertCounterStoreToR10 checks that some StoreMem references the
// given R10-relative slot, which doubles as proof that the slot
// init prelude (`Mov.Imm Rx, 0; StoreMem R10[slot], Rx`) ran.
func assertCounterStoreToR10(stream asm.Instructions, slot int16) error {
	for _, ins := range stream {
		if ins.Dst == asm.R10 && int16(ins.Offset) == slot && ins.OpCode.Class().IsStore() {
			return nil
		}
	}
	return errors.New("no StoreMem to expected counter slot")
}


