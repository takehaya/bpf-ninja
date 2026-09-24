package dsltest

import (
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
	"testing"
	"testing/fstest"
)

// Inline states must read the current option length before advancing to the
// next, differently sized option. The loop callback uses the same contract.
func TestParserInlineOperationOrder(t *testing.T) {
	src := `header foo_h { bit<8> length; }
 extern ParserCounter { ParserCounter(); void set(in bit<8> value); void decrement(in bit<8> value); bool is_zero(); }
 parser P(packet_in pkt, out foo_h hdr) {
 ParserCounter() pc;
 state start { pkt.extract(hdr); pc.set((bit<8>)(hdr.length + 0)); transition consume; }
 state consume {
  pc.decrement((bit<8>)pkt.lookahead<bit<16>>()[7:0]);
  pkt.advance(16);
  transition select(pc.is_zero()) { true: accept; default: reject; }
 }
 }`
	v, err := vocab.Load(fstest.MapFS{"vocab/foo.p4": {Data: []byte(src)}}, "vocab")
	if err != nil {
		t.Fatal(err)
	}
	r := NewWithVocab(t, "foo", v)
	packet := make([]byte, 64)
	copy(packet, []byte{2, 9, 2, 10, 7})
	r.MustMatch(t, packet, "subtract current option length 2 before advancing")
	packet[0] = 7
	r.MustReject(t, packet, "must not subtract next option length 7")
}

func TestParserInlineAuxCounter(t *testing.T) {
	src := `header foo_h { bit<8> count; }
 header opt_h { bit<8> kind; bit<8> length; }
 extern ParserCounter { ParserCounter(); void set(in bit<8> value); void decrement(in bit<8> value); bool is_zero(); }
 parser P(packet_in pkt, out foo_h hdr, out opt_h opt) {
 ParserCounter() pc;
 state start { pkt.extract(hdr); pc.set((bit<8>)(hdr.count + 0)); transition consume; }
 state consume { pkt.extract(opt); pc.decrement(opt.length); transition select(pc.is_zero()) { true: accept; default: reject; } }
 }`
	v, err := vocab.Load(fstest.MapFS{"vocab/foo.p4": {Data: []byte(src)}}, "vocab")
	if err != nil {
		t.Fatal(err)
	}
	r := NewWithVocab(t, "foo", v)
	pkt := make([]byte, 64)
	copy(pkt, []byte{2, 9, 2})
	r.MustMatch(t, pkt, "counter 2 subtracts extracted opt.length 2")
	pkt[0] = 9
	r.MustReject(t, pkt, "must not subtract option kind 9")
}
