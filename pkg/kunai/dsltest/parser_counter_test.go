package dsltest

import (
	"sync"
	"testing"
	"testing/fstest"

	"github.com/google/gopacket/layers"

	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// counterVocab loads a minimal eth/ipv4/tcp vocabulary where ipv4
// walks its options trailer with ParserCounter instead of the simple
// `pkt.advance(((bit<32>)(hdr.ihl - 5)) << 5)` template the bundled
// vocab uses. The vocab parses are memoised across tests since the
// result is read-only.
func counterVocab(t *testing.T) map[string]*vocab.ProtocolSpec {
	t.Helper()
	specs, err := loadCounterVocab()
	if err != nil {
		t.Fatalf("counterVocab: %v", err)
	}
	return specs
}

var loadCounterVocab = sync.OnceValues(func() (map[string]*vocab.ProtocolSpec, error) {
	const ethSrc = `
header eth_h {
    bit<48> dst;
    bit<48> src;
    bit<16> ethertype;
}
parser EthParser(packet_in pkt, out eth_h hdr) {
    state start { pkt.extract(hdr); transition accept; }
}
`
	// IPV4_MAX_DEPTH = 11 covers IHL=15 (40-byte trailer / 4 bytes
	// per iter = 10 iters; +1 absorbs the initial counter-zero
	// check before the first decrement). Each iteration consumes 4
	// bytes — IPv4 options always pad to 4-byte boundaries because
	// IHL is in 4-byte units.
	const ipv4Src = `
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

const bit<16> KUNAI_IPV4_ETH_ETHERTYPE = 0x0800;
// IPV4_MAX_DEPTH = 11: IHL=15 → 40-byte trailer / 4 bytes per
// iter = 10 iters; +1 absorbs the initial counter-zero check.
const bit<8>  IPV4_MAX_DEPTH     = 11;

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
        pkt.advance(32);
        pc.decrement(4);
        transition walk;
    }
}
`
	const tcpSrc = `
header tcp_h {
    bit<16> sport;
    bit<16> dport;
    bit<32> seq;
    bit<32> ack;
    bit<4>  data_offset;
    bit<3>  reserved;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

const bit<8> KUNAI_TCP_IPV4_PROTOCOL = 6;

parser TcpParser(packet_in pkt, out tcp_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
`
	fsys := fstest.MapFS{
		"vocab/eth.p4":  &fstest.MapFile{Data: []byte(ethSrc)},
		"vocab/ipv4.p4": &fstest.MapFile{Data: []byte(ipv4Src)},
		"vocab/tcp.p4":  &fstest.MapFile{Data: []byte(tcpSrc)},
	}
	return vocab.Load(fsys, "vocab")
})

// TestParserCounterIPv4NoOptions exercises the IHL=5 fast path: the
// `(4, 5): accept;` arm short-circuits the counter walk.
func TestParserCounterIPv4NoOptions(t *testing.T) {
	r := NewWithVocab(t, "eth/ipv4/tcp", counterVocab(t))
	r.MustMatch(t, BuildEthIPv4TCP(t, 12345, 80), "IHL=5 IPv4/TCP frame (no options)")
}

// TestParserCounterIPv4Walk runs the counter walk for IHL > 5. Each
// case bumps IHL via gopacket's IPv4Options, exercises the (4, _):
// walk arm, and the matching tcp layer past the options proves R4
// lands at the correct post-trailer position. The IHL=15 row
// saturates the bpf_loop max_iter cap (40-byte trailer / 4 bytes
// per iter = 10 iters).
func TestParserCounterIPv4Walk(t *testing.T) {
	r := NewWithVocab(t, "eth/ipv4/tcp", counterVocab(t))
	maxOpts := make([]layers.IPv4Option, 40)
	for i := range maxOpts {
		maxOpts[i] = layers.IPv4Option{OptionType: 1, OptionLength: 1}
	}
	cases := []struct {
		name string
		opts []layers.IPv4Option
	}{
		{
			name: "single 4-byte router-alert",
			opts: []layers.IPv4Option{{
				OptionType:   0x94,
				OptionLength: 4,
				OptionData:   []byte{0x00, 0x00},
			}},
		},
		{
			name: "two 4-byte option words",
			opts: []layers.IPv4Option{
				{OptionType: 0x94, OptionLength: 4, OptionData: []byte{0x00, 0x00}},
				{OptionType: 0x07, OptionLength: 3, OptionData: []byte{0x00}},
			},
		},
		{
			name: "IHL=15 saturated (40 NOPs)",
			opts: maxOpts,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := Defaults()
			o.IPv4Options = tc.opts
			r.MustMatch(t, Build(t, o), "counter walk drains IPv4 options before TCP")
		})
	}
}

// loadCounterTupleVocab synthesises a 2-key (counter.is_zero,
// lookahead<bit<8>>()) IPv4 walk that extracts Router Alert as a
// per-option aux header. The Mechanism 8 codegen path
// (emitMultiStateCounterKindDispatch) only fires under this exact
// shape, so the existing single-key counterVocab does not exercise
// it.
var loadCounterTupleVocab = sync.OnceValues(func() (map[string]*vocab.ProtocolSpec, error) {
	const ethSrc = `
header eth_h {
    bit<48> dst;
    bit<48> src;
    bit<16> ethertype;
}
parser EthParser(packet_in pkt, out eth_h hdr) {
    state start { pkt.extract(hdr); transition accept; }
}
`
	const ipv4Src = `
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

header ipv4_opt_router_alert_h {
    bit<8>  kind;
    bit<8>  length;
    bit<16> value;
}

const bit<16> KUNAI_IPV4_ETH_ETHERTYPE = 0x0800;
// IPV4_PARSER_MAX_DEPTH = 32: bpf_loop chain cap. NOP-heavy worst
// case (40 single-byte options) truncates at iter 32; mixed real
// options (Router Alert at 4 B/iter) drain well before that.
const bit<8>  IPV4_PARSER_MAX_DEPTH = 32;

extern ParserCounter {
    ParserCounter();
    void set(in bit<8> value);
    void decrement(in bit<8> value);
    bool is_zero();
}

parser IPv4Parser(packet_in pkt,
                  out ipv4_h                  hdr,
                  out ipv4_opt_router_alert_h router_alert) {
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
        transition select(pc.is_zero(), pkt.lookahead<bit<8>>()) {
            (true,  _):    accept;
            (false, 0):    accept;
            (false, 1):    parse_nop;
            (false, 148):  parse_router_alert;
            (false, _):    reject;
        }
    }
    state parse_nop          { pkt.advance(8); pc.decrement(1); transition walk; }
    state parse_router_alert { pkt.extract(router_alert); pc.decrement(4); transition walk; }
}
`
	const tcpSrc = `
header tcp_h {
    bit<16> sport;
    bit<16> dport;
    bit<32> seq;
    bit<32> ack;
    bit<4>  data_offset;
    bit<3>  reserved;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

const bit<8> KUNAI_TCP_IPV4_PROTOCOL = 6;

parser TcpParser(packet_in pkt, out tcp_h hdr) {
    state start { pkt.extract(hdr); transition accept; }
}
`
	fsys := fstest.MapFS{
		"vocab/eth.p4":  &fstest.MapFile{Data: []byte(ethSrc)},
		"vocab/ipv4.p4": &fstest.MapFile{Data: []byte(ipv4Src)},
		"vocab/tcp.p4":  &fstest.MapFile{Data: []byte(tcpSrc)},
	}
	return vocab.Load(fsys, "vocab")
})

func counterTupleVocab(t *testing.T) map[string]*vocab.ProtocolSpec {
	t.Helper()
	specs, err := loadCounterTupleVocab()
	if err != nil {
		t.Fatalf("counterTupleVocab: %v", err)
	}
	return specs
}

// TestParserCounterTupleDispatch exercises the 2-key (counter,
// lookahead) tuple form end-to-end: counter probe + kind cascade +
// per-option aux extraction. IHL=5 short-circuits via (4, 5) →
// accept, IHL=6 with Router Alert routes through the (false, 148)
// → parse_router_alert sibling. Asserts that downstream TCP still
// parses (= R4 landed at the correct post-trailer offset).
func TestParserCounterTupleDispatch(t *testing.T) {
	r := NewWithVocab(t, "eth/ipv4/tcp", counterTupleVocab(t))
	r.MustMatch(t, BuildEthIPv4TCP(t, 12345, 80), "IHL=5 fast path through tuple-select")

	o := Defaults()
	o.IPv4Options = []layers.IPv4Option{{
		OptionType:   0x94,
		OptionLength: 4,
		OptionData:   []byte{0x00, 0x00},
	}}
	r.MustMatch(t, Build(t, o), "tuple-select walk + Router Alert extraction + downstream TCP")
}
