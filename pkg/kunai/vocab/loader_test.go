package vocab

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/takehaya/xdp-ninja/pkg/kunai/protocols"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab/p4lite"
)

// loadBundled loads the baked-in vocabulary exactly as production code will.
func loadBundled(t *testing.T) map[string]*ProtocolSpec {
	t.Helper()
	specs, err := Load(protocols.FS, ".")
	if err != nil {
		t.Fatalf("Load bundled vocab: %v", err)
	}
	return specs
}

func TestLoadBundledCount(t *testing.T) {
	specs := loadBundled(t)
	want := []string{
		"eth", "ipv4", "ipv6", "tcp", "udp", "gtp", "srv6",
		"vlan", "qinq", "cw",
		"mpls", "gre", "vxlan", "geneve",
		"icmp", "icmp6",
	}
	for _, name := range want {
		if _, ok := specs[name]; !ok {
			t.Errorf("missing protocol %q in bundled vocab (loaded: %v)", name, specNames(specs))
		}
	}
}

func TestLoadMplsDispatch(t *testing.T) {
	mpls := loadBundled(t)["mpls"]
	dc := indexByName(mpls.Consts)
	eth, ok := dc["MPLS_ETH_ETHERTYPE"]
	if !ok || eth.Type != DispatchField || eth.Parent != "eth" || eth.Value != 0x8847 {
		t.Errorf("MPLS_ETH_ETHERTYPE = %+v", eth)
	}
	stack, ok := dc["MPLS_MPLS_NO_CHECK"]
	if !ok || stack.Type != DispatchNoCheck || !stack.Bool {
		t.Errorf("MPLS_MPLS_NO_CHECK = %+v", stack)
	}
	if mpls.MaxDepth != 8 {
		t.Errorf("MPLS_MAX_DEPTH: spec.MaxDepth = %d, want 8", mpls.MaxDepth)
	}
}

// TestLoadBundledNoPhantomParserDispatch guards against re-introducing
// the `<SELF>_PARSER_MAX_DEPTH = N` drift that TCP and IPv4 used to
// carry. The loader's MAX_DEPTH path matches the exact name
// `<SELF>_MAX_DEPTH` only; a `_PARSER_` infix slips past that check
// and is silently classified as a `<SELF>_<PARENT>_<FIELD>` dispatch
// const with Parent="parser" — which dispatches to nothing because
// no real layer is named "parser", so the intended iteration cap is
// never applied. Loud-fail here so source/impl drift can't recur.
func TestLoadBundledNoPhantomParserDispatch(t *testing.T) {
	specs := loadBundled(t)
	for name, spec := range specs {
		for _, c := range spec.Consts {
			if c.Type == DispatchField && c.Parent == "parser" {
				t.Errorf("%s: const %q has phantom Parent=%q FieldName=%q Value=%d — declare `<SELF>_MAX_DEPTH = N` (no `_PARSER_` infix) instead",
					name, c.Name, c.Parent, c.FieldName, c.Value)
			}
		}
	}
}

func TestLoadGreDispatch(t *testing.T) {
	gre := loadBundled(t)["gre"]
	dc := indexByName(gre.Consts)
	v4, ok := dc["GRE_IPV4_PROTOCOL"]
	if !ok || v4.Parent != "ipv4" || v4.Value != 47 {
		t.Errorf("GRE_IPV4_PROTOCOL = %+v", v4)
	}
}

func TestLoadVxlanGenevePorts(t *testing.T) {
	vxlan := loadBundled(t)["vxlan"]
	if dc, ok := indexByName(vxlan.Consts)["VXLAN_UDP_DPORT"]; !ok || dc.Value != 4789 {
		t.Errorf("VXLAN_UDP_DPORT = %+v", dc)
	}
	geneve := loadBundled(t)["geneve"]
	if dc, ok := indexByName(geneve.Consts)["GENEVE_UDP_DPORT"]; !ok || dc.Value != 6081 {
		t.Errorf("GENEVE_UDP_DPORT = %+v", dc)
	}
}

func TestLoadVlanDispatchConstants(t *testing.T) {
	vlan := loadBundled(t)["vlan"]
	dc, ok := indexByName(vlan.Consts)["VLAN_ETH_ETHERTYPE"]
	if !ok {
		t.Fatal("VLAN_ETH_ETHERTYPE not found")
	}
	if dc.Type != DispatchField || dc.Parent != "eth" || dc.Value != 0x8100 {
		t.Errorf("VLAN_ETH_ETHERTYPE = %+v", dc)
	}
}

func TestLoadCwIsNoCheck(t *testing.T) {
	cw := loadBundled(t)["cw"]
	dc, ok := indexByName(cw.Consts)["CW_MPLS_NO_CHECK"]
	if !ok {
		t.Fatal("CW_MPLS_NO_CHECK not found")
	}
	if dc.Type != DispatchNoCheck || dc.Parent != "mpls" || !dc.Bool {
		t.Errorf("CW_MPLS_NO_CHECK = %+v", dc)
	}
}

func TestLoadGtpChainSelfReference(t *testing.T) {
	specs := loadBundled(t)
	gtp, ok := specs["gtp"]
	if !ok {
		t.Fatal("gtp not loaded")
	}
	if len(gtp.File.Parsers) == 0 {
		t.Fatal("gtp parser missing")
	}
	var extState *p4lite.State
	for _, s := range gtp.File.Parsers[0].States {
		if s.Name == "parse_ext" {
			extState = s
			break
		}
	}
	if extState == nil {
		t.Fatal("parse_ext state missing")
	}
	if extState.Transition.Select == nil {
		t.Fatal("parse_ext should transition via select")
	}
	var foundSelf bool
	for _, c := range extState.Transition.Select.Cases {
		if c.Target == "parse_ext" {
			foundSelf = true
		}
	}
	if !foundSelf {
		t.Error("parse_ext does not self-reference (chain not representable)")
	}
}

func TestLoadGtpMultipleHeaders(t *testing.T) {
	gtp := loadBundled(t)["gtp"]
	if gtp.HeaderName != "gtp_h" {
		t.Errorf("primary header = %q", gtp.HeaderName)
	}
	wantHeaders := []string{"gtp_h", "gtp_opt_h", "gtp_ext_h"}
	got := make([]string, 0, len(gtp.File.Headers))
	for _, h := range gtp.File.Headers {
		got = append(got, h.Name)
	}
	if len(got) != len(wantHeaders) {
		t.Fatalf("got %d headers, want %d: %v", len(got), len(wantHeaders), got)
	}
	for i, want := range wantHeaders {
		if got[i] != want {
			t.Errorf("header[%d] = %q, want %q", i, got[i], want)
		}
	}
}

func TestLoadSrv6Header(t *testing.T) {
	srv6 := loadBundled(t)["srv6"]
	if srv6.HeaderName != "srv6_h" {
		t.Errorf("primary header = %q", srv6.HeaderName)
	}
	wantHeaders := []string{"srv6_h", "srv6_seg_h"}
	got := make([]string, 0, len(srv6.File.Headers))
	for _, h := range srv6.File.Headers {
		got = append(got, h.Name)
	}
	if len(got) != len(wantHeaders) {
		t.Fatalf("got %d headers, want %d: %v", len(got), len(wantHeaders), got)
	}
	for i, want := range wantHeaders {
		if got[i] != want {
			t.Errorf("header[%d] = %q, want %q", i, got[i], want)
		}
	}
	// segments aux is declared as a stack so resolver can route
	// `srv6.segments[N].addr` to it. The parser block does not push
	// to it; the variable trail in codegen advances R4 past all
	// segments in one statically-bounded skip.
	if srv6.ParseStateMachine == nil {
		t.Fatal("expected non-trivial ParseStateMachine after segments declaration")
	}
	stack, ok := srv6.ParseStateMachine.StackRefs["segments"]
	if !ok {
		t.Fatalf("StackRefs[segments] missing; got %+v", srv6.ParseStateMachine.StackRefs)
	}
	if stack.Capacity != 8 || stack.ElemSize != 16 || stack.HeaderName != "srv6_seg_h" {
		t.Errorf("segments stack = %+v", stack)
	}
}

func TestLoadIpv4DispatchClassification(t *testing.T) {
	ipv4 := loadBundled(t)["ipv4"]
	// After SANITY removal, ipv4 self-validates via the parser block.
	// SelectDispatchConst returns Field for eth/vlan/qinq parents, and
	// nil for parents without a Field declaration; resolver synthesises
	// DispatchSelfValidating in that case.
	eth := ipv4.SelectDispatchConst("eth")
	if eth == nil || eth.Type != DispatchField {
		t.Errorf("SelectDispatchConst(\"eth\") = %+v, want Field dispatch", eth)
	}
	for _, parent := range []string{"gtp", "mpls"} {
		if got := ipv4.SelectDispatchConst(parent); got != nil {
			t.Errorf("SelectDispatchConst(%q) = %+v, want nil (resolver falls back to self-validation)", parent, got)
		}
	}
	if !ipv4.IsSelfValidating() {
		t.Error("ipv4 must be self-validating")
	}
}

func TestLoadGtpUdpDport(t *testing.T) {
	gtp := loadBundled(t)["gtp"]
	dc, ok := indexByName(gtp.Consts)["GTP_UDP_DPORT"]
	if !ok {
		t.Fatal("GTP_UDP_DPORT not found")
	}
	if dc.Type != DispatchField || dc.Parent != "udp" || dc.FieldName != "dport" || dc.Value != 2152 {
		t.Errorf("const = %+v", dc)
	}
}

func TestLoadTcpDispatchClassification(t *testing.T) {
	specs := loadBundled(t)
	tcp, ok := specs["tcp"]
	if !ok {
		t.Fatal("tcp not loaded")
	}
	byName := indexByName(tcp.Consts)
	cases := []struct {
		constName string
		wantType  DispatchType
		parent    string
		field     string
		value     uint64
	}{
		{"TCP_IPV4_PROTOCOL", DispatchField, "ipv4", "protocol", 6},
		{"TCP_IPV6_NEXT_HEADER", DispatchField, "ipv6", "next_header", 6},
	}
	for _, tc := range cases {
		dc, ok := byName[tc.constName]
		if !ok {
			t.Errorf("const %q not found", tc.constName)
			continue
		}
		if dc.Type != tc.wantType {
			t.Errorf("%s: type %v, want %v", tc.constName, dc.Type, tc.wantType)
		}
		if dc.Parent != tc.parent {
			t.Errorf("%s: parent %q, want %q", tc.constName, dc.Parent, tc.parent)
		}
		if dc.FieldName != tc.field {
			t.Errorf("%s: field %q, want %q", tc.constName, dc.FieldName, tc.field)
		}
		if dc.Value != tc.value {
			t.Errorf("%s: value %d, want %d", tc.constName, dc.Value, tc.value)
		}
	}
}

func TestLoadEthMplsNoCheck(t *testing.T) {
	specs := loadBundled(t)
	eth := specs["eth"]
	if eth == nil {
		t.Fatal("eth not loaded")
	}
	dc, ok := indexByName(eth.Consts)["ETH_MPLS_NO_CHECK"]
	if !ok {
		t.Fatal("ETH_MPLS_NO_CHECK not found")
	}
	if dc.Type != DispatchNoCheck || dc.Parent != "mpls" || !dc.Bool {
		t.Errorf("no-check const = %+v", dc)
	}
}

// TestComputeAuxLayoutsTcpKindBytes pins the TLV-walk siblings TCP
// declares — each one's aux header should land in AuxLayouts with
// IsDynamicEligible = true and the kind byte recovered from the
// parser block's `transition select` case label (= MSS_KIND = 2,
// WS_KIND = 3, SACK_PERM_KIND = 4, SACK_KIND = 5, TS_KIND = 8).
func TestComputeAuxLayoutsTcpKindBytes(t *testing.T) {
	specs := loadBundled(t)
	tcp := specs["tcp"]
	if tcp == nil || tcp.ParseStateMachine == nil {
		t.Fatal("tcp.ParseStateMachine missing")
	}
	want := map[string]uint64{"mss": 2, "ws": 3, "sack_perm": 4, "sack": 5, "ts": 8}
	got := map[string]uint64{}
	for outName, layout := range tcp.ParseStateMachine.AuxLayouts {
		if !layout.IsDynamicEligible {
			t.Errorf("aux %q has IsDynamicEligible = false; TLV-walk siblings should always be eligible", outName)
		}
		got[outName] = layout.DynamicKindByte
	}
	if len(got) != len(want) {
		t.Fatalf("got %d eligible auxes, want %d (got: %v)", len(got), len(want), got)
	}
	for name, kind := range want {
		gotKind, ok := got[name]
		if !ok {
			t.Errorf("missing aux %q", name)
			continue
		}
		if gotKind != kind {
			t.Errorf("aux %q DynamicKindByte = %d, want %d", name, gotKind, kind)
		}
	}
}

func TestLoadIpv4FieldLayout(t *testing.T) {
	specs := loadBundled(t)
	ipv4 := specs["ipv4"]
	if ipv4 == nil {
		t.Fatal("ipv4 not loaded")
	}
	if ipv4.HeaderName != "ipv4_h" {
		t.Errorf("HeaderName = %q", ipv4.HeaderName)
	}
	// Sum of bits must equal 160 (20 bytes) for the standard IPv4 base header.
	var total int
	for _, f := range ipv4.Fields {
		total += f.Bits
	}
	if total != 160 {
		t.Errorf("ipv4 total bits = %d, want 160", total)
	}
	if ipv4.Fields[0].Name != "version" || ipv4.Fields[0].Bits != 4 {
		t.Errorf("first field = %+v, want {version, 4}", ipv4.Fields[0])
	}
}

func TestLoadRejectsMismatchedSelfPrefix(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> x; }
const bit<8> BAR_ETH_PROTOCOL = 1;
parser F(packet_in pkt, out foo_h h) { state start { pkt.extract(h); transition accept; } }
`)},
	}
	if _, err := Load(fsys, "vocab"); err == nil {
		t.Fatal("expected error for mismatched self-prefix")
	}
}


func TestLoadRejectsConstOutsideNamingConvention(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> x; }
const bit<8> FOO_ONLY = 1;
parser F(packet_in pkt, out foo_h h) { state start { pkt.extract(h); transition accept; } }
`)},
	}
	if _, err := Load(fsys, "vocab"); err == nil {
		t.Fatal("expected error for const not matching any pattern")
	}
}

func TestLoadRejectsNoCheckFalse(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> x; }
const bool FOO_BAR_NO_CHECK = false;
parser F(packet_in pkt, out foo_h h) { state start { pkt.extract(h); transition accept; } }
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil {
		t.Fatal("expected error for NO_CHECK=false")
	}
	if !strings.Contains(err.Error(), "true") {
		t.Errorf("error should mention 'true': %v", err)
	}
}

func TestLoadRejectsFieldConstAsBool(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> x; }
const bool FOO_BAR_FIELD = true;
parser F(packet_in pkt, out foo_h h) { state start { pkt.extract(h); transition accept; } }
`)},
	}
	if _, err := Load(fsys, "vocab"); err == nil {
		t.Fatal("expected error for bool used in field dispatch")
	}
}

func TestLoadAcceptsAuxiliaryHeaders(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> x; }
header foo_opt_h { bit<8> y; }
parser F(packet_in pkt, out foo_h h, out foo_opt_h opt) {
  state start { pkt.extract(h); transition accept; }
}
`)},
	}
	specs, err := Load(fsys, "vocab")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if specs["foo"].HeaderName != "foo_h" {
		t.Errorf("primary header = %q, want foo_h", specs["foo"].HeaderName)
	}
	if len(specs["foo"].File.Headers) != 2 {
		t.Errorf("expected 2 headers in AST, got %d", len(specs["foo"].File.Headers))
	}
}

func TestLoadRejectsMissingPrimaryHeader(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header wrong_h { bit<8> x; }
parser F(packet_in pkt, out wrong_h h) { state start { pkt.extract(h); transition accept; } }
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil {
		t.Fatal("expected error for missing primary header foo_h")
	}
	if !strings.Contains(err.Error(), "foo_h") {
		t.Errorf("error should mention foo_h: %v", err)
	}
}

func TestLoadMaxDepthParses(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> x; }
const bit<8> FOO_MAX_DEPTH = 12;
parser F(packet_in pkt, out foo_h h) { state start { pkt.extract(h); transition accept; } }
`)},
	}
	specs, err := Load(fsys, "vocab")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := specs["foo"].MaxDepth; got != 12 {
		t.Errorf("MaxDepth = %d, want 12", got)
	}
	// MAX_DEPTH must not leak into the dispatch const list.
	for _, c := range specs["foo"].Consts {
		if strings.Contains(c.Name, "MAX_DEPTH") {
			t.Errorf("MAX_DEPTH leaked into Consts: %+v", c)
		}
	}
}

func TestLoadRejectsMaxDepthOutOfRange(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"zero", `const bit<8> FOO_MAX_DEPTH = 0;`, ">= 1"},
		{"overflow", `const bit<8> FOO_MAX_DEPTH = 200;`, "exceeds cap"},
		{"bool", `const bool FOO_MAX_DEPTH = true;`, "must be bit<N>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> x; }
` + tc.body + `
parser F(packet_in pkt, out foo_h h) { state start { pkt.extract(h); transition accept; } }
`)},
			}
			_, err := Load(fsys, "vocab")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want containing %q", err, tc.want)
			}
		})
	}
}

func TestLoadChainEndParses(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/mpls.p4": &fstest.MapFile{Data: []byte(`
header mpls_h { bit<20> label; bit<3> tc; bit<1> s; bit<8> ttl; }
const bit<1> MPLS_CHAIN_END_S = 1;
parser F(packet_in pkt, out mpls_h h) { state start { pkt.extract(h); transition accept; } }
`)},
	}
	specs, err := Load(fsys, "vocab")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ce := specs["mpls"].ChainEnd
	if ce == nil {
		t.Fatal("CHAIN_END const not parsed into ProtocolSpec.ChainEnd")
	}
	if ce.FieldName != "s" || ce.Value != 1 || ce.Bits != 1 {
		t.Errorf("ChainEnd = %+v; want field=s value=1 bits=1", ce)
	}
}

func TestLoadRejectsChainEndUnknownField(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> x; }
const bit<8> FOO_CHAIN_END_BOGUS = 1;
parser F(packet_in pkt, out foo_h h) { state start { pkt.extract(h); transition accept; } }
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("err = %v; want 'unknown field' diagnostic", err)
	}
}

func TestLoadRejectsDuplicateChainEnd(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> a; bit<8> b; }
const bit<8> FOO_CHAIN_END_A = 1;
const bit<8> FOO_CHAIN_END_B = 2;
parser F(packet_in pkt, out foo_h h) { state start { pkt.extract(h); transition accept; } }
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil || !strings.Contains(err.Error(), "duplicate CHAIN_END") {
		t.Fatalf("err = %v; want duplicate CHAIN_END diagnostic", err)
	}
}

func TestLoadRejectsBoolChainEnd(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<1> x; }
const bool FOO_CHAIN_END_X = true;
parser F(packet_in pkt, out foo_h h) { state start { pkt.extract(h); transition accept; } }
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil || !strings.Contains(err.Error(), "must be bit<N>") {
		t.Fatalf("err = %v; want bit<N> diagnostic", err)
	}
}

func TestLoadMplsBundledChainEnd(t *testing.T) {
	mpls := loadBundled(t)["mpls"]
	if mpls.ChainEnd == nil {
		t.Fatal("bundled MPLS_CHAIN_END_S should populate ProtocolSpec.ChainEnd")
	}
	if mpls.ChainEnd.FieldName != "s" || mpls.ChainEnd.Value != 1 || mpls.ChainEnd.Bits != 1 {
		t.Errorf("MPLS ChainEnd = %+v", mpls.ChainEnd)
	}
}

func TestLoadRejectsDuplicateMaxDepth(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> x; }
const bit<8> FOO_MAX_DEPTH = 4;
const bit<8> FOO_MAX_DEPTH = 8;
parser F(packet_in pkt, out foo_h h) { state start { pkt.extract(h); transition accept; } }
`)},
	}
	_, err := Load(fsys, "vocab")
	// Same const name twice — the generic dup-by-name check in
	// classifyConsts catches it before the MAX_DEPTH-specific path.
	if err == nil || !strings.Contains(err.Error(), "duplicate const") {
		t.Fatalf("err = %v; want duplicate-const error", err)
	}
}

func TestLoadRejectsDuplicateProtocolName(t *testing.T) {
	// fstest.MapFS is case-sensitive but our filenames are normalized to
	// lowercase. Simulate by creating two paths that normalize identically
	// after case-folding.
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> x; }
parser F(packet_in pkt, out foo_h h) { state start { pkt.extract(h); transition accept; } }
`)},
		"vocab/FOO.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> x; }
parser F(packet_in pkt, out foo_h h) { state start { pkt.extract(h); transition accept; } }
`)},
	}
	if _, err := Load(fsys, "vocab"); err == nil {
		t.Fatal("expected duplicate-name error")
	}
}

// --- ParseStateMachine ---

func TestParseStateMachineTrivialIsNil(t *testing.T) {
	// Protocols whose .p4 declares only `state start { extract(primary); transition accept; }`
	// must yield ProtocolSpec.ParseStateMachine == nil so codegen routes
	// them through the legacy fixed-size path. ipv4 / ipv6 self-validate
	// their version field and therefore carry a non-trivial parser
	// machine — they are exercised by TestIsSelfValidating instead.
	specs := loadBundled(t)
	// tcp's parser block is start + skip_options, so it is non-trivial.
	trivial := []string{"eth", "udp", "icmp", "icmp6"}
	for _, name := range trivial {
		sp, ok := specs[name]
		if !ok {
			t.Errorf("missing protocol %q in bundled vocab", name)
			continue
		}
		if sp.ParseStateMachine != nil {
			t.Errorf("protocol %q: expected ParseStateMachine == nil (trivial extract+accept), got %d states", name, len(sp.ParseStateMachine.States))
		}
	}
}

func TestParseStateMachineGtp(t *testing.T) {
	specs := loadBundled(t)
	gtp := specs["gtp"]
	if gtp == nil {
		t.Fatal("missing gtp spec")
	}
	if gtp.ParseStateMachine == nil {
		t.Fatal("expected gtp to have a non-trivial ParseStateMachine (it has optional + ext-chain states)")
	}
	machine := gtp.ParseStateMachine

	if got, want := len(machine.States), 3; got != want {
		t.Fatalf("state count = %d, want %d", got, want)
	}
	if machine.States[0].Name != "start" {
		t.Errorf("state[0] = %q, want start", machine.States[0].Name)
	}
	idx := machine.StateIdx
	if idx["start"] != 0 || idx["parse_opt"] < 1 || idx["parse_ext"] < 1 {
		t.Errorf("state index map missing expected entries: %+v", idx)
	}

	// start must be a tuple-select on (e,s,pn).
	start := machine.States[0]
	if start.Trans.Kind != TransSelect {
		t.Fatalf("start.Trans.Kind = %v, want TransSelect", start.Trans.Kind)
	}
	if got, want := len(start.Trans.Select.Keys), 3; got != want {
		t.Errorf("start select key count = %d, want %d (e,s,pn)", got, want)
	}
	for i, want := range []string{"e", "s", "pn"} {
		key := start.Trans.Select.Keys[i]
		if key.Kind != SelectKeyField {
			t.Errorf("start select key[%d] kind = %d, want SelectKeyField", i, key.Kind)
			continue
		}
		if key.Field.FieldName != want {
			t.Errorf("start select key[%d] = %q, want %q", i, key.Field.FieldName, want)
		}
	}

	// parse_ext must self-loop on next_ext != 0.
	pext := machine.States[idx["parse_ext"]]
	if pext.Trans.Kind != TransSelect {
		t.Fatalf("parse_ext.Trans.Kind = %v, want TransSelect", pext.Trans.Kind)
	}
	selfLoopFound := false
	for _, c := range pext.Trans.Select.Cases {
		if c.Target == idx["parse_ext"] {
			selfLoopFound = true
		}
	}
	// `default: parse_ext` may live in Default rather than a Case.
	if !selfLoopFound && pext.Trans.Select.Default != idx["parse_ext"] {
		t.Errorf("parse_ext has no self-loop edge; cases=%+v default=%d", pext.Trans.Select.Cases, pext.Trans.Select.Default)
	}

	// parse_ext extracts a stack push.
	if len(pext.Extracts) != 1 || !pext.Extracts[0].IsStackPush {
		t.Errorf("parse_ext extract = %+v, want one stack push", pext.Extracts)
	}

	// OffsetAtEntry: start arrives with R4 == layer entry (=0); parse_opt
	// runs after gtp_h (8 B); parse_ext runs after gtp_h + gtp_opt_h (12 B)
	// on the first iteration. Subsequent iterations of the parse_ext
	// self-loop have a dynamic per-iteration offset that the static model
	// does not capture; assignStateOffsets keeps the first-arrival value
	// since the conflict only arises on the self-edge.
	if got := machine.States[idx["start"]].OffsetAtEntry; got != 0 {
		t.Errorf("start.OffsetAtEntry = %d, want 0", got)
	}
	if got := machine.States[idx["parse_opt"]].OffsetAtEntry; got != 8 {
		t.Errorf("parse_opt.OffsetAtEntry = %d, want 8", got)
	}
	if got := pext.OffsetAtEntry; got != 12 {
		t.Errorf("parse_ext.OffsetAtEntry = %d, want 12", got)
	}

	// AuxLayouts: opt sits at offset 8, gated by E|S|PN bits (0x07
	// mask on byte 0 of gtp_h, NotEqual zero). exts is a stack so it
	// must be absent from AuxLayouts (PR-B handles header stacks).
	auxOpt, ok := machine.AuxLayouts["opt"]
	if !ok {
		t.Fatalf("AuxLayouts[opt] missing; got keys %v", auxLayoutNames(machine.AuxLayouts))
	}
	if auxOpt.HeaderName != "gtp_opt_h" {
		t.Errorf("aux opt: HeaderName = %q, want gtp_opt_h", auxOpt.HeaderName)
	}
	if auxOpt.OffsetInLayer != 8 {
		t.Errorf("aux opt: OffsetInLayer = %d, want 8", auxOpt.OffsetInLayer)
	}
	if auxOpt.HeaderSize != 4 {
		t.Errorf("aux opt: HeaderSize = %d, want 4", auxOpt.HeaderSize)
	}
	if auxOpt.Gating == nil {
		t.Fatal("aux opt: Gating is nil; want (byte 0 & 0x07) != 0")
	}
	if auxOpt.Gating.ByteOff != 0 || auxOpt.Gating.Mask != 0x07 || auxOpt.Gating.Op != GatingNe || auxOpt.Gating.Value != 0 {
		t.Errorf("aux opt Gating = %+v, want {ByteOff:0 Mask:0x07 Op:Ne Value:0}", auxOpt.Gating)
	}
	if _, ok := machine.AuxLayouts["exts"]; ok {
		t.Errorf("AuxLayouts[exts] should be absent (stack handled by StackRefs); got %+v", machine.AuxLayouts["exts"])
	}
}

func auxLayoutNames(m map[string]*AuxLayout) []string {
	if len(m) == 0 {
		return nil
	}
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	return names
}

func TestParseStateMachineSrv6(t *testing.T) {
	// 2 states: `start` extracts the SRH primary and transitions to
	// `skip_segments` on routing_type==4 (reject otherwise);
	// `skip_segments` runs the variable trail via pkt.advance and
	// accepts.
	specs := loadBundled(t)
	srv6 := specs["srv6"]
	if srv6 == nil || srv6.ParseStateMachine == nil {
		t.Fatal("expected srv6 to have a non-trivial ParseStateMachine")
	}
	machine := srv6.ParseStateMachine
	if len(machine.States) != 2 {
		t.Fatalf("srv6 state count = %d, want 2 (start + skip_segments)", len(machine.States))
	}
	start := machine.States[0]
	if start.Name != "start" {
		t.Errorf("states[0].Name = %q, want %q", start.Name, "start")
	}
	if start.Trans.Kind != TransSelect {
		t.Errorf("start transition kind = %v, want TransSelect (routing_type guard)", start.Trans.Kind)
	}
	skip := machine.States[1]
	if skip.Name != "skip_segments" {
		t.Errorf("states[1].Name = %q, want %q", skip.Name, "skip_segments")
	}
	if len(skip.Advances) != 1 {
		t.Fatalf("skip_segments advance count = %d, want 1", len(skip.Advances))
	}
	adv := skip.Advances[0]
	if adv.Kind != AdvanceOpField {
		t.Errorf("advance kind = %v, want AdvanceOpField", adv.Kind)
	}
	want := HeaderLength{LenByteOff: 1, LenMask: 0x0F, LenShift: 0, Scale: 8, Base: 0}
	if adv.Skip == nil || *adv.Skip != want {
		t.Errorf("skip = %+v, want %+v", adv.Skip, want)
	}
}

// TestIPv6ExtHeaderAnnotations pins the kunai-specific annotations
// on ipv6_ext_h: the variable-trail params replace the legacy
// codegen/parser_trail.go::knownVariableTails entry, and the writeback
// resolves ipv6.next_header to the correct byte offset (6) so the
// chain tail's next_header propagates to the parent layer.
func TestIPv6ExtHeaderAnnotations(t *testing.T) {
	specs := loadBundled(t)
	ipv6 := specs["ipv6"]
	if ipv6 == nil {
		t.Fatal("missing ipv6 spec")
	}
	ann, ok := ipv6.HeaderAnnotations["ipv6_ext_h"]
	if !ok || ann == nil {
		t.Fatal("ipv6_ext_h has no HeaderAnnotations")
	}
	wantVT := &VariableTailSpec{LenFieldByteOff: 1, LenMask: 0x03, LenShift: 0, Scale: 8, Base: 0}
	if ann.VariableTail == nil || *ann.VariableTail != *wantVT {
		t.Errorf("VariableTail = %+v, want %+v", ann.VariableTail, wantVT)
	}
	wantWB := &WriteBackSpec{
		SourceField:   "next_header",
		ParentProto:   "ipv6",
		ParentField:   "next_header",
		SourceByteOff: 0, // first field of ipv6_ext_h
		ParentByteOff: 6, // ipv6_h: version(4) + traffic_class(8) + flow_label(20) + payload_length(16) = 48 bits, then next_header
	}
	if ann.WriteBack == nil || *ann.WriteBack != *wantWB {
		t.Errorf("WriteBack = %+v, want %+v", ann.WriteBack, wantWB)
	}
}

func TestParseStateMachineRejectsMultiStateCycle(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> x; }
parser F(packet_in pkt, out foo_h h) {
  state start  { pkt.extract(h); transition s2; }
  state s2     { transition s3; }
  state s3     { transition s2; }
}
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil {
		t.Fatal("expected error for multi-state cycle s2 → s3 → s2")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("error should mention cycle: %v", err)
	}
}

func TestParseStateMachineAllowsSelfLoop(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h     { bit<8> next; }
header foo_ext_h { bit<8> next_ext; bit<24> _pad; }
parser F(packet_in pkt, out foo_h h, out foo_ext_h[8] exts) {
  state start { pkt.extract(h); transition parse_ext; }
  state parse_ext {
    pkt.extract(exts.next);
    transition select(exts.last.next_ext) { 0: accept; _: parse_ext; }
  }
}
`)},
	}
	specs, err := Load(fsys, "vocab")
	if err != nil {
		t.Fatalf("self-loop should be allowed: %v", err)
	}
	machine := specs["foo"].ParseStateMachine
	if machine == nil {
		t.Fatal("expected ParseStateMachine != nil for self-loop case")
	}
}

func TestParseStateMachineRejectsTooManyKeys(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> a; bit<8> b; bit<8> c; bit<8> d; }
parser F(packet_in pkt, out foo_h h) {
  state start {
    pkt.extract(h);
    transition select(h.a, h.b, h.c, h.d) { (0, 0, 0, 0): accept; default: reject; }
  }
}
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil {
		t.Fatal("expected error for select with 4 keys")
	}
	if !strings.Contains(err.Error(), "MVP cap") && !strings.Contains(err.Error(), "keys") {
		t.Errorf("error should mention key cap: %v", err)
	}
}

func TestParseStateMachineRejectsMissingStart(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> x; }
parser F(packet_in pkt, out foo_h h) {
  state begin { pkt.extract(h); transition accept; }
}
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil {
		t.Fatal("expected error for parser without `start` state")
	}
	if !strings.Contains(err.Error(), "start") {
		t.Errorf("error should mention start: %v", err)
	}
}

func TestParseStateMachineRejectsUnknownExtract(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> x; }
parser F(packet_in pkt, out foo_h h) {
  state start { pkt.extract(undeclared); transition accept; }
}
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil {
		t.Fatal("expected error for extract of undeclared variable")
	}
}

func TestParseStateMachineRejectsTupleArityMismatch(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> a; bit<8> b; }
parser F(packet_in pkt, out foo_h h) {
  state start {
    pkt.extract(h);
    transition select(h.a, h.b) { 0: accept; default: reject; }
  }
}
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil {
		t.Fatal("expected error for case with fewer values than keys")
	}
}

func indexByName(cs []DispatchConst) map[string]DispatchConst {
	m := make(map[string]DispatchConst, len(cs))
	for _, c := range cs {
		m[c.Name] = c
	}
	return m
}

func specNames(s map[string]*ProtocolSpec) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
}

// TestVariableTrailAbsentForFixedProtocols pins which protocols
// declare no Mechanism-1 (PrimaryAdvanceSkip) variable trailer.
// Adding such a trailer to a previously-fixed protocol changes
// codegen behaviour, so the test forces a deliberate update here
// when that happens.
//
// IPv4 used to declare a Mechanism-1 trailer
// (`pkt.advance(((bit<32>)(hdr.ihl - 5)) << 5)`) but moved to
// Mechanism 8 (ParserCounter byte-bounded walk) when option-aware
// extraction landed. TCP is the lone remaining Mechanism-1 user
// for its data_offset-driven trailer skip. SRv6 now declares its
// variable trail through pkt.advance in srv6.p4's skip_segments
// state, so it's omitted here too.
func TestVariableTrailAbsentForFixedProtocols(t *testing.T) {
	specs := loadBundled(t)
	for _, name := range []string{"eth", "ipv4", "ipv6", "udp", "gtp", "vlan", "qinq", "mpls", "gre", "vxlan", "geneve", "icmp", "icmp6", "cw"} {
		if vs := specs[name].PrimaryAdvanceSkip(); vs != nil {
			t.Errorf("%s should not declare a variable trailer (got %+v)", name, *vs)
		}
	}
}


// TestFlagTriggersGRE confirms the bundled GRE vocab declares the
// C/K/S optional-field triggers in declaration order so codegen
// advances R4 in the correct sequence (Checksum → Key → Sequence).
func TestFlagTriggersGRE(t *testing.T) {
	specs := loadBundled(t)
	gre := specs["gre"]
	if gre.FlagsByteOffset != 0 {
		t.Errorf("gre.FlagsByteOffset = %d, want 0", gre.FlagsByteOffset)
	}
	want := []FlagTrigger{
		{Name: "C", BitMask: 0x80, LenBytes: 4},
		{Name: "K", BitMask: 0x20, LenBytes: 4},
		{Name: "S", BitMask: 0x10, LenBytes: 4},
	}
	if len(gre.FlagTriggers) != len(want) {
		t.Fatalf("gre triggers: got %d, want %d (%+v)", len(gre.FlagTriggers), len(want), gre.FlagTriggers)
	}
	for i, w := range want {
		if gre.FlagTriggers[i] != w {
			t.Errorf("gre trigger[%d] = %+v, want %+v", i, gre.FlagTriggers[i], w)
		}
	}
}

// TestFlagTriggersAbsent guards against accidentally adding OPT_*
// constants to other protocols — codegen would silently advance R4
// past phantom optional fields.
func TestFlagTriggersAbsent(t *testing.T) {
	specs := loadBundled(t)
	for name, spec := range specs {
		if name == "gre" {
			continue
		}
		if len(spec.FlagTriggers) != 0 {
			t.Errorf("%s should declare no FlagTriggers (got %+v)", name, spec.FlagTriggers)
		}
	}
}

// TestFlagTriggerWithoutFlagsByteOffsetFails: declaring a TRIGGER/LEN
// pair without the FLAGS_BYTE_OFFSET anchor is meaningless because
// codegen has nowhere to read the bit.
func TestFlagTriggerWithoutFlagsByteOffsetFails(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> a; bit<8> b; bit<16> c; }
const bit<8> FOO_OPT_TRIGGER_X = 0x80;
const bit<8> FOO_OPT_LEN_X = 4;
parser F(packet_in pkt, out foo_h h) {
  state start { pkt.extract(h); transition accept; }
}
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil || !strings.Contains(err.Error(), "OPT_FLAGS_BYTE_OFFSET") {
		t.Fatalf("expected missing-FLAGS_BYTE_OFFSET error, got %v", err)
	}
}

// TestFlagTriggerLenWithoutTrigger pins the trigger ↔ length
// pairing — a dangling LEN_X is a configuration bug.
func TestFlagTriggerLenWithoutTrigger(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> a; bit<8> b; bit<16> c; }
const bit<8> FOO_OPT_FLAGS_BYTE_OFFSET = 0;
const bit<8> FOO_OPT_LEN_X = 4;
parser F(packet_in pkt, out foo_h h) {
  state start { pkt.extract(h); transition accept; }
}
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil || !strings.Contains(err.Error(), "OPT_TRIGGER_X") {
		t.Fatalf("expected missing-trigger error, got %v", err)
	}
}

// TestRejectsLegacyHDRLEN pins the loud rejection of any `HDRLEN_*`
// const family — the parser-block `pkt.advance` form is the single
// source of truth for variable trailers, and a silent fallthrough
// would let a stale vocab file compile to no trailer at all.
func TestRejectsLegacyHDRLEN(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<4> ver; bit<4> hdrlen; bit<8> b; bit<16> c; }
const bit<8> FOO_HDRLEN_BYTE_OFFSET = 0;
const bit<8> FOO_HDRLEN_MASK = 0x0F;
const bit<8> FOO_HDRLEN_SHIFT = 0;
const bit<8> FOO_HDRLEN_SCALE = 4;
const bit<8> FOO_HDRLEN_BASE = 4;
parser F(packet_in pkt, out foo_h h) {
  state start { pkt.extract(h); transition accept; }
}
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil || !strings.Contains(err.Error(), "HDRLEN_* const family is no longer supported") {
		t.Fatalf("expected HDRLEN retirement error, got %v", err)
	}
}

// TestParserBlockAdvanceLowersToHeaderLength pins the loader-side
// translation of `pkt.advance(((bit<32>)(hdr.<F> - K)) << S)` into
// the five-tuple HeaderLength shape codegen consumes — the
// load-bearing invariant connecting parser-block syntax to the
// variable-trail emit path.
func TestParserBlockAdvanceLowersToHeaderLength(t *testing.T) {
	cases := []struct {
		name string
		body string
		want HeaderLength
	}{
		{
			// TCP shape: data_offset (bit<4>) at byte 12 upper nibble,
			// 4-byte word scale, 5-word minimum (= 20-byte primary).
			"tcp_data_offset",
			`header foo_h {
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
			parser P(packet_in pkt, out foo_h hdr) {
				state start {
					pkt.extract(hdr);
					transition skip;
				}
				state skip {
					pkt.advance(((bit<32>)(hdr.data_offset - 5)) << 5);
					transition accept;
				}
			}`,
			HeaderLength{LenByteOff: 12, LenMask: 0xF0, LenShift: 4, Scale: 4, Base: 20},
		},
		{
			// IPv4 shape: ihl (bit<4>) at byte 0 lower nibble.
			"ipv4_ihl",
			`header foo_h { bit<4> version; bit<4> ihl; bit<8> tos; bit<16> total; }
			parser P(packet_in pkt, out foo_h hdr) {
				state start {
					pkt.extract(hdr);
					transition skip;
				}
				state skip {
					pkt.advance(((bit<32>)(hdr.ihl - 5)) << 5);
					transition accept;
				}
			}`,
			HeaderLength{LenByteOff: 0, LenMask: 0x0F, LenShift: 0, Scale: 4, Base: 20},
		},
		{
			// SRv6 shape: hdr_ext_len (bit<8>) at byte 1, masked with
			// 0x0F (= LenMask cap so verifier sees a static upper bound),
			// scale 8 bytes/unit (= S=6 in bits: << 6 means << 3 in bytes
			// after the scaleBytes = 1 << (S-3) normalisation), base 0.
			"srv6_hdr_ext_len_mask",
			`header foo_h { bit<8> next_header; bit<8> hdr_ext_len; bit<48> tail; }
			parser P(packet_in pkt, out foo_h hdr) {
				state start {
					pkt.extract(hdr);
					transition skip;
				}
				state skip {
					pkt.advance(((bit<32>)(hdr.hdr_ext_len & 0x0F)) << 6);
					transition accept;
				}
			}`,
			HeaderLength{LenByteOff: 1, LenMask: 0x0F, LenShift: 0, Scale: 8, Base: 0},
		},
		{
			// IPv6 ext header shape: hdr_ext_len (bit<8>) at byte 1,
			// masked with 0x03 (tighter cap than SRv6 — IPv6 ext headers
			// are typically ≤ 32 bytes in well-formed traffic), scale 8.
			"ipv6_ext_hdr_ext_len_mask",
			`header foo_h { bit<8> next_header; bit<8> hdr_ext_len; bit<48> tail; }
			parser P(packet_in pkt, out foo_h hdr) {
				state start {
					pkt.extract(hdr);
					transition skip;
				}
				state skip {
					pkt.advance(((bit<32>)(hdr.hdr_ext_len & 0x03)) << 6);
					transition accept;
				}
			}`,
			HeaderLength{LenByteOff: 1, LenMask: 0x03, LenShift: 0, Scale: 8, Base: 0},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"vocab/foo.p4": &fstest.MapFile{Data: []byte(tc.body)},
			}
			specs, err := Load(fsys, "vocab")
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			var spec *ProtocolSpec
			for _, s := range specs {
				spec = s
				break
			}
			if spec == nil || spec.ParseStateMachine == nil {
				t.Fatalf("no ParseStateMachine produced")
			}
			var advances []AdvanceOp
			for _, st := range spec.ParseStateMachine.States {
				advances = append(advances, st.Advances...)
			}
			if len(advances) != 1 {
				t.Fatalf("Advances=%d, want 1", len(advances))
			}
			got := *advances[0].Skip
			if got != tc.want {
				t.Errorf("Skip = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestParserBlockAdvanceRejects pins the load-time guards on
// pkt.advance: target must be the primary header, field must exist
// inside one byte, and the shift must give a whole-byte scale.
func TestParserBlockAdvanceRejects(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"unknown_field",
			`header foo_h { bit<8> a; }
parser P(packet_in pkt, out foo_h hdr) {
	state start { pkt.extract(hdr); transition skip; }
	state skip { pkt.advance(((bit<32>)(hdr.bogus - 5)) << 5); transition accept; }
}`,
			"unknown field",
		},
		{
			"sub_byte_shift",
			`header foo_h { bit<4> ver; bit<4> hdrlen; }
parser P(packet_in pkt, out foo_h hdr) {
	state start { pkt.extract(hdr); transition skip; }
	state skip { pkt.advance(((bit<32>)(hdr.hdrlen - 5)) << 2); transition accept; }
}`,
			"sub-byte",
		},
		{
			"extract_advance_mix",
			`header foo_h { bit<4> ver; bit<4> hdrlen; }
parser P(packet_in pkt, out foo_h hdr) {
	state start {
		pkt.extract(hdr);
		pkt.advance(((bit<32>)(hdr.hdrlen - 5)) << 5);
		transition accept;
	}
}`,
			"mixes pkt.extract with primary-targeted pkt.advance",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"vocab/foo.p4": &fstest.MapFile{Data: []byte(tc.body)},
			}
			_, err := Load(fsys, "vocab")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want containing %q", err, tc.want)
			}
		})
	}
}

// TestParserBlockAdvanceLookaheadLowering pins the loader-side
// translation of `pkt.advance(((bit<32>)pkt.lookahead<bit<16>>()[7:0]) << 3)`
// — the unknown-option length-skip form — into a HeaderLength with
// LenByteOff=1 (the length byte sits at R4+1 once the kind byte is
// the current cursor). Scale=1 byte, no minimum to subtract.
func TestParserBlockAdvanceLookaheadLowering(t *testing.T) {
	src := `header foo_h { bit<8> a; }
parser P(packet_in pkt, out foo_h hdr) {
	state start { pkt.extract(hdr); transition skip; }
	state skip {
		pkt.advance(((bit<32>)pkt.lookahead<bit<16>>()[7:0]) << 3);
		transition accept;
	}
}`
	fsys := fstest.MapFS{"vocab/foo.p4": &fstest.MapFile{Data: []byte(src)}}
	specs, err := Load(fsys, "vocab")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	skip := specs["foo"].ParseStateMachine.States[1]
	if len(skip.Advances) != 1 {
		t.Fatalf("Advances=%d, want 1", len(skip.Advances))
	}
	adv := skip.Advances[0]
	if adv.Kind != AdvanceOpLookahead {
		t.Fatalf("Kind=%d, want AdvanceOpLookahead", adv.Kind)
	}
	want := HeaderLength{LenByteOff: 1, LenMask: 0xFF, LenShift: 0, Scale: 1, Base: 0}
	if *adv.Skip != want {
		t.Errorf("Skip = %+v, want %+v", *adv.Skip, want)
	}
}

// TestParserBlockAdvanceLiteralLowering pins the literal-form
// `pkt.advance(8);` (NOP padding skip) into LiteralBytes=1.
func TestParserBlockAdvanceLiteralLowering(t *testing.T) {
	src := `header foo_h { bit<8> a; }
parser P(packet_in pkt, out foo_h hdr) {
	state start { pkt.extract(hdr); transition skip; }
	state skip { pkt.advance(8); transition accept; }
}`
	fsys := fstest.MapFS{"vocab/foo.p4": &fstest.MapFile{Data: []byte(src)}}
	specs, err := Load(fsys, "vocab")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	adv := specs["foo"].ParseStateMachine.States[1].Advances[0]
	if adv.Kind != AdvanceOpLiteral || adv.LiteralBytes != 1 {
		t.Errorf("adv = %+v, want Kind=AdvanceOpLiteral LiteralBytes=1", adv)
	}
}

// TestOwnedStackResolution pins the `out H[N] x` auto-binding rule
// the loader applies to declared-but-not-extracted stacks. A kind+
// length aux header `opt_h` followed by fixed-element `block_h`
// records is the canonical SACK-blocks layout: the parser-state
// shape `extract(opt); advance(opt.length...);` is the unique
// candidate sibling, so the loader binds `blocks` to owner `opt`
// with OffsetAfterOwner = 2 (= opt's HeaderSize in bytes).
func TestOwnedStackResolution(t *testing.T) {
	src := `header foo_h { bit<16> ethertype; }
header opt_h { bit<8> kind; bit<8> length; }
header block_h { bit<32> left; bit<32> right; }

const bit<16> FOO_ETH_ETHERTYPE = 0x88aa;

parser P(packet_in pkt, out foo_h hdr, out opt_h opt, out block_h[2] blocks) {
	state start {
		pkt.extract(hdr);
		transition parse_opt;
	}
	state parse_opt {
		pkt.extract(opt);
		pkt.advance(((bit<32>)(opt.length - 2)) << 3);
		transition accept;
	}
}`
	fsys := fstest.MapFS{"vocab/foo.p4": &fstest.MapFile{Data: []byte(src)}}
	specs, err := Load(fsys, "vocab")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	stack, ok := specs["foo"].ParseStateMachine.StackRefs["blocks"]
	if !ok {
		t.Fatalf("StackRefs[blocks] missing; got %+v", specs["foo"].ParseStateMachine.StackRefs)
	}
	if stack.OwnerOption != "opt" {
		t.Errorf("stack.OwnerOption = %q, want %q", stack.OwnerOption, "opt")
	}
	if stack.OffsetAfterOwner != 2 {
		t.Errorf("stack.OffsetAfterOwner = %d, want 2 (= opt header size)", stack.OffsetAfterOwner)
	}
}

// TestOwnedStackTopLevelUnchanged pins that stacks with no owner-
// candidate sibling stay top-level (OwnerOption empty). srv6.segments
// is the canonical case — declared but not extracted, anchored to
// the layer's variable trail rather than an option. Uses a select-
// based start (mirroring srv6's self-validating dispatch) so the
// loader keeps the ParseStateMachine non-nil instead of collapsing
// to the trivial single-state shape.
func TestOwnedStackTopLevelUnchanged(t *testing.T) {
	src := `header foo_h { bit<8> nh; bit<8> hdr_ext_len; bit<8> rt_type; bit<8> seg_left; bit<32> rsvd; }
header seg_h { bit<128> addr; }

const bit<8> FOO_IPV6_NEXT_HEADER = 43;

parser P(packet_in pkt, out foo_h hdr, out seg_h[8] segments) {
	state start {
		pkt.extract(hdr);
		transition select(hdr.rt_type) {
			4:       accept;
			default: reject;
		}
	}
}`
	fsys := fstest.MapFS{"vocab/foo.p4": &fstest.MapFile{Data: []byte(src)}}
	specs, err := Load(fsys, "vocab")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	stack, ok := specs["foo"].ParseStateMachine.StackRefs["segments"]
	if !ok {
		t.Fatalf("StackRefs[segments] missing")
	}
	if stack.OwnerOption != "" {
		t.Errorf("stack.OwnerOption = %q, want empty (top-level stack should not auto-bind)", stack.OwnerOption)
	}
	if stack.OffsetAfterOwner != 0 {
		t.Errorf("stack.OffsetAfterOwner = %d, want 0", stack.OffsetAfterOwner)
	}
}

// TestOwnedStackAmbiguousErrors pins that two sibling states matching
// the option-with-trailing-array shape force a loader error rather
// than a silent first-wins binding — at most one candidate per
// parser block.
func TestOwnedStackAmbiguousErrors(t *testing.T) {
	src := `header foo_h { bit<8> tag; }
header opt_a_h { bit<8> kind; bit<8> length; }
header opt_b_h { bit<8> kind; bit<8> length; }
header block_h { bit<32> left; bit<32> right; }

const bit<16> FOO_ETH_ETHERTYPE = 0x88ab;

parser P(packet_in pkt, out foo_h hdr, out opt_a_h opt_a, out opt_b_h opt_b, out block_h[2] blocks) {
	state start {
		pkt.extract(hdr);
		transition select(hdr.tag) {
			0:       parse_a;
			default: parse_b;
		}
	}
	state parse_a {
		pkt.extract(opt_a);
		pkt.advance(((bit<32>)(opt_a.length - 2)) << 3);
		transition accept;
	}
	state parse_b {
		pkt.extract(opt_b);
		pkt.advance(((bit<32>)(opt_b.length - 2)) << 3);
		transition accept;
	}
}`
	fsys := fstest.MapFS{"vocab/foo.p4": &fstest.MapFile{Data: []byte(src)}}
	_, err := Load(fsys, "vocab")
	if err == nil {
		t.Fatal("Load: expected ambiguous-owner error, got nil")
	}
	if !strings.Contains(err.Error(), "owner-bound ambiguous") {
		t.Errorf("err = %v; want containing %q", err, "owner-bound ambiguous")
	}
}

// TestParserBlockAdvanceLiteralRejects pins the load-time guards on
// the literal form: whole-byte advance and ≥ 1-byte minimum.
func TestParserBlockAdvanceLiteralRejects(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"sub_byte_literal", `pkt.advance(7);`, "sub-byte"},
		{"zero_literal", `pkt.advance(0);`, "at least 1 byte"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `header foo_h { bit<8> a; }
parser P(packet_in pkt, out foo_h hdr) {
	state start { pkt.extract(hdr); transition skip; }
	state skip { ` + tc.body + ` transition accept; }
}`
			fsys := fstest.MapFS{"vocab/foo.p4": &fstest.MapFile{Data: []byte(src)}}
			_, err := Load(fsys, "vocab")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want containing %q", err, tc.want)
			}
		})
	}
}

// TestParserBlockAdvanceLookaheadRejects pins the load-time guards
// on the lookahead form: byte-aligned slice required, whole-byte
// peek width required, whole-byte shift required.
func TestParserBlockAdvanceLookaheadRejects(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"non_byte_aligned_slice",
			`pkt.advance(((bit<32>)pkt.lookahead<bit<16>>()[3:0]) << 3);`,
			"select exactly 8 bits",
		},
		{
			"non_byte_boundary_lo",
			`pkt.advance(((bit<32>)pkt.lookahead<bit<16>>()[10:3]) << 3);`,
			"start at a byte boundary",
		},
		{
			"sub_byte_shift",
			`pkt.advance(((bit<32>)pkt.lookahead<bit<16>>()[7:0]) << 2);`,
			"sub-byte",
		},
		{
			"non_byte_lookahead_width",
			`pkt.advance(((bit<32>)pkt.lookahead<bit<12>>()[7:0]) << 3);`,
			"whole-byte width",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `header foo_h { bit<8> a; }
parser P(packet_in pkt, out foo_h hdr) {
	state start { pkt.extract(hdr); transition skip; }
	state skip { ` + tc.body + ` transition accept; }
}`
			fsys := fstest.MapFS{"vocab/foo.p4": &fstest.MapFile{Data: []byte(src)}}
			_, err := Load(fsys, "vocab")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want containing %q", err, tc.want)
			}
		})
	}
}

// TestSelectKeyLookaheadAccepted pins the load-time happy path for
// the new lookahead select key — the kind-byte dispatch shape TLV
// walks need. The vocab loader resolves it into a SelectKey with
// Kind=SelectKeyLookahead and Bits=8 so codegen can emit a
// no-advance peek-and-compare.
func TestSelectKeyLookaheadAccepted(t *testing.T) {
	src := `header foo_h { bit<8> a; }
parser P(packet_in pkt, out foo_h hdr) {
	state start {
		pkt.extract(hdr);
		transition select(pkt.lookahead<bit<8>>()) {
			0: accept;
			default: reject;
		}
	}
}`
	fsys := fstest.MapFS{"vocab/foo.p4": &fstest.MapFile{Data: []byte(src)}}
	specs, err := Load(fsys, "vocab")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	keys := specs["foo"].ParseStateMachine.States[0].Trans.Select.Keys
	if len(keys) != 1 {
		t.Fatalf("keys=%d, want 1", len(keys))
	}
	if keys[0].Kind != SelectKeyLookahead || keys[0].Bits != 8 {
		t.Errorf("key = %+v, want {Kind:SelectKeyLookahead Bits:8}", keys[0])
	}
}

// TestSelectKeyLookaheadRejectsNon8Bit pins the MVP cap: lookahead
// keys must be exactly 8 bits because codegen only knows how to
// emit a single-byte LDX for the peek. Wider widths would need
// multi-byte loads.
func TestSelectKeyLookaheadRejectsNon8Bit(t *testing.T) {
	src := `header foo_h { bit<8> a; }
parser P(packet_in pkt, out foo_h hdr) {
	state start {
		pkt.extract(hdr);
		transition select(pkt.lookahead<bit<16>>()) {
			0: accept;
			default: reject;
		}
	}
}`
	fsys := fstest.MapFS{"vocab/foo.p4": &fstest.MapFile{Data: []byte(src)}}
	_, err := Load(fsys, "vocab")
	if err == nil || !strings.Contains(err.Error(), "must be exactly 8 bits") {
		t.Fatalf("err = %v; want bit-width hint", err)
	}
}

// TestIsSelfValidating pins the parser-block self-check detection.
// True: ipv4 (transition select(hdr.version)), ipv6 (tuple-select
// over version + next_header), srv6 (routing_type). False: protocols
// with no parser machine (eth, tcp, udp) — they rely on Field/NoCheck
// dispatch from their parents.
func TestIsSelfValidating(t *testing.T) {
	specs := loadBundled(t)

	for _, name := range []string{"ipv4", "ipv6", "srv6"} {
		if !specs[name].IsSelfValidating() {
			t.Errorf("%s must report self-validating", name)
		}
	}
	for _, name := range []string{"eth", "tcp", "udp"} {
		s := specs[name]
		if s == nil {
			t.Fatalf("%s spec not loaded", name)
		}
		if s.IsSelfValidating() {
			t.Errorf("%s should not report self-validating (no non-trivial parser block)", name)
		}
	}
}

// TestRejectsParserMachinePlusOPT pins the same exclusivity for the
// OPT_TRIGGER family.
func TestRejectsParserMachinePlusOPT(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> a; bit<8> b; bit<16> c; }
const bit<8> FOO_OPT_FLAGS_BYTE_OFFSET = 0;
const bit<8> FOO_OPT_TRIGGER_X = 0x80;
const bit<8> FOO_OPT_LEN_X = 4;
parser F(packet_in pkt, out foo_h h) {
  state start {
    pkt.extract(h);
    transition select(h.a) { 1: accept; default: reject; }
  }
}
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil || !strings.Contains(err.Error(), "OPT_TRIGGER_") {
		t.Fatalf("expected layout exclusivity error, got %v", err)
	}
}

// TestRejectsSanityConstName pins that the SANITY family is gone:
// any const matching `<SELF>_[<PARENT>_]SANITY_<TYPE>` must fail at
// load with a pointer to parser-block self-validation. Without an
// explicit reject path the name would silently fall through to
// reField (parent="sanity", field="nibble") and become a Field
// dispatch — silent miss territory.
func TestRejectsSanityConstName(t *testing.T) {
	cases := []struct {
		name   string
		source string
	}{
		{
			name: "parent_specific",
			source: `
header foo_h { bit<8> a; bit<8> b; bit<16> c; }
const bit<4> FOO_BAR_SANITY_NIBBLE = 4;
parser F(packet_in pkt, out foo_h h) {
  state start { pkt.extract(h); transition accept; }
}
`,
		},
		{
			name: "parent_less",
			source: `
header foo_h { bit<8> a; bit<8> b; bit<16> c; }
const bit<4> FOO_SANITY_NIBBLE = 4;
parser F(packet_in pkt, out foo_h h) {
  state start { pkt.extract(h); transition accept; }
}
`,
		},
		{
			// `FOO_BAR_BAZ` looks like a multi-token parent name. The
			// previous regex (parent group `[A-Z0-9]+`) failed to match
			// these and let them slip through reField as silent Field
			// dispatches; the widened pattern catches them.
			name: "multi_token_parent",
			source: `
header foo_h { bit<8> a; bit<8> b; bit<16> c; }
const bit<4> FOO_BAR_BAZ_SANITY_NIBBLE = 4;
parser F(packet_in pkt, out foo_h h) {
  state start { pkt.extract(h); transition accept; }
}
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"vocab/foo.p4": &fstest.MapFile{Data: []byte(tc.source)},
			}
			_, err := Load(fsys, "vocab")
			if err == nil || !strings.Contains(err.Error(), "SANITY family") {
				t.Fatalf("expected SANITY-removal error, got %v", err)
			}
		})
	}
}

// TestRejectsDuplicateConstName pins that two consts with the same
// name on a vocab file fail at load — `SelectDispatchConst` would
// otherwise pick whichever copy came first and silently mask the
// typo. p4c-check normally catches this in valid P4-16, but kunai
// needs to fail loud even when consumed standalone.
func TestRejectsDuplicateConstName(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> a; bit<8> b; bit<16> c; }
const bit<16> FOO_ETH_ETHERTYPE = 0x0800;
const bit<16> FOO_ETH_ETHERTYPE = 0x86DD;
parser F(packet_in pkt, out foo_h h) {
  state start { pkt.extract(h); transition accept; }
}
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil || !strings.Contains(err.Error(), "duplicate const") {
		t.Fatalf("expected duplicate-const error, got %v", err)
	}
}

// TestRejectsDuplicateHeaderName pins that two headers with the
// same name fail at load. p4lite/parser.go appends to file.Headers
// without checking, so without this loop the second declaration
// would silently never load-bear anything.
func TestRejectsDuplicateHeaderName(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8>  a; bit<8> b; bit<16> c; }
header foo_h { bit<32> different; }
parser F(packet_in pkt, out foo_h h) {
  state start { pkt.extract(h); transition accept; }
}
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil || !strings.Contains(err.Error(), "duplicate header") {
		t.Fatalf("expected duplicate-header error, got %v", err)
	}
}

// --- ParserCounter integration ---

func TestLoadParserCounterRoundTrip(t *testing.T) {
	// Exercises every counter op: extern decl, instance, set +
	// decrement, and a counter-driven select. Foo→Bar dispatch
	// satisfies the cross-vocab namespace check.
	fsys := fstest.MapFS{
		"vocab/foo.p4":  &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> ihl; }
const bit<16> FOO_BAR_ETHERTYPE = 0x0800;

extern ParserCounter {
    ParserCounter();
    void set(in bit<8> value);
    void decrement(in bit<8> value);
    bool is_zero();
}

parser F(packet_in pkt, out foo_h h) {
    ParserCounter() pc;
    state start {
        pkt.extract(h);
        pc.set(((bit<8>)(h.ihl - 5)) << 3);
        transition wait;
    }
    state wait {
        transition select(pc.is_zero()) {
            true:  accept;
            false: consume;
        }
    }
    state consume {
        pkt.advance(8);
        pc.decrement(1);
        transition wait;
    }
}
`)},
		"vocab/bar.p4": &fstest.MapFile{Data: []byte(`
header bar_h { bit<48> dst; bit<48> src; bit<16> et; }
parser B(packet_in pkt, out bar_h h) { state start { pkt.extract(h); transition accept; } }
`)},
	}
	specs, err := Load(fsys, "vocab")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	foo, ok := specs["foo"]
	if !ok {
		t.Fatal("foo not loaded")
	}
	psm := foo.ParseStateMachine
	if psm == nil {
		t.Fatal("expected non-trivial ParseStateMachine for ParserCounter walk")
	}
	if len(psm.Counters) != 1 || psm.Counters[0].Name != "pc" {
		t.Fatalf("Counters = %+v, want one entry named pc", psm.Counters)
	}
	startCt := psm.States[psm.EntryIdx].Counters
	if len(startCt) != 1 || startCt[0].Kind != CounterOpSet || startCt[0].Counter != "pc" {
		t.Fatalf("start state Counters = %+v, want one CounterOpSet(pc)", startCt)
	}
	waitIdx, ok := psm.StateIdx["wait"]
	if !ok {
		t.Fatal("wait state missing")
	}
	wait := psm.States[waitIdx]
	if wait.Trans.Kind != TransSelect ||
		wait.Trans.Select == nil ||
		len(wait.Trans.Select.Keys) != 1 ||
		wait.Trans.Select.Keys[0].Kind != SelectKeyCounterIsZero ||
		wait.Trans.Select.Keys[0].Counter != "pc" {
		t.Errorf("wait transition = %+v, want CounterIsZero(pc) select", wait.Trans)
	}
	if !IsMultiStateLoopEntry(psm.States, waitIdx) {
		t.Errorf("wait should register as a multi-state loop entry (counter dispatch shape)")
	}
	consumeIdx := psm.StateIdx["consume"]
	consume := psm.States[consumeIdx]
	if len(consume.Counters) != 1 || consume.Counters[0].Kind != CounterOpDecrement ||
		consume.Counters[0].LiteralBytes != 1 {
		t.Errorf("consume Counters = %+v, want one CounterOpDecrement(pc, 1)", consume.Counters)
	}
}

func TestLoadParserCounterRejectsUndeclaredName(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> ihl; }
const bit<16> FOO_BAR_ETHERTYPE = 0x0800;

parser F(packet_in pkt, out foo_h h) {
    state start {
        pkt.extract(h);
        ghost.decrement(1);
        transition accept;
    }
}
`)},
		"vocab/bar.p4": &fstest.MapFile{Data: []byte(`
header bar_h { bit<48> a; bit<48> b; bit<16> c; }
parser B(packet_in pkt, out bar_h h) { state start { pkt.extract(h); transition accept; } }
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil || !strings.Contains(err.Error(), "not declared as a `ParserCounter()` instance") {
		t.Fatalf("expected undeclared-counter error, got %v", err)
	}
}

// TestLoadParserCounterTupleSelect pins the 2-key
// (counter.is_zero, lookahead<bit<8>>()) tuple shape that drives the
// canonical TNA byte-bounded TLV walk. The loader must recognise the
// entry as a multi-state self-loop entry, and dispatchKindForSibling
// must read the kind value from the tuple's second slot.
func TestLoadParserCounterTupleSelect(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h    { bit<8> ihl; }
header foo_ra_h { bit<8> kind; bit<8> length; bit<16> value; }
const bit<16> FOO_BAR_ETHERTYPE = 0x0800;
const bit<8>  FOO_MAX_DEPTH = 11;

extern ParserCounter {
    ParserCounter();
    void set(in bit<8> value);
    void decrement(in bit<8> value);
    bool is_zero();
}

parser F(packet_in pkt, out foo_h h, out foo_ra_h ra) {
    ParserCounter() pc;
    state start {
        pkt.extract(h);
        pc.set(((bit<8>)(h.ihl - 5)) << 5);
        transition select(h.ihl) {
            5:       accept;
            default: walk;
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
    state parse_router_alert { pkt.extract(ra); pc.decrement(4); transition walk; }
}
`)},
		"vocab/bar.p4": &fstest.MapFile{Data: []byte(`
header bar_h { bit<48> a; bit<48> b; bit<16> c; }
parser B(packet_in pkt, out bar_h h) { state start { pkt.extract(h); transition accept; } }
`)},
	}
	specs, err := Load(fsys, "vocab")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	psm := specs["foo"].ParseStateMachine
	if psm == nil {
		t.Fatal("expected non-trivial ParseStateMachine for tuple-select walk")
	}
	walkIdx, ok := psm.StateIdx["walk"]
	if !ok {
		t.Fatal("walk state missing")
	}
	if !IsMultiStateLoopEntry(psm.States, walkIdx) {
		t.Errorf("walk should register as a multi-state loop entry (2-key counter+lookahead shape)")
	}
	// Router Alert sibling must be reachable via kind=148. Confirms
	// dispatchKindForSibling reads the kind from the tuple's second
	// slot, not the counter slot.
	layout, ok := psm.AuxLayouts["ra"]
	if !ok || layout == nil {
		t.Fatal("ra AuxLayout missing")
	}
	if !layout.IsDynamicEligible {
		t.Errorf("ra should be IsDynamicEligible (extracted by sibling of multi-state loop)")
	}
	if layout.DynamicKindByte != 148 {
		t.Errorf("ra DynamicKindByte = %d, want 148", layout.DynamicKindByte)
	}
}

// TestLoadParserCounterDecrementFieldExpr pins the field-expr form of
// `<counter>.decrement(<aux>.<field>)`: the loader resolves the aux
// header out-param + field name to a byte offset within the aux
// header, populating CounterOp.DecrementByteOff. LiteralBytes stays
// zero. Synthetic shape mirrors the IPv4 RR layout (kind+length+
// pointer header + variable trailer) without depending on the
// production ipv4.p4.
func TestLoadParserCounterDecrementFieldExpr(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h    { bit<8> ihl; }
header foo_rr_h { bit<8> kind; bit<8> length; bit<8> pointer; }
const bit<16> FOO_BAR_ETHERTYPE = 0x0800;
const bit<8>  FOO_MAX_DEPTH = 11;

extern ParserCounter {
    ParserCounter();
    void set(in bit<8> value);
    void decrement(in bit<8> value);
    bool is_zero();
}

parser F(packet_in pkt, out foo_h h, out foo_rr_h rr) {
    ParserCounter() pc;
    state start {
        pkt.extract(h);
        pc.set(((bit<8>)(h.ihl - 5)) << 5);
        transition select(h.ihl) {
            5:       accept;
            default: walk;
        }
    }
    state walk {
        transition select(pc.is_zero(), pkt.lookahead<bit<8>>()) {
            (true,  _): accept;
            (false, 7): parse_record_route;
            (false, _): reject;
        }
    }
    state parse_record_route {
        pkt.extract(rr);
        pc.decrement(rr.length);
        transition walk;
    }
}
`)},
		"vocab/bar.p4": &fstest.MapFile{Data: []byte(`
header bar_h { bit<48> a; bit<48> b; bit<16> c; }
parser B(packet_in pkt, out bar_h h) { state start { pkt.extract(h); transition accept; } }
`)},
	}
	specs, err := Load(fsys, "vocab")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	psm := specs["foo"].ParseStateMachine
	stIdx := psm.StateIdx["parse_record_route"]
	st := psm.States[stIdx]
	if len(st.Counters) != 1 {
		t.Fatalf("parse_record_route Counters = %d, want 1", len(st.Counters))
	}
	op := st.Counters[0]
	if op.Kind != CounterOpDecrement {
		t.Errorf("op.Kind = %v, want CounterOpDecrement", op.Kind)
	}
	if op.LiteralBytes != 0 {
		t.Errorf("LiteralBytes = %d, want 0 (field-expr form)", op.LiteralBytes)
	}
	if op.DecrementTarget != "rr" || op.DecrementFieldName != "length" {
		t.Errorf("decrement = (%q, %q), want (rr, length)", op.DecrementTarget, op.DecrementFieldName)
	}
	if op.DecrementByteOff != 1 {
		t.Errorf("DecrementByteOff = %d, want 1 (length is byte 1 of foo_rr_h)", op.DecrementByteOff)
	}
}

// TestLoadParserCounterDecrementFieldExprRejectsPrimary guards the
// "aux only" rule for counter.decrement field-expr — primary-target
// decrements would need a different anchoring path (the counter is
// set from primary; decrement reads primary too is a redundant
// no-op). Reject loudly.
func TestLoadParserCounterDecrementFieldExprRejectsPrimary(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> ihl; }
const bit<16> FOO_BAR_ETHERTYPE = 0x0800;
const bit<8>  FOO_MAX_DEPTH = 11;

extern ParserCounter {
    ParserCounter();
    void set(in bit<8> value);
    void decrement(in bit<8> value);
    bool is_zero();
}

parser F(packet_in pkt, out foo_h h) {
    ParserCounter() pc;
    state start {
        pkt.extract(h);
        pc.set(((bit<8>)(h.ihl - 5)) << 5);
        pc.decrement(h.ihl);
        transition accept;
    }
}
`)},
		"vocab/bar.p4": &fstest.MapFile{Data: []byte(`
header bar_h { bit<48> a; bit<48> b; bit<16> c; }
parser B(packet_in pkt, out bar_h h) { state start { pkt.extract(h); transition accept; } }
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil {
		t.Fatal("expected error for primary-target counter.decrement field-expr")
	}
	if !strings.Contains(err.Error(), "primary header") {
		t.Errorf("err = %v; want 'primary header' hint", err)
	}
}

// TestLoadParserCounterRejectsReversedTuple guards the strict tuple
// order: (counter, lookahead) is accepted, the reversed
// (lookahead, counter) shape must reject so codegen invariants
// (probe counter first, branch on kind second) stay narrow.
// IsMultiStateLoopEntry returning false on the reversed shape leaves
// validateStateGraph with an unsupported cycle, so the loader's
// "no lowering for" error covers the symptom.
func TestLoadParserCounterRejectsReversedTuple(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> ihl; }
const bit<16> FOO_BAR_ETHERTYPE = 0x0800;
const bit<8>  FOO_MAX_DEPTH = 4;

extern ParserCounter {
    ParserCounter();
    void set(in bit<8> value);
    void decrement(in bit<8> value);
    bool is_zero();
}

parser F(packet_in pkt, out foo_h h) {
    ParserCounter() pc;
    state start {
        pkt.extract(h);
        pc.set(((bit<8>)(h.ihl - 5)) << 5);
        transition walk;
    }
    state walk {
        transition select(pkt.lookahead<bit<8>>(), pc.is_zero()) {
            (_,    true):  accept;
            (1,    false): parse_nop;
            (_,    _):     reject;
        }
    }
    state parse_nop { pkt.advance(8); pc.decrement(1); transition walk; }
}
`)},
		"vocab/bar.p4": &fstest.MapFile{Data: []byte(`
header bar_h { bit<48> a; bit<48> b; bit<16> c; }
parser B(packet_in pkt, out bar_h h) { state start { pkt.extract(h); transition accept; } }
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil {
		t.Fatal("expected Load to reject reversed (lookahead, counter) tuple")
	}
	if !strings.Contains(err.Error(), "no lowering for") {
		t.Errorf("expected 'no lowering for' diagnostic, got %v", err)
	}
}
