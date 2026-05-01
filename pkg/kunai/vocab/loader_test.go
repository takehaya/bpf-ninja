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

func TestLoadIpv4GtpSanity(t *testing.T) {
	ipv4 := loadBundled(t)["ipv4"]
	dc, ok := indexByName(ipv4.Consts)["IPV4_GTP_SANITY_NIBBLE"]
	if !ok {
		t.Fatal("IPV4_GTP_SANITY_NIBBLE not found")
	}
	if dc.Type != DispatchSanity || dc.Parent != "gtp" || dc.SanityType != "NIBBLE" || dc.Value != 4 {
		t.Errorf("const = %+v", dc)
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

func TestLoadIpv4MplsSanity(t *testing.T) {
	specs := loadBundled(t)
	ipv4 := specs["ipv4"]
	if ipv4 == nil {
		t.Fatal("ipv4 not loaded")
	}
	dc, ok := indexByName(ipv4.Consts)["IPV4_MPLS_SANITY_NIBBLE"]
	if !ok {
		t.Fatal("IPV4_MPLS_SANITY_NIBBLE not found")
	}
	if dc.Type != DispatchSanity || dc.Parent != "mpls" || dc.SanityType != "NIBBLE" || dc.Value != 4 || dc.Bits != 4 {
		t.Errorf("sanity const = %+v", dc)
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

func TestLoadTcpOptionWalk(t *testing.T) {
	specs := loadBundled(t)
	tcp := specs["tcp"]
	if tcp == nil {
		t.Fatal("tcp not loaded")
	}
	if tcp.OptionWalk == nil {
		t.Fatal("tcp.OptionWalk is nil; expected option-walk metadata after declaring <PROTO>_OPT_<NAME>_KIND/SIZE")
	}
	walk := tcp.OptionWalk
	if walk.TerminatorKind != 0 || walk.PaddingKind != 1 || walk.LengthByteOff != 1 {
		t.Errorf("walk skeleton = {term=%d, pad=%d, lenOff=%d}, want {0,1,1}", walk.TerminatorKind, walk.PaddingKind, walk.LengthByteOff)
	}
	wantNames := map[string]struct {
		kind uint64
		size int
	}{
		"MSS":       {2, 4},
		"WS":        {3, 3},
		"SACK_PERM": {4, 2},
		"TS":        {8, 10},
	}
	if len(walk.Options) != len(wantNames) {
		t.Fatalf("got %d options, want %d", len(walk.Options), len(wantNames))
	}
	for _, opt := range walk.Options {
		want, ok := wantNames[opt.Name]
		if !ok {
			t.Errorf("unexpected option %q", opt.Name)
			continue
		}
		if opt.Kind != want.kind || opt.Size != want.size {
			t.Errorf("option %q = {kind=%d, size=%d}, want {%d, %d}", opt.Name, opt.Kind, opt.Size, want.kind, want.size)
		}
		if opt.HeaderRef == nil {
			t.Errorf("option %q has nil HeaderRef", opt.Name)
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
	// them through the legacy fixed-size path.
	specs := loadBundled(t)
	trivial := []string{"eth", "ipv4", "tcp", "udp", "icmp", "icmp6"}
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
		if start.Trans.Select.Keys[i].FieldName != want {
			t.Errorf("start select key[%d] = %q, want %q", i, start.Trans.Select.Keys[i].FieldName, want)
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
	specs := loadBundled(t)
	srv6 := specs["srv6"]
	if srv6 == nil || srv6.ParseStateMachine == nil {
		t.Fatal("expected srv6 to have a non-trivial ParseStateMachine (single state with a routing_type select)")
	}
	machine := srv6.ParseStateMachine
	if len(machine.States) != 1 {
		t.Fatalf("srv6 state count = %d, want 1", len(machine.States))
	}
	state := machine.States[0]
	if state.Trans.Kind != TransSelect {
		t.Errorf("srv6 transition kind = %v, want TransSelect (routing_type guard)", state.Trans.Kind)
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

// TestVariableSuffixIPv4 confirms the bundled IPv4 vocab declares the
// VAREXT_LEN five-tuple correctly so codegen can advance past
// options when IHL > 5. The numeric values are pinned because
// codegen depends on them — nudging them silently would shift R4.
func TestVariableSuffixIPv4(t *testing.T) {
	specs := loadBundled(t)
	vs := specs["ipv4"].VariableSuffix
	if vs == nil {
		t.Fatal("ipv4 must declare a VariableSuffix")
	}
	if vs.LenByteOff != 0 || vs.LenMask != 0x0F || vs.LenShift != 0 ||
		vs.Scale != 4 || vs.Base != 20 {
		t.Errorf("unexpected ipv4 VariableSuffix: %+v", *vs)
	}
}

// TestVariableSuffixTCP confirms the TCP data_offset upper-nibble
// shape — the shift is what distinguishes it from IPv4 IHL.
func TestVariableSuffixTCP(t *testing.T) {
	specs := loadBundled(t)
	vs := specs["tcp"].VariableSuffix
	if vs == nil {
		t.Fatal("tcp must declare a VariableSuffix")
	}
	if vs.LenByteOff != 12 || vs.LenMask != 0xF0 || vs.LenShift != 4 ||
		vs.Scale != 4 || vs.Base != 20 {
		t.Errorf("unexpected tcp VariableSuffix: %+v", *vs)
	}
}

// TestVariableSuffixAbsentForFixedProtocols pins which protocols do
// NOT declare a VariableSuffix — adding VAREXT to a previously-fixed
// protocol changes codegen behaviour, so the test forces a deliberate
// update here when that happens.
func TestVariableSuffixAbsentForFixedProtocols(t *testing.T) {
	specs := loadBundled(t)
	for _, name := range []string{"eth", "ipv6", "udp", "gtp", "srv6", "vlan", "qinq", "mpls", "gre", "vxlan", "geneve", "icmp", "icmp6", "cw"} {
		if specs[name].VariableSuffix != nil {
			t.Errorf("%s should not declare a VariableSuffix (got %+v)", name, *specs[name].VariableSuffix)
		}
	}
}

// TestVariableSuffixIncomplete rejects partial declarations: a
// VAREXT_LEN_BYTE_OFFSET without the rest is a configuration bug,
// not a "best-effort" behaviour.
func TestVariableSuffixIncomplete(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> a; bit<8> b; bit<16> c; }
const bit<8> FOO_VAREXT_LEN_BYTE_OFFSET = 0;
const bit<8> FOO_VAREXT_LEN_MASK = 0x0F;
parser F(packet_in pkt, out foo_h h) {
  state start { pkt.extract(h); transition accept; }
}
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("expected incomplete-VAREXT error, got %v", err)
	}
}

// TestVariableSuffixUnknownSuffix rejects an unrecognised key like
// VAREXT_LEN_FOO so typos surface immediately.
func TestVariableSuffixUnknownSuffix(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> a; bit<8> b; bit<16> c; }
const bit<8> FOO_VAREXT_LEN_FOO = 0;
parser F(packet_in pkt, out foo_h h) {
  state start { pkt.extract(h); transition accept; }
}
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil || !strings.Contains(err.Error(), "unknown suffix") {
		t.Fatalf("expected unknown-suffix error, got %v", err)
	}
}

// TestVariableSuffixBaseMustEqualHeaderSize: Base != header bytes is
// a logical error — the codegen subtracts Base from total to get the
// trailer length, so any mismatch means the vocab and codegen
// disagree about where the fixed prefix ends.
func TestVariableSuffixBaseMustEqualHeaderSize(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> a; bit<8> b; bit<16> c; }
const bit<8> FOO_VAREXT_LEN_BYTE_OFFSET = 0;
const bit<8> FOO_VAREXT_LEN_MASK = 0x0F;
const bit<8> FOO_VAREXT_LEN_SHIFT = 0;
const bit<8> FOO_VAREXT_LEN_SCALE = 4;
const bit<8> FOO_VAREXT_LEN_BASE = 8;
parser F(packet_in pkt, out foo_h h) {
  state start { pkt.extract(h); transition accept; }
}
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil || !strings.Contains(err.Error(), "primary header size") {
		t.Fatalf("expected base-mismatch error, got %v", err)
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

// TestRejectsParserMachinePlusVAREXT pins the layout exclusivity
// invariant: vocab cannot declare both a non-trivial parser block
// (which already expresses aux extracts) AND a primary-header
// VAREXT_LEN trailer. Codegen would silently ignore the trailer
// because genLayerInner dispatches on ParseStateMachine first.
func TestRejectsParserMachinePlusVAREXT(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> a; bit<8> b; bit<16> c; }
const bit<8> FOO_VAREXT_LEN_BYTE_OFFSET = 0;
const bit<8> FOO_VAREXT_LEN_MASK = 0x0F;
const bit<8> FOO_VAREXT_LEN_SHIFT = 0;
const bit<8> FOO_VAREXT_LEN_SCALE = 4;
const bit<8> FOO_VAREXT_LEN_BASE = 4;
parser F(packet_in pkt, out foo_h h) {
  state start {
    pkt.extract(h);
    transition select(h.a) { 1: accept; default: reject; }
  }
}
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil || !strings.Contains(err.Error(), "VAREXT_LEN_") {
		t.Fatalf("expected layout exclusivity error, got %v", err)
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

// TestVariableSuffixScaleMustBePowerOfTwo: codegen lowers the
// `* Scale` step to a left-shift table, so non-power-of-two values
// or values past 128 break the emit.
func TestVariableSuffixScaleMustBePowerOfTwo(t *testing.T) {
	fsys := fstest.MapFS{
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(`
header foo_h { bit<8> a; bit<8> b; bit<16> c; }
const bit<8> FOO_VAREXT_LEN_BYTE_OFFSET = 0;
const bit<8> FOO_VAREXT_LEN_MASK = 0x0F;
const bit<8> FOO_VAREXT_LEN_SHIFT = 0;
const bit<8> FOO_VAREXT_LEN_SCALE = 3;
const bit<8> FOO_VAREXT_LEN_BASE = 4;
parser F(packet_in pkt, out foo_h h) {
  state start { pkt.extract(h); transition accept; }
}
`)},
	}
	_, err := Load(fsys, "vocab")
	if err == nil || !strings.Contains(err.Error(), "power of two") {
		t.Fatalf("expected scale-power-of-two error, got %v", err)
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
