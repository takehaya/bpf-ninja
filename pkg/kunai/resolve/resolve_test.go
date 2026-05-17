package resolve

import (
	"strings"
	"testing"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/dslvocab"
	xdphost "github.com/takehaya/xdp-ninja/pkg/kunai/host/xdp"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/parser"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

func loadVocab(t *testing.T) map[string]*vocab.ProtocolSpec {
	t.Helper()
	v, err := dslvocab.Bundled()
	if err != nil {
		t.Fatalf("load vocab: %v", err)
	}
	return v
}

// xdpTestActions points at the canonical XDP action map shipped by
// the host/xdp adapter so this test keeps its action symbols in sync
// with what real hosts use. Tests that exercise `where action == XDP_*`
// atoms pass it to resolveOK / resolveErr; non-action tests pass nil
// so action atoms are rejected.
var xdpTestActions = xdphost.Actions

func resolveOK(t *testing.T, expr string, actions map[string]int32) *ir.Program {
	t.Helper()
	f, err := parser.Parse(expr, "t.dsl", reservedFromActions(actions))
	if err != nil {
		t.Fatalf("parse(%q): %v", expr, err)
	}
	p, err := Resolve(f, loadVocab(t), actions)
	if err != nil {
		t.Fatalf("resolve(%q): %v", expr, err)
	}
	return p
}

func resolveErr(t *testing.T, expr string, actions map[string]int32, wantContains string) {
	t.Helper()
	f, err := parser.Parse(expr, "t.dsl", reservedFromActions(actions))
	if err != nil {
		t.Fatalf("parse(%q): %v", expr, err)
	}
	_, err = Resolve(f, loadVocab(t), actions)
	if err == nil {
		t.Fatalf("resolve(%q): expected error", expr)
	}
	if wantContains != "" && !strings.Contains(err.Error(), wantContains) {
		t.Errorf("resolve(%q) error = %v; want contains %q", expr, err, wantContains)
	}
}

// reservedFromActions mirrors kunai.Compile's auto-derivation: parser
// gets a label-rejection set built from action map keys. Lives in
// the test rather than as a kunai-package export because resolve is
// below the kunai-package layer in the import graph.
func reservedFromActions(actions map[string]int32) map[string]bool {
	if actions == nil {
		return nil
	}
	out := make(map[string]bool, len(actions))
	for k := range actions {
		out[k] = true
	}
	return out
}

func TestResolveSimpleChain(t *testing.T) {
	p := resolveOK(t, "eth/ipv4/tcp", nil)
	if len(p.Layers) != 3 {
		t.Fatalf("layers==%d", len(p.Layers))
	}
	if p.Layers[0].Spec.Name != "eth" {
		t.Errorf("layer0 = %q", p.Layers[0].Spec.Name)
	}
	if p.Layers[0].Dispatch != nil {
		t.Errorf("root layer should have no dispatch: %+v", p.Layers[0].Dispatch)
	}
	ipv4Dispatch := p.Layers[1].Dispatch
	if ipv4Dispatch == nil || ipv4Dispatch.Const.Name != "IPV4_ETH_ETHERTYPE" || ipv4Dispatch.Const.Value != 0x0800 {
		t.Errorf("ipv4 dispatch = %+v", ipv4Dispatch)
	}
	tcpDispatch := p.Layers[2].Dispatch
	if tcpDispatch == nil || tcpDispatch.Const.Name != "TCP_IPV4_PROTOCOL" || tcpDispatch.Const.Value != 6 {
		t.Errorf("tcp dispatch = %+v", tcpDispatch)
	}
}

func TestChainRootWarning(t *testing.T) {
	// Standard L2 entry (root == eth) must NOT raise a warning.
	p := resolveOK(t, "eth/ipv4/tcp", nil)
	if len(p.Warnings) != 0 {
		t.Errorf("eth/ipv4/tcp: unexpected warnings: %v", p.Warnings)
	}

	// Bare non-eth root SHOULD warn. The chain itself still resolves
	// — non-eth roots are valid for tunnels / raw-IP capture, just
	// rarely what users mean.
	p2 := resolveOK(t, "tcp", nil)
	if len(p2.Warnings) == 0 {
		t.Fatalf("tcp: expected chain root warning, got none")
	}
	if !strings.Contains(p2.Warnings[0], "chain root") || !strings.Contains(p2.Warnings[0], "eth") {
		t.Errorf("warning message lacks expected substrings: %q", p2.Warnings[0])
	}

	// ipv4-root (without eth) is the canonical "I forgot eth/" case
	// and must also warn.
	p3 := resolveOK(t, "ipv4/tcp", nil)
	if len(p3.Warnings) == 0 {
		t.Fatalf("ipv4/tcp: expected chain root warning, got none")
	}
}

func TestResolveIPv6Chain(t *testing.T) {
	p := resolveOK(t, "eth/ipv6/tcp", nil)
	// tcp is dual-declared; under ipv6 we expect TCP_IPV6_NEXT_HEADER==6.
	tcp := p.Layers[2].Dispatch
	if tcp == nil || tcp.Const.Name != "TCP_IPV6_NEXT_HEADER" {
		t.Errorf("tcp dispatch = %+v", tcp)
	}
}

func TestResolveGtpChainUsesSelfValidating(t *testing.T) {
	// gtp has GTP_UDP_DPORT==2152 (field dispatch from udp); ipv4 under
	// gtp resolves via DispatchSelfValidating because gtp has no type
	// field and ipv4's parser block validates `version == 4` itself.
	p := resolveOK(t, "eth/ipv4/udp/gtp/ipv4/tcp", nil)
	gtp := p.Layers[3].Dispatch
	if gtp == nil || gtp.Const.Name != "GTP_UDP_DPORT" || gtp.Const.Value != 2152 {
		t.Errorf("gtp dispatch = %+v", gtp)
	}
	innerIPv4 := p.Layers[4].Dispatch
	if innerIPv4 == nil || innerIPv4.Type != vocab.DispatchSelfValidating || innerIPv4.Const != nil {
		t.Errorf("inner ipv4 dispatch = %+v, want DispatchSelfValidating with nil Const", innerIPv4)
	}
}

func TestResolveAutoIndex(t *testing.T) {
	p := resolveOK(t, "eth/ipv4/udp/gtp/ipv4/tcp", nil)
	outer := p.Layers[1]
	inner := p.Layers[4]
	if outer.Spec.Name != "ipv4" || outer.Index != 0 {
		t.Errorf("outer = %+v", outer)
	}
	if inner.Spec.Name != "ipv4" || inner.Index != 1 {
		t.Errorf("inner = %+v", inner)
	}
	// Both auto keys should be registered in LabelTable.
	if _, ok := p.LabelTable["ipv4#0"]; !ok {
		t.Error("ipv4#0 not registered")
	}
	if _, ok := p.LabelTable["ipv4#1"]; !ok {
		t.Error("ipv4#1 not registered")
	}
}

func TestResolveExplicitLabels(t *testing.T) {
	p := resolveOK(t, "eth/ipv4@outer/udp/gtp/ipv4@inner/tcp", nil)
	outer := p.LabelTable["outer"]
	inner := p.LabelTable["inner"]
	if outer == nil || inner == nil {
		t.Fatal("labels not registered")
	}
	if outer.Index != 0 || inner.Index != 1 {
		t.Errorf("indexes %d / %d", outer.Index, inner.Index)
	}
	if outer.Label != "outer" || inner.Label != "inner" {
		t.Errorf("labels %q / %q", outer.Label, inner.Label)
	}
}

func TestResolveDuplicateLabelRejected(t *testing.T) {
	resolveErr(t, "eth/ipv4@foo/udp/ipv4@foo/tcp", nil, "duplicate label")
}

func TestResolveLabelCollidesWithProto(t *testing.T) {
	// "ipv4" is a protocol name; using it as a label must fail.
	resolveErr(t, "eth/udp@ipv4/tcp", nil, "collides with protocol")
}

func TestResolveMvpLabelCap(t *testing.T) {
	// Three user-labeled ipv4 instances exceed the MVP cap of 2.
	// GTP-in-GTP nesting is unusual at runtime but valid for resolver checks.
	resolveErr(t, "eth/ipv4@a/udp/gtp/ipv4@b/udp/gtp/ipv4@c/tcp", nil, "MVP supports up to 2")
}

func TestResolveUnknownProtocol(t *testing.T) {
	resolveErr(t, "eth/bogus/tcp", nil, `unknown protocol "bogus"`)
}

func TestResolveUnknownField(t *testing.T) {
	resolveErr(t, "eth/ipv4[bogus==1]/tcp", nil, `has no field "bogus"`)
}

func TestResolveMissingDispatch(t *testing.T) {
	// tcp has no TCP_ETH_* dispatch constant and no parent-less
	// sanity, so "tcp directly under eth" must fail.
	resolveErr(t, "eth/tcp", nil, "no dispatch constant")
}

func TestResolveRejectsValueWiderThanField(t *testing.T) {
	// tcp.dport is 16 bits; 99999 does not fit.
	resolveErr(t, "eth/ipv4/tcp[dport==99999]", nil, "does not fit")
}

func TestResolvePredicateField(t *testing.T) {
	p := resolveOK(t, "eth/ipv4/tcp[dport==443]", nil)
	tcp := p.Layers[2]
	if len(tcp.Predicates) != 1 {
		t.Fatalf("preds==%d", len(tcp.Predicates))
	}
	pr := tcp.Predicates[0]
	if pr.Field == nil || pr.Field.Field.Name != "dport" || pr.Field.Layer != tcp {
		t.Errorf("pred field = %+v", pr.Field)
	}
	if pr.Op != ast.CmpEq || pr.Value.Int != 443 {
		t.Errorf("pred op/value = %v / %+v", pr.Op, pr.Value)
	}
}

func TestResolveBracketAuxField(t *testing.T) {
	// `gtp[opt.next_ext == 0]`: aux field via bracket form. The
	// resolver should produce a FieldRef with Aux populated, the
	// gating coming from the parser block (E|S|PN gate on byte 0).
	p := resolveOK(t, "eth/ipv4/udp/gtp[opt.next_ext==0]/ipv4/tcp", nil)
	gtp := p.Layers[3]
	if len(gtp.Predicates) != 1 {
		t.Fatalf("expected 1 predicate on gtp, got %d", len(gtp.Predicates))
	}
	pr := gtp.Predicates[0]
	if pr.Field == nil || pr.Field.Aux == nil {
		t.Fatalf("expected pred with Aux set, got %+v", pr.Field)
	}
	aux := pr.Field.Aux
	if aux.OutParam != "opt" || aux.HeaderName != "gtp_opt_h" {
		t.Errorf("aux = %+v", aux)
	}
	if aux.OffsetInLayer != 8 || aux.HeaderSize != 4 {
		t.Errorf("aux offset/size = %d/%d, want 8/4", aux.OffsetInLayer, aux.HeaderSize)
	}
	if aux.Gating == nil || aux.Gating.Mask != 0x07 {
		t.Errorf("aux gating = %+v, want mask 0x07", aux.Gating)
	}
	if aux.FieldBitOff != 24 || aux.FieldBitWidth != 8 {
		t.Errorf("field window = (%d, %d), want (24, 8)", aux.FieldBitOff, aux.FieldBitWidth)
	}
}

func TestResolveWhereAuxField(t *testing.T) {
	// `where gtp.opt.next_ext == 0`: 3-part path in where clause.
	p := resolveOK(t, "eth/ipv4/udp/gtp/ipv4/tcp where gtp.opt.next_ext == 0", nil)
	if p.Where == nil {
		t.Fatal("where condition missing")
	}
	// Walk to the leaf comparison and check its Field.Aux is populated.
	leaf := p.Where
	for leaf.Left != nil || leaf.Inner != nil {
		switch {
		case leaf.Left != nil:
			leaf = leaf.Left
		case leaf.Inner != nil:
			leaf = leaf.Inner
		}
	}
	if leaf.ArithL == nil || leaf.ArithL.Field == nil || leaf.ArithL.Field.Aux == nil {
		t.Fatalf("leaf condition has no Aux field ref: %+v", leaf)
	}
	if leaf.ArithL.Field.Aux.OutParam != "opt" {
		t.Errorf("aux out param = %q, want opt", leaf.ArithL.Field.Aux.OutParam)
	}
}

func TestResolveAuxStackRejectsSinglePath(t *testing.T) {
	// Stack auxes (gtp.exts) need an index inside a bracket
	// predicate. Without one the resolver suggests `[N]` or a
	// surrounding any/all.
	resolveErr(t, "eth/ipv4/udp/gtp[exts.next_ext==0]/ipv4/tcp", nil, "needs an index")
}

func TestResolvePredicateInIntegerAcceptsResolve(t *testing.T) {
	// F7 landed: integer alternatives now resolve cleanly. The
	// predicate is no longer flagged Unsupported.
	p := resolveOK(t, "eth/ipv4/tcp[dport in [80, 443]]", nil)
	pr := p.Layers[2].Predicates[0]
	if pr.Unsupported != "" {
		t.Errorf("PredIn integer should NOT be Unsupported, got %q", pr.Unsupported)
	}
	if len(pr.List) != 2 {
		t.Errorf("List length = %d, want 2", len(pr.List))
	}
}

func TestResolvePredicateHasMarksUnsupported(t *testing.T) {
	p := resolveOK(t, "eth/ipv4/tcp[flags has SYN]", nil)
	if got := p.Layers[2].Predicates[0].Unsupported; got == "" {
		t.Error("PredHas should be marked Unsupported")
	}
}

func TestResolveAlternationResolves(t *testing.T) {
	// Alternatives resolve (each is a valid protocol) and the group
	// is not flagged Unsupported because codegen can emit it.
	p := resolveOK(t, "eth/(vlan|qinq)", nil)
	alt := p.Layers[1]
	if alt.Unsupported != "" {
		t.Errorf("alternation group should not be Unsupported, got %q", alt.Unsupported)
	}
	if len(alt.Alternation) != 2 {
		t.Errorf("alt count==%d", len(alt.Alternation))
	}
}

func TestResolveAlternationNestedFlattens(t *testing.T) {
	// P3-13: nested alt groups are equivalent to a flat alt because
	// alt members are single layers without their own chain /
	// quantifier / predicate (= grouping has no extra semantic).
	// The resolver flattens `((a|b)|c)` into `(a|b|c)` so codegen
	// sees a 3-way alt and runs the existing P3-12 path.
	for _, tc := range []struct {
		expr     string
		wantLeaf []string
	}{
		// Outer-2 with one nested-2 + one leaf → flat 3.
		{"eth/((vlan|qinq)|ipv4)", []string{"vlan", "qinq", "ipv4"}},
		// Both members nested → flat 4 (= altCountCap).
		{"eth/((vlan|qinq)|(ipv4|ipv6))", []string{"vlan", "qinq", "ipv4", "ipv6"}},
		// Three-deep nesting still flattens.
		{"eth/(((vlan|qinq)|ipv4)|ipv6)", []string{"vlan", "qinq", "ipv4", "ipv6"}},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			p := resolveOK(t, tc.expr, nil)
			if len(p.Layers) < 2 {
				t.Fatalf("layers=%d, want >=2", len(p.Layers))
			}
			alt := p.Layers[1]
			if alt.Alternation == nil {
				t.Fatal("layer 1 should be an alt group")
			}
			if got := len(alt.Alternation); got != len(tc.wantLeaf) {
				t.Fatalf("flatten count = %d; want %d (%v)", got, len(tc.wantLeaf), tc.wantLeaf)
			}
			for i, leafName := range tc.wantLeaf {
				m := alt.Alternation[i]
				if m.Spec == nil || m.Spec.Name != leafName {
					t.Errorf("alt[%d].Spec.Name = %v; want %s", i, m.Spec, leafName)
				}
				if m.Alternation != nil {
					t.Errorf("alt[%d] still nested (Alternation != nil)", i)
				}
			}
		})
	}
}


func TestResolveAlternationFollowedLayerAgreesOnDispatch(t *testing.T) {
	// IPv4 sits under either VLAN or QinQ via ethertype==0x0800 — the
	// dispatch agrees across alternatives, so the post-group layer
	// resolves cleanly with one representative DispatchChoice.
	p := resolveOK(t, "eth/(vlan|qinq)/ipv4", nil)
	follow := p.Layers[2]
	if follow.Unsupported != "" {
		t.Errorf("post-alt layer should resolve, got %q", follow.Unsupported)
	}
	if follow.Dispatch == nil {
		t.Fatal("post-alt layer should carry a representative dispatch")
	}
	if follow.Dispatch.Const.FieldName != "ethertype" || follow.Dispatch.Const.Value != 0x0800 {
		t.Errorf("post-alt dispatch = %+v; want ethertype==0x0800", follow.Dispatch.Const)
	}
}

func TestResolveMarksRuntimeOffsetForLayersPastHetAlt(t *testing.T) {
	// `eth/(ipv4|ipv6)/tcp where tcp.dport == 443` — the alt members
	// disagree on header size (20 vs 40), so tcp.dport's offset is
	// runtime-variable and the resolver must mark tcp with
	// NeedsRuntimeOffset so codegen knows to address through a
	// per-layer entry slot rather than R0+static_prefix.
	p := resolveOK(t, "eth/(ipv4|ipv6)/tcp where tcp.dport == 443", nil)
	if len(p.Layers) != 3 {
		t.Fatalf("layers=%d; want 3", len(p.Layers))
	}
	eth, alt, tcp := p.Layers[0], p.Layers[1], p.Layers[2]

	if eth.LayerPos != 0 || alt.LayerPos != 1 || tcp.LayerPos != 2 {
		t.Errorf("LayerPos = %d/%d/%d; want 0/1/2", eth.LayerPos, alt.LayerPos, tcp.LayerPos)
	}
	for _, m := range alt.Alternation {
		if m.LayerPos != 1 {
			t.Errorf("alt member %q LayerPos = %d; want 1 (alt group's pos)", m.Spec.Name, m.LayerPos)
		}
	}

	if eth.NeedsRuntimeOffset || alt.NeedsRuntimeOffset {
		t.Error("eth / alt should NOT need runtime offset (eth precedes het-alt; alt itself has no Spec)")
	}
	if !tcp.NeedsRuntimeOffset {
		t.Error("tcp SHOULD need runtime offset (sits past het-alt and is referenced by where)")
	}
}

func TestResolveDoesNotMarkRuntimeOffsetWithoutHetAlt(t *testing.T) {
	// `eth/(vlan|qinq)/ipv4/tcp where tcp.dport == 443` — alt is
	// uniform-size (4 bytes each), so the static prefix path still
	// works; no layer should be marked.
	p := resolveOK(t, "eth/(vlan|qinq)/ipv4/tcp where tcp.dport == 443", nil)
	for _, l := range p.Layers {
		if l.NeedsRuntimeOffset {
			name := "<alt>"
			if l.Spec != nil {
				name = l.Spec.Name
			}
			t.Errorf("layer %q (pos %d) was marked NeedsRuntimeOffset; want false (uniform-size alt)", name, l.LayerPos)
		}
		for _, m := range l.Alternation {
			if m.NeedsRuntimeOffset {
				t.Errorf("alt member %q was marked NeedsRuntimeOffset; want false", m.Spec.Name)
			}
		}
	}
}

func TestResolveDoesNotMarkRuntimeOffsetWithoutWhere(t *testing.T) {
	// Het-alt without any where / capture reference: nothing to
	// address through a slot, so no layer needs the marker.
	p := resolveOK(t, "eth/(ipv4|ipv6)/tcp", nil)
	for _, l := range p.Layers {
		if l.NeedsRuntimeOffset {
			name := "<alt>"
			if l.Spec != nil {
				name = l.Spec.Name
			}
			t.Errorf("layer %q (pos %d) was marked NeedsRuntimeOffset; want false (no where/capture references)", name, l.LayerPos)
		}
	}
}

func TestResolveMarksRuntimeOffsetForCaptureTargetPastHetAlt(t *testing.T) {
	// `capture proto+0` targeting tcp through a het-alt: the resolver
	// must mark tcp so codegen routes the capture's offset through
	// a slot.
	p := resolveOK(t, "eth/(ipv4|ipv6)/tcp capture tcp+0", nil)
	tcp := p.Layers[2]
	if !tcp.NeedsRuntimeOffset {
		t.Error("tcp SHOULD need runtime offset (capture target past het-alt)")
	}
}

func TestResolveAlternationFollowedLayerDivergesAccepted(t *testing.T) {
	// P3-12: alts that disagree on the post-group dispatch field used
	// to be a hard reject; now they resolve with IsAltDiverged=true
	// and AltConsts populated, and codegen routes through a per-alt
	// JNE check gated on the matched-alt index. Sanity-check the
	// resolver's IR shape here; the actual emit is tested in
	// pkg/kunai/codegen and end-to-end in compile_test / load_dsl_test.
	p := resolveOK(t, "eth/(ipv4|ipv6)/tcp", nil)
	if len(p.Layers) != 3 {
		t.Fatalf("layers = %d; want 3", len(p.Layers))
	}
	tcp := p.Layers[2]
	if tcp.Dispatch == nil {
		t.Fatal("tcp dispatch nil")
	}
	if !tcp.Dispatch.IsAltDiverged {
		t.Error("tcp.Dispatch.IsAltDiverged = false; want true")
	}
	if len(tcp.Dispatch.AltConsts) != 2 {
		t.Fatalf("len(AltConsts) = %d; want 2", len(tcp.Dispatch.AltConsts))
	}
	if tcp.Dispatch.AltConsts[0].FieldName != "protocol" {
		t.Errorf("AltConsts[0].FieldName = %q; want protocol", tcp.Dispatch.AltConsts[0].FieldName)
	}
	if tcp.Dispatch.AltConsts[1].FieldName != "next_header" {
		t.Errorf("AltConsts[1].FieldName = %q; want next_header", tcp.Dispatch.AltConsts[1].FieldName)
	}
}

func TestResolveCaptureBasic(t *testing.T) {
	p := resolveOK(t, "eth/ipv4/tcp[dport==443] capture headers+64", nil)
	if len(p.Captures) != 1 {
		t.Fatalf("captures==%d", len(p.Captures))
	}
	c := p.Captures[0]
	if c.Kind != ast.CapHeadersPlus || c.Extra != 64 {
		t.Errorf("capture = %+v", c)
	}
}

// --- Where clause resolution ---

func TestResolveWhereAction(t *testing.T) {
	p := resolveOK(t, "eth/ipv4/tcp where action == XDP_DROP", xdpTestActions)
	if p.Where == nil || p.Where.Kind != ast.WAtomAction || p.Where.ActionValue != "XDP_DROP" {
		t.Errorf("where = %+v", p.Where)
	}
	if p.Where.Unsupported != "" {
		t.Errorf("action should not be Unsupported: %q", p.Where.Unsupported)
	}
}

func TestResolveWhereRejectsUnknownAction(t *testing.T) {
	// Parser already restricts action to IDENT; resolver enforces the
	// XDP_* whitelist.
	resolveErr(t, "eth/ipv4/tcp where action == SOMETHING_ELSE", xdpTestActions, "unknown action")
}


func TestResolveWhereArithWithLabels(t *testing.T) {
	expr := "eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where outer.total_length == inner.total_length + 36"
	p := resolveOK(t, expr, nil)
	if p.Where == nil || p.Where.Kind != ast.WAtomArith {
		t.Fatalf("where = %+v", p.Where)
	}
	outerField := p.Where.ArithL.Field
	if outerField == nil || outerField.Layer.Label != "outer" || outerField.Field.Name != "total_length" {
		t.Errorf("outer field = %+v", outerField)
	}
	innerField := p.Where.ArithR.Left.Field
	if innerField == nil || innerField.Layer.Label != "inner" || innerField.Field.Name != "total_length" {
		t.Errorf("inner field = %+v", innerField)
	}
	if p.Where.ArithR.Right.Const != 36 {
		t.Errorf("constant = %d", p.Where.ArithR.Right.Const)
	}
}

func TestResolveWhereBarePredicate(t *testing.T) {
	// "tcp.dport" uses a bare protocol name; since the filter has exactly
	// one tcp layer, it resolves to that instance.
	p := resolveOK(t, "eth/ipv4/tcp where tcp.dport == 443", nil)
	fld := p.Where.ArithL.Field
	if fld == nil || fld.Layer.Spec.Name != "tcp" || fld.Field.Name != "dport" {
		t.Errorf("field = %+v", fld)
	}
}

func TestResolveWhereAmbiguousBareRef(t *testing.T) {
	// Two unlabeled ipv4 instances make the bare name ambiguous.
	// Where-clause values are integers (IPv4 literals only appear inside
	// predicate brackets), so we compare against an integer here.
	resolveErr(t, "eth/ipv4/udp/gtp/ipv4/tcp where ipv4.src == 0", nil, "ambiguous")
}

func TestResolveWhereUnknownQualifier(t *testing.T) {
	resolveErr(t, "eth/ipv4/tcp where notaproto.src == 0", nil, `unknown label or protocol "notaproto"`)
}

func TestResolveWhereUnknownField(t *testing.T) {
	resolveErr(t, "eth/ipv4/tcp where tcp.nosuchfield == 0", nil, `has no field "nosuchfield"`)
}

func TestResolveWhereAndOrNot(t *testing.T) {
	p := resolveOK(t, "eth/ipv4/tcp where not tcp.dport == 443 and tcp.sport == 80 or tcp.sport == 81", nil)
	// Top-level: or(and(not(==),==),==)
	if p.Where.Kind != ast.WOr {
		t.Fatalf("top = %v", p.Where.Kind)
	}
	if p.Where.Left.Kind != ast.WAnd || p.Where.Left.Left.Kind != ast.WNot {
		t.Errorf("left branches = %+v", p.Where.Left)
	}
}

// --- Per-capture where ---

func TestResolveCaptureWhereAttached(t *testing.T) {
	p := resolveOK(t, "eth/ipv4/tcp[dport==443] capture headers where action == XDP_PASS capture all where action == XDP_DROP", xdpTestActions)
	if len(p.Captures) != 2 {
		t.Fatalf("captures==%d", len(p.Captures))
	}
	if p.Captures[0].Where == nil || p.Captures[0].Where.ActionValue != "XDP_PASS" {
		t.Errorf("c0 where = %+v", p.Captures[0].Where)
	}
	if p.Captures[1].Where == nil || p.Captures[1].Where.ActionValue != "XDP_DROP" {
		t.Errorf("c1 where = %+v", p.Captures[1].Where)
	}
}

func TestResolveCaptureFieldsMarksUnsupported(t *testing.T) {
	p := resolveOK(t, "eth/ipv4/tcp capture ipv4.src, tcp.dport", nil)
	c := p.Captures[0]
	if c.Kind != ast.CapFields || c.Unsupported == "" {
		t.Errorf("capture = %+v", c)
	}
	if len(c.Fields) != 2 {
		t.Fatalf("fields==%d", len(c.Fields))
	}
	if c.Fields[0].Field.Name != "src" || c.Fields[1].Field.Name != "dport" {
		t.Errorf("fields = %+v, %+v", c.Fields[0], c.Fields[1])
	}
}

func TestResolveCaptureToLayerByLabel(t *testing.T) {
	p := resolveOK(t, "eth/ipv4@outer/udp/gtp/ipv4@inner/tcp capture inner+8", nil)
	c := p.Captures[0]
	if c.Kind != ast.CapToLayer || c.Extra != 8 {
		t.Fatalf("capture = %+v", c)
	}
	if c.TargetLayer == nil || c.TargetLayer.Spec.Name != "ipv4" {
		t.Errorf("target = %+v", c.TargetLayer)
	}
}

func TestResolveCaptureToLayerByProto(t *testing.T) {
	p := resolveOK(t, "eth/ipv4/tcp capture ipv4", nil)
	c := p.Captures[0]
	if c.Kind != ast.CapToLayer || c.TargetLayer == nil || c.TargetLayer.Spec.Name != "ipv4" {
		t.Fatalf("capture = %+v", c)
	}
}

func TestResolveCaptureToLayerRejectsUnknownLabel(t *testing.T) {
	resolveErr(t, "eth/ipv4/tcp capture nope", nil, "unknown")
}

func TestResolveCaptureToLayerRejectsAmbiguousProto(t *testing.T) {
	resolveErr(t, "eth/ipv4/udp/gtp/ipv4/tcp capture ipv4", nil, "ambiguous")
}

func TestResolveCaptureAbsolute(t *testing.T) {
	p := resolveOK(t, "eth/ipv4/tcp capture absolute 96", nil)
	c := p.Captures[0]
	if c.Kind != ast.CapAbsolute || c.Extra != 96 {
		t.Fatalf("capture = %+v", c)
	}
}

func TestResolveCaptureAbsoluteRejectsZero(t *testing.T) {
	resolveErr(t, "eth/ipv4/tcp capture absolute 0", nil, "must be > 0")
}

// --- Integration: every canonical filter example from docs/ja/dsl-grammar.md & dsl-usage.md ---

func TestResolveArithFitCheckRejectsOverwidthLiteral(t *testing.T) {
	// tcp.dport is bit<16>; 99999 cannot be narrowed to Int<16> per
	// dsl-types.md §6.1.
	resolveErr(t, "eth/ipv4/tcp where tcp.dport > 99999", nil, "does not fit")
}

func TestResolveArithStaticDivByZero(t *testing.T) {
	resolveErr(t, "eth/ipv4/tcp where tcp.dport / 0 == 1", nil, "division by zero")
}

func TestResolveArithStaticModByZero(t *testing.T) {
	resolveErr(t, "eth/ipv4/tcp where tcp.dport % 0 == 1", nil, "modulo by zero")
}

func TestResolveArithFieldOnlyCmpAccepted(t *testing.T) {
	// Two integer fields: no literal, no fit-check needed; widening
	// per §5.2 keeps it well-typed.
	resolveOK(t, "eth/ipv4/tcp where tcp.dport == tcp.sport", nil)
}

func TestResolveNegativeLiteralFitsInt16(t *testing.T) {
	// -1 narrows to bit<16> as 0xffff via 2's complement (§4.1, §7.3).
	resolveOK(t, "eth/ipv4/tcp where tcp.dport == -1", nil)
}

func TestResolveNegativeLiteralOutOfRangeInt8(t *testing.T) {
	// -129 cannot fit in bit<8>: signed range is [-128, 256).
	resolveErr(t, "eth/ipv4/tcp where ipv4.ttl == -129", nil, "does not fit")
}

// resolveStrict parses expr and resolves it with StrictArithLint
// enabled, returning the error (if any) for assertion. Helper keeps
// the F1 tests compact.
func resolveStrict(t *testing.T, expr string) error {
	t.Helper()
	f, err := parser.Parse(expr, "t.dsl", nil)
	if err != nil {
		t.Fatalf("parse(%q): %v", expr, err)
	}
	_, err = ResolveWithOptions(f, loadVocab(t), nil, Options{StrictArithLint: true})
	return err
}

func TestResolveStrictArithLintRejectsTwoFieldAdd(t *testing.T) {
	err := resolveStrict(t, "eth/ipv4/tcp where tcp.dport + tcp.sport > 100")
	if err == nil || !strings.Contains(err.Error(), "likely overflows") {
		t.Fatalf("err = %v; want overflow-suspect error", err)
	}
}

func TestResolveStrictArithLintAllowsFieldPlusConst(t *testing.T) {
	// Single field + small const is the common, intentional pattern;
	// strict mode must not false-positive on it.
	if err := resolveStrict(t, "eth/ipv4/tcp where tcp.dport + 1 > 100"); err != nil {
		t.Fatalf("err = %v; want clean resolve", err)
	}
}

func TestResolveStrictArithLintRejectsFieldMinusEqualWidth(t *testing.T) {
	err := resolveStrict(t, "eth/ipv4/tcp where tcp.dport - tcp.sport > 100")
	if err == nil || !strings.Contains(err.Error(), "likely underflows") {
		t.Fatalf("err = %v; want underflow-suspect error", err)
	}
}

func TestResolveStrictArithLintOffByDefault(t *testing.T) {
	// Without StrictArithLint, two-field arith resolves cleanly —
	// the typed-OK / silent-wrap contract from §6.1 stays intact.
	resolveOK(t, "eth/ipv4/tcp where tcp.dport + tcp.sport > 100", nil)
}


func TestResolveAllExamples(t *testing.T) {
	// Each entry lists: (expr, should resolve?). Examples that require
	// protocols or features outside the MVP vocabulary — MPLS, VXLAN,
	// CW, three-stage SRv6 — are expected to fail clearly.
	cases := []struct {
		name      string
		expr      string
		wantErr   bool
		wantInErr string
	}{
		{"basic", "eth/ipv4/tcp[dport==443]", false, ""},
		{"cidr", "eth/ipv4[src==10.0.0.0/8]/tcp", false, ""},
		{"vlan_opt", "eth/vlan?/ipv4/tcp", false, ""},
		{"mpls_stack", "eth/mpls{1,8}/ipv4/tcp", false, ""},
		// VXLAN's payload is always Ethernet, but ipv4's self-validating
		// parser block lets the chain resolve; at runtime its
		// `transition select(version)` rejects non-IPv4 payloads.
		{"vxlan_with_labels", "eth/ipv4@outer/udp/vxlan[vni==100]/ipv4@inner/tcp[dport==80]", false, ""},
		// srv6 chain resolves dispatch via ipv6's self-validating parser,
		// but hits the MVP label cap (max 2 labeled instances).
		{"srv6_three_stage", "eth/ipv6@transit/srv6/ipv6@service/srv6/ipv6@user/tcp", true, "3 labeled instances"},
		{"gtp", "eth/ipv4/udp/gtp[teid==0x12345]/ipv4/tcp[dport==443]", false, ""},
		{"l3vpn", "eth/mpls+/ipv4/tcp", false, ""},
		{"l2vpn_no_cw", "eth/mpls+/eth@inner/ipv4/tcp", false, ""},
		{"l2vpn_cw", "eth/mpls+/cw?/eth@inner/ipv4/tcp", false, ""},
		{"where_arith_gtp", "eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where outer.total_length == inner.total_length + 36", false, ""},
		{"where_action", "eth/ipv4/tcp where action == XDP_DROP", false, ""},
		{"capture_truncated", "eth/ipv4/tcp[dport==443] capture headers+64", false, ""},
		{"capture_conditional", "eth/ipv4/tcp[dport==443] capture headers where action == XDP_PASS capture all where action == XDP_DROP", false, ""},
	}
	// Example list mixes action-bearing and pure expressions; pass the
	// XDP action map throughout so action atoms resolve. Reserved
	// labels match so tests that touch @label collisions stay honest.
	reserved := reservedFromActions(xdpTestActions)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := parser.Parse(tc.expr, "ex.dsl", reserved)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			_, err = Resolve(f, loadVocab(t), xdpTestActions)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q", tc.wantInErr)
				}
				if tc.wantInErr != "" && !strings.Contains(err.Error(), tc.wantInErr) {
					t.Errorf("error = %v; want contains %q", err, tc.wantInErr)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
