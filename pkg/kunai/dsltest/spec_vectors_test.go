package dsltest

import (
	"encoding/hex"
	"errors"
	"math"
	"os"
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/kunai"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
	"github.com/takehaya/bpf-ninja/pkg/kunai/host/cgroupskb"
	"github.com/takehaya/bpf-ninja/pkg/kunai/host/netfilter"
	"github.com/takehaya/bpf-ninja/pkg/kunai/host/tc"
	"github.com/takehaya/bpf-ninja/pkg/kunai/host/xdp"
	"github.com/takehaya/bpf-ninja/pkg/kunai/parser"
)

// specHostCaps mirrors Kunai/Host.lean HostKind.host.
var specHostCaps = map[string]func() codegen.Capabilities{
	"xdp_entry":        func() codegen.Capabilities { return codegen.Capabilities{} },
	"xdp_exit":         xdp.FexitCapabilities,
	"tc_entry":         tc.EntryCapabilities,
	"tc_exit":          tc.FexitCapabilities,
	"cgroup_skb_entry": cgroupskb.EntryCapabilities,
	"cgroup_skb_exit":  cgroupskb.FexitCapabilities,
	"netfilter_entry":  netfilter.EntryCapabilities,
	"netfilter_exit":   netfilter.FexitCapabilities,
}

// specSetSlots declares a vector's sets to codegen the way bpf-ninja's
// packet-key resolver (internal/program pktSetSlots) does: each set is one
// scalar key of the declared width, allocated on first use downward from
// the host slot at -24, aligned to its width (8 at most), inside a 16-byte
// buffer; a set past the buffer has no slot. The membership lookup is the
// host's, after the filter, and the runner does not perform it, so a
// vector's reject verdict is not checked on the kernel.
type specSetSlots struct {
	decls  []specSet
	base   map[string]int16
	cursor int16
}

const (
	specSetKeyTop   = int16(-24)
	specSetKeyFloor = int16(-40)
)

func newSpecSetSlots(decls []specSet) *specSetSlots {
	return &specSetSlots{decls: decls, base: map[string]int16{}, cursor: specSetKeyTop}
}

func (s *specSetSlots) decl(name string) (specSet, bool) {
	for _, d := range s.decls {
		if d.Name == name {
			return d, true
		}
	}
	return specSet{}, false
}

func (s *specSetSlots) HasSet(name string) bool {
	_, ok := s.decl(name)
	return ok
}

func (s *specSetSlots) SlotFor(set, _ string) (int16, int, bool) {
	d, ok := s.decl(set)
	if !ok {
		return 0, 0, false
	}
	size := int16(d.Width / 8)
	base, allocated := s.base[set]
	if !allocated {
		align := min(size, 8)
		base = (s.cursor - size) &^ (align - 1)
		if base < specSetKeyFloor {
			return 0, 0, false
		}
		s.base[set], s.cursor = base, base
	}
	return base, int(size), true
}

// TestSpecVectors checks the Go implementation against the Lean semantics.
// Without root only parsing and the illTyped/notImplemented compile
// expectations run; with root, every vector whose compile is expected to
// succeed is also matched against the real BPF program, compiled for the
// vector's host; on an exit host the wrapper presents the vector's action
// as the traced program's return value. A vector that declares sets runs
// on the kernel only when Lean accepts: the filter alone must accept too,
// while a Lean reject may come from the set lookup, which is the host's
// and not performed here. A vector with goStatus "mismatch" is a documented
// divergence (see spec/lean/DECISIONS.md): it is logged, not asserted.
func TestSpecVectors(t *testing.T) { runSpecVectors(t, loadSpecVectors(t)) }

// TestSpecVectorsGenerated runs the mutated vectors (truncations and byte
// flips of the golden packets); their verdicts come from the Lean
// evaluator at generation time.
func TestSpecVectorsGenerated(t *testing.T) {
	runSpecVectors(t, loadSpecVectorsFrom(t, specVectorsGenPath))
}

func runSpecVectors(t *testing.T, vectors []specVector) {
	root := os.Getuid() == 0
	for _, v := range vectors {
		t.Run(v.ID, func(t *testing.T) {
			hostCaps, ok := specHostCaps[v.Host]
			if !ok {
				t.Fatalf("unknown host %q", v.Host)
			}
			// Lean models actions as 32-bit values (TC_ACT_UNSPEC is 2^32-1).
			if v.Action < 0 || v.Action > math.MaxUint32 {
				t.Fatalf("action %d is not a 32-bit value", v.Action)
			}
			caps, action := hostCaps(), int32(uint32(v.Action))
			caps.Lang.SetSlots = newSpecSetSlots(v.Sets)
			if v.GoStatus == "mismatch" {
				_, err := kunai.Compile(v.Expr, caps)
				t.Logf("documented divergence (not asserted): %s; compile err=%v", v.Note, err)
				return
			}
			if _, err := parser.Parse(v.Expr, "", nil); err != nil && v.Expected.Kind != "illTyped" {
				t.Fatalf("parse %q: %v", v.Expr, err)
			}
			out, err := kunai.Compile(v.Expr, caps)
			switch {
			case v.GoStatus == "notImplemented":
				if !errors.Is(err, codegen.ErrNotImplemented) {
					t.Fatalf("Compile(%q) = %v; want ErrNotImplemented (%s)", v.Expr, err, v.Note)
				}
				return
			case v.Expected.Kind == "illTyped":
				// The resolver must reject it; an ErrNotImplemented is an
				// implementation limit and belongs under goStatus notImplemented.
				if err == nil || errors.Is(err, codegen.ErrNotImplemented) {
					t.Fatalf("Compile(%q) = %v; Lean: illTyped %q", v.Expr, err, v.Expected.Reason)
				}
				return
			case err != nil:
				t.Fatalf("Compile(%q): %v", v.Expr, err)
			}
			want := v.Expected.Kind == "accept"
			if !root || (len(v.Sets) > 0 && !want) {
				return
			}
			pkt, err := hex.DecodeString(v.Packet)
			if err != nil {
				t.Fatalf("packet hex: %v", err)
			}
			// Twice, with kunai's stack filled with zeros and with ones: a
			// slot read before it is written shows up as a verdict that
			// depends on the fill.
			for _, fill := range []int32{0, -1} {
				if got := NewFromOutputStackFilled(t, v.Expr, out, action, fill).Match(t, pkt); got != want {
					t.Fatalf("%q on %d-byte packet (stack filled with %#x): got match=%v, Lean says %s. %s", v.Expr, len(pkt), uint32(fill), got, v.Expected.Kind, v.Note)
				}
			}
		})
	}
}
