package dsltest

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
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
	"tc_wire_entry":    tc.WireEntryCapabilities,
	"tc_wire_exit":     tc.WireFexitCapabilities,
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
// host's, after the filter; the runner reads the key the filter left in
// the region (Runner.MatchKey) and looks it up in the vector's members
// (setsAdmit).
type specSetSlots struct {
	decls  []specSet
	base   map[string]int16
	cursor int16
}

// The packet-key region the wrapper zeroes and reads back (runner.go).
const (
	specSetKeyTop   = setKeyLow + keyRegionSize
	specSetKeyFloor = setKeyLow
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
// as the traced program's return value. A vector that declares sets is
// accepted when the filter accepts and every set it extracts a key for
// holds that key, as the host's lookup after the filter decides. A vector
// with goStatus "mismatch" is a documented
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
	// The mutated vectors of one expression come in a row and compile to
	// the same program, so its two loads (one per stack fill) are kept
	// until the expression changes. Loading dominates the run time, more
	// so on kernels whose verifier is slow on the TCP option filters.
	var loads specLoads
	t.Cleanup(loads.close)
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
			parsed, err := parser.Parse(v.Expr, "", nil)
			if err != nil && v.Expected.Kind != "illTyped" {
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
			pkt, err := hex.DecodeString(v.Packet)
			if err != nil {
				t.Fatalf("packet hex: %v", err)
			}
			checkCaptureBound(t, v, parsed, out, len(pkt))
			if !root {
				return
			}
			// Twice, with kunai's stack filled with zeros and with ones: a
			// slot read before it is written shows up as a verdict that
			// depends on the fill.
			for i, r := range loads.get(t, v, out, action) {
				fill := specStackFills[i]
				got, region := r.MatchKey(t, pkt)
				if got {
					got = setsAdmit(t, v.Sets, r, region)
				}
				if got != want {
					t.Fatalf("%q on %d-byte packet (stack filled with %#x): got match=%v, Lean says %s. %s", v.Expr, len(pkt), uint32(fill), got, v.Expected.Kind, v.Note)
				}
			}
		})
	}
}

// specStackFills are the stack fills each vector runs under.
var specStackFills = [2]int32{0, -1}

// specLoads holds the Runners of the last expression runSpecVectors
// loaded, one per entry of specStackFills.
type specLoads struct {
	key     string
	runners [len(specStackFills)]*Runner
}

// get returns v's Runners, loading them unless the previous vector had the
// same expression, host, action and sets. A reused Runner gets a zeroed
// scratch map, so each vector starts from the state a fresh load has.
func (l *specLoads) get(t *testing.T, v specVector, out codegen.Output, action int32) [len(specStackFills)]*Runner {
	t.Helper()
	sets, err := json.Marshal(v.Sets)
	if err != nil {
		t.Fatalf("sets: %v", err)
	}
	key := fmt.Sprintf("%s\x00%s\x00%d\x00%s", v.Expr, v.Host, action, sets)
	if key == l.key && l.runners[0] != nil {
		for _, r := range l.runners {
			r.resetScratch(t)
		}
		return l.runners
	}
	l.close()
	for i, fill := range specStackFills {
		l.runners[i] = loadFromOutput(t, v.Expr, out, action, &fill)
	}
	l.key = key
	return l.runners
}

func (l *specLoads) close() {
	for i, r := range l.runners {
		if r != nil {
			r.close()
			l.runners[i] = nil
		}
	}
	l.key = ""
}

// setsAdmit is the host's lookup after the filter: every set the filter
// extracts a key for must hold it. A key of at most 8 bytes is stored
// native-endian (the value `set add` writes), a 16-byte one in network
// order; a member is the field's numeric value either way.
func setsAdmit(t *testing.T, decls []specSet, r *Runner, region [keyRegionSize]byte) bool {
	t.Helper()
	for _, d := range decls {
		key := r.SetKey(t, region, d.Name)
		if key == nil {
			continue
		}
		var v big.Int
		switch len(key) {
		case 1:
			v.SetUint64(uint64(key[0]))
		case 2:
			v.SetUint64(uint64(binary.NativeEndian.Uint16(key)))
		case 4:
			v.SetUint64(uint64(binary.NativeEndian.Uint32(key)))
		case 8:
			v.SetUint64(binary.NativeEndian.Uint64(key))
		case 16:
			v.SetBytes(key)
		default:
			t.Fatalf("set %s: %d-byte key", d.Name, len(key))
		}
		held := false
		for _, m := range d.Members {
			var want big.Int
			if _, ok := want.SetString(m.String(), 10); !ok {
				t.Fatalf("set %s: member %q is not a decimal integer", d.Name, m)
			}
			if want.Cmp(&v) == 0 {
				held = true
				break
			}
		}
		if !held {
			return false
		}
	}
	return true
}
