package attach

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

func TestSelectHookType(t *testing.T) {
	edges := []extensionLink{{10, 20, 3}, {10, 21, 4}, {11, 22, 3}}
	for _, tt := range []struct {
		name   string
		id     uint32
		actual ebpf.ProgramType
		types  map[uint32]ebpf.ProgramType
		want   ebpf.ProgramType
		err    string
	}{
		{"plain", 20, ebpf.XDP, nil, ebpf.XDP, ""},
		{"xdp", 10, ebpf.Extension, map[uint32]ebpf.ProgramType{20: ebpf.XDP, 21: ebpf.XDP}, ebpf.XDP, ""},
		{"tc", 11, ebpf.Extension, map[uint32]ebpf.ProgramType{22: ebpf.SchedCLS}, ebpf.SchedCLS, ""},
		{"unattached", 12, ebpf.Extension, nil, 0, "unattached"},
		{"conflicting", 10, ebpf.Extension, map[uint32]ebpf.ProgramType{20: ebpf.XDP, 21: ebpf.SchedCLS}, 0, "conflicting"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectHookType(tt.id, tt.actual, edges, func(id uint32) (ebpf.ProgramType, error) {
				return tt.types[id], nil
			})
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("got %v, want %s", err, tt.err)
				}
			} else if err != nil || got != tt.want {
				t.Fatalf("got %s, %v; want %s", got, err, tt.want)
			}
		})
	}
}

func TestCheckReplacement(t *testing.T) {
	edges := []extensionLink{{10, 20, 3}, {11, 21, 4}}
	if err := checkReplacement(edges, 20, 3, "prog0"); err == nil || !strings.Contains(err.Error(), "-p 10") {
		t.Fatalf("expected EXT target hint, got %v", err)
	}
	for _, edge := range []extensionLink{{0, 20, 4}, {0, 21, 3}, {0, 22, 3}} {
		if err := checkReplacement(edges, edge.TargetID, edge.FuncID, "prog0"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEffectiveHookType(t *testing.T) {
	for _, target := range []Target{
		{Type: ebpf.XDP},
		{Type: ebpf.XDP, HookType: ebpf.XDP},
		{Type: ebpf.Extension, HookType: ebpf.XDP},
	} {
		if got := target.EffectiveHookType(); got != ebpf.XDP {
			t.Fatalf("got %s, want XDP", got)
		}
	}
	if got := (Target{Type: ebpf.Extension}).EffectiveHookType(); got != 0 {
		t.Fatalf("unresolved EXT hook type: %s", got)
	}
}

func TestExtensionGuardDispatcherSlots(t *testing.T) {
	proto := &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4}}
	entry := &btf.Func{Name: "entry", Type: proto, Linkage: btf.GlobalFunc}
	replaced := &btf.Func{Name: "replaced", Type: proto, Linkage: btf.GlobalFunc}
	slot := &btf.Func{Name: "arbitrary_loader_name", Type: proto, Linkage: btf.GlobalFunc}
	local := &btf.Func{Name: "local", Type: proto, Linkage: btf.StaticFunc}
	builder, err := btf.NewBuilder([]btf.Type{entry, replaced, slot, local}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := builder.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var fn *btf.Func
	if err := spec.TypeByName("replaced", &fn); err != nil {
		t.Fatal(err)
	}
	fid, err := spec.TypeID(fn)
	if err != nil {
		t.Fatal(err)
	}
	prog := new(ebpf.Program)
	guard := &ExtensionGuard{edges: []extensionLink{{10, 20, fid}}, programs: map[*ebpf.Program]*extensionProgram{prog: {20, "entry", spec}}}
	for _, allow := range []bool{false, true} {
		for _, name := range []string{"entry", "replaced", "arbitrary_loader_name", "local"} {
			err := guard.Check(prog, name, allow)
			want := name == "replaced" || (name == "arbitrary_loader_name" && !allow)
			if (err != nil) != want {
				t.Fatalf("%s override=%v: %v", name, allow, err)
			}
			if name == "arbitrary_loader_name" && !allow && (!strings.Contains(err.Error(), "EBUSY") || !strings.Contains(err.Error(), "--allow-dispatcher-slot")) {
				t.Fatal(err)
			}
		}
	}
	// A renamed program with multiple BTF functions may have no resolvable
	// entry. Only a dispatcher slot check should need that resolution.
	resolveErr := errors.New("cannot resolve entry function from BTF")
	for _, tt := range []struct {
		name      string
		edges     []extensionLink
		function  string
		allowSlot bool
		wantCalls int
		wantErr   string
	}{
		{"no links", nil, slot.Name, false, 0, ""},
		{"unrelated link", []extensionLink{{10, 21, fid}}, slot.Name, false, 0, ""},
		{"outgoing link", []extensionLink{{20, 21, fid}}, slot.Name, false, 0, ""},
		{"replaced", guard.edges, replaced.Name, false, 0, "is replaced"},
		{"replaced with override", guard.edges, replaced.Name, true, 0, "is replaced"},
		{"slot", guard.edges, slot.Name, false, 1, resolveErr.Error()},
		{"slot with override", guard.edges, slot.Name, true, 0, ""},
		{"local", guard.edges, local.Name, false, 0, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := &ExtensionGuard{edges: tt.edges}
			p := &extensionProgram{id: 20, spec: spec}
			calls := 0
			err := g.check(p, tt.function, tt.allowSlot, func() (string, error) {
				calls++
				return "", resolveErr
			})
			if calls != tt.wantCalls {
				t.Fatalf("entry resolver called %d times, want %d", calls, tt.wantCalls)
			}
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got %v, want %s", err, tt.wantErr)
			}
		})
	}
	guard.edges = nil
	if err := guard.Check(prog, slot.Name, false); err != nil {
		t.Fatalf("ordinary global function: %v", err)
	}
}

func TestListReachableProgramsVanishedExtension(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	newProg := func() *ebpf.Program {
		p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "ext_race", Type: ebpf.XDP, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	root := newProg()
	defer func() { _ = root.Close() }()
	child := newProg()
	ri, err := root.Info()
	if err != nil {
		t.Fatal(err)
	}
	ci, err := child.Info()
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := ri.ID()
	cid, _ := ci.ID()
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
	targets, err := listReachablePrograms(root, []extensionLink{{uint32(cid), uint32(rid), 1}})
	if err != nil || len(targets) != 0 {
		t.Fatalf("vanished edge: %v, %v", targets, err)
	}
}
