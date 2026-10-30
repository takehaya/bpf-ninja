package program

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/attach"
)

func TestHookPointsInvalidConfiguration(t *testing.T) {
	for _, tc := range []struct {
		targets []attach.Target
		stages  []Stage
	}{
		{},
		{make([]attach.Target, 256), []Stage{{}}},
		{[]attach.Target{{}}, []Stage{{IsFexit: true}}},
		{[]attach.Target{{}}, []Stage{{}, {IsFexit: true}}},
		{[]attach.Target{{Type: ebpf.SchedCLS}}, []Stage{{}}},
		{[]attach.Target{{Type: ebpf.XDP}}, []Stage{{}}},
	} {
		if root, err := validateHookPoints(tc.targets, tc.stages); err == nil || root != nil {
			t.Fatalf("accepted invalid config: %+v root=%v err=%v", tc, root, err)
		}
	}
}

func TestHookRecordsRejectCrossRunSwap(t *testing.T) {
	records := []hookRecord{
		{Interface: 0, PacketID: 1, Marker: 1},
		{Interface: 1, PacketID: 1, Marker: 1, Mutated: 42},
		{Interface: 0, PacketID: 2, Marker: 2},
		{Interface: 1, PacketID: 2, Marker: 2, Mutated: 42},
		{Interface: 2, PacketID: 2, Marker: 2, Mutated: 42},
	}
	if err := checkHookRecords(records, []byte{1, 2}); err != nil {
		t.Fatal(err)
	}
	// Reassign marker 2's hook_c to marker 1's ID, keeping the size histogram.
	records[4].PacketID = 1
	if err := checkHookRecords(records, []byte{1, 2}); err == nil {
		t.Fatal("accepted cross-run hook_c swap")
	} else {
		t.Logf("rejected cross-run hook_c swap: %v", err)
	}
}

func TestHookRootContext(t *testing.T) {
	for _, kind := range []string{"xdp_md", "__sk_buff"} {
		for _, valid := range []bool{false, true} {
			ctx := &btf.Struct{Name: kind, Size: 24}
			param := btf.Type(&btf.Pointer{Target: ctx})
			if !valid {
				param = &btf.Pointer{Target: &btf.Struct{Name: "other", Size: 24}}
			}
			root := &btf.Func{Name: "root", Type: &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4}, Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: ctx}}}}}
			h := &btf.Func{Name: "hook", Type: &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4}, Params: []btf.FuncParam{{Name: "ctx", Type: param}}}}
			b, e := btf.NewBuilder([]btf.Type{root, h}, nil)
			if e != nil {
				t.Fatal(e)
			}
			raw, e := b.Marshal(nil, nil)
			if e != nil {
				t.Fatal(e)
			}
			spec, e := btf.LoadSpecFromReader(bytes.NewReader(raw))
			if e != nil {
				t.Fatal(e)
			}
			if e = validateHookRootContext(spec, "root", "hook"); (e == nil) != valid {
				t.Fatalf("%s valid=%v: %v", kind, valid, e)
			}
		}
	}
}
