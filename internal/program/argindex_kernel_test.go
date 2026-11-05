package program

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/record"
	"github.com/takehaya/bpf-ninja/internal/recordbuild"
	"github.com/takehaya/bpf-ninja/internal/setmap"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// The packet's first byte is a key. Injection adds a lookup hook on fw, on vec
// and on rsv, and an update hook on sessions, whose BPF_NOEXIST update succeeds
// with status 1<<32 on a new key and fails with -EEXIST on a present one. An
// update on copies from a read-only value gets a static hook. The queue and the
// delete on gone cover the other hooks with a status.
const argIndexSource = `
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
struct fw_rule { __u32 id; __u8 pad[7]; __u8 action; };
struct fw_value { __u64 n; struct fw_rule rules[3]; __u32 counts[4]; __u16 grid[2][3]; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct fw_value);
} fw SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32[4]);
} vec SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} sessions SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct fw_rule[2]);
} rsv SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __uint(map_flags, BPF_F_RDONLY_PROG);
    __type(key, __u32);
    __type(value, __u32);
} ro SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} copies SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} gone SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 1);
    __uint(value_size, 4);
} fifo SEC(".maps");
SEC("xdp")
int index_target(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    if (data + 1 > end) return XDP_ABORTED;
    __u32 idx = *(__u8 *)data;
    int verdict = XDP_PASS;
    struct fw_value *v = bpf_map_lookup_elem(&fw, &idx);
    if (v && v->n == 99) verdict = XDP_DROP;
    __u32 *w = bpf_map_lookup_elem(&vec, &idx);
    if (w && w[0] == 99) verdict = XDP_DROP;
    __u32 one = 1;
    bpf_map_update_elem(&sessions, &idx, &one, BPF_NOEXIST);
    struct fw_rule *rs = bpf_map_lookup_elem(&rsv, &idx);
    if (rs && rs[0].id == 99) verdict = XDP_DROP;
    __u32 *r = bpf_map_lookup_elem(&ro, &idx);
    if (r) bpf_map_update_elem(&copies, &idx, r, BPF_NOEXIST);
    bpf_map_delete_elem(&gone, &idx);
    bpf_map_push_elem(&fifo, &idx, BPF_EXIST);
    bpf_map_pop_elem(&fifo, &one);
    bpf_map_peek_elem(&fifo, &one);
    return verdict;
}
char _license[] SEC("license") = "GPL";
`

type argIndexFixture struct {
	root    *attach.ProgInfo
	targets map[string]attach.Target
	maps    map[string]*ebpf.Map
}

func loadArgIndexFixture(t *testing.T) *argIndexFixture {
	t.Helper()
	testutil.SkipIfNotRoot(t)
	elf, err := os.ReadFile(testutil.CompileBPFSource(t, argIndexSource))
	if err != nil {
		t.Fatal(err)
	}
	res, err := inject.TransformLookup(elf, inject.LookupRequest{
		ELFSHA256: fmt.Sprintf("%x", sha256.Sum256(elf)), ProgramName: "index_target", Auto: true,
		Updates: inject.CallAny, Deletes: inject.CallAny, Pushes: inject.CallAny, Pops: inject.CallAny, Peeks: inject.CallAny,
		StaticUntrusted: true, HookName: "idx", Stack: inject.StackAudit{LowestOffset: -64},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range res.Hooks {
		if want := h.Name == "idx_ro" || h.Name == "idx_copies_update"; h.Static != want {
			t.Fatalf("hook %s static=%v, want %v", h.Name, h.Static, want)
		}
	}
	coll, err := ebpf.NewCollection(res.Spec)
	if err != nil {
		t.Fatalf("loading the injected program: %v", err)
	}
	t.Cleanup(coll.Close)
	info, err := coll.Programs["index_target"].Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	root, err := attach.FindBPFProgramByID(uint32(id))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Program.Close() })
	names := []string{"idx_fw", "idx_vec", "idx_rsv", "idx_sessions_update", "idx_copies_update", "idx_gone_delete", "idx_fifo_push", "idx_fifo_pop", "idx_fifo_peek"}
	targets, _, err := attach.ResolveTargets([]*attach.ProgInfo{root}, names, false)
	if err != nil || len(targets) != len(names) {
		t.Fatalf("targets %+v: %v", targets, err)
	}
	f := &argIndexFixture{root: root, targets: map[string]attach.Target{}, maps: coll.Maps}
	for _, target := range targets {
		f.targets[target.FuncName] = target
	}
	f.seed(t)
	return f
}

// seed writes fw, vec, rsv and ro for keys 1 and 2; key 3 is absent from all of them.
func (f *argIndexFixture) seed(t *testing.T) {
	t.Helper()
	for key, v := range map[uint32]struct {
		action0, action2 uint8
		count3           uint32
		grid12           uint16
		vec2             uint32
	}{1: {2, 9, 1, 7, 40}, 2: {3, 2, 5, 8, 50}} {
		value := make([]byte, 8+3*12+4*4+2*3*2)
		value[8+11] = v.action0
		value[8+2*12+11] = v.action2
		binary.NativeEndian.PutUint32(value[8+36+12:], v.count3)
		binary.NativeEndian.PutUint16(value[8+36+16+10:], v.grid12)
		if err := f.maps["fw"].Put(key, value); err != nil {
			t.Fatal(err)
		}
		vec := make([]byte, 16)
		binary.NativeEndian.PutUint32(vec[8:], v.vec2)
		if err := f.maps["vec"].Put(key, vec); err != nil {
			t.Fatal(err)
		}
		rules := make([]byte, 2*12)
		rules[12+11] = v.action2
		if err := f.maps["rsv"].Put(key, rules); err != nil {
			t.Fatal(err)
		}
		if err := f.maps["ro"].Put(key, uint32(1)); err != nil {
			t.Fatal(err)
		}
	}
}

// resetSessions removes every key the packets add, so a new-key update succeeds.
func (f *argIndexFixture) resetSessions() {
	for _, key := range []uint32{1, 2, 3} {
		_ = f.maps["sessions"].Delete(key)
		_ = f.maps["copies"].Delete(key)
	}
}

type argIndexRecord struct {
	idx  byte
	note string
}

// capture runs packets under one hook's filter and returns each selected
// packet's first byte and the comment --record filter writes.
func (f *argIndexFixture) capture(t *testing.T, hook string, exit bool, tf filter.TargetFilters, packets []byte) []argIndexRecord {
	t.Helper()
	f.resetSessions()
	target := f.targets[hook]
	layout, err := recordbuild.Build(target, tf, recordbuild.Options{Mode: record.ModeFilter})
	if err != nil || layout == nil {
		t.Fatalf("layout %v", err)
	}
	probe, err := LoadMultiPointRecord([]attach.Target{target}, []Stage{{IsFexit: exit}}, []filter.TargetFilters{tf}, true, nil, EmitBoth, []*record.Layout{layout})
	if err != nil {
		t.Fatalf("load: %+v", err)
	}
	defer func() { _ = probe.Close() }()
	for _, p := range packets {
		data := make([]byte, 64)
		data[0] = p
		if _, err := f.root.Program.Run(&ebpf.RunOptions{Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	var out []argIndexRecord
	for _, inner := range probe.InnerMaps {
		rd, err := fastrb.New(inner.FD(), int(inner.MaxEntries()))
		if err != nil {
			t.Fatal(err)
		}
		rd.ReadBatch(func(raw []byte) {
			s, err := capture.ParseRawSample(raw)
			if err != nil {
				t.Fatal(err)
			}
			note, err := layout.Comment(s.Record)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, argIndexRecord{s.Data[0], note})
		})
		_ = rd.Close()
	}
	slices.SortStableFunc(out, func(a, b argIndexRecord) int { return int(a.idx) - int(b.idx) })
	return out
}

func TestBpfArgFilterArrayIndex(t *testing.T) {
	f := loadArgIndexFixture(t)
	for _, c := range []struct {
		hook  string
		exprs []string
		want  []argIndexRecord
	}{
		{"idx_fw", []string{"value->rules[0].action==2"}, []argIndexRecord{{1, "value->rules[0].action=2"}}},
		{"idx_fw", []string{"value->rules[0].action==3"}, []argIndexRecord{{2, "value->rules[0].action=3"}}},
		{"idx_fw", []string{"value->rules[2].action==2"}, []argIndexRecord{{2, "value->rules[2].action=2"}}},
		{"idx_fw", []string{"value->rules[1].action==2"}, nil},
		{"idx_fw", []string{"value->rules[0].action==3", "value->rules[2].action==2"},
			[]argIndexRecord{{2, "value->rules[0].action=3 value->rules[2].action=2"}}},
		{"idx_fw", []string{"value->counts[3]==1"}, []argIndexRecord{{1, "value->counts[3]=1"}}},
		{"idx_fw", []string{"value->grid[1][2]==8"}, []argIndexRecord{{2, "value->grid[1][2]=8"}}},
		{"idx_vec", []string{"value[0][2]==50"}, []argIndexRecord{{2, "value[0][2]=50"}}},
		{"idx_rsv", []string{"value[0][1].action==2"}, []argIndexRecord{{2, "value[0][1].action=2"}}},
	} {
		args, err := filter.ParseAndValidateFilters(c.exprs, f.targets[c.hook].Params)
		if err != nil {
			t.Fatalf("%v: %v", c.exprs, err)
		}
		tf := filter.TargetFilters{Args: args}
		for _, exit := range []bool{false, true} {
			if got := f.capture(t, c.hook, exit, tf, []byte{1, 2, 3}); !slices.Equal(got, c.want) {
				t.Errorf("%v exit=%v: %+v, want %+v", c.exprs, exit, got, c.want)
			}
		}
		f.checkPlain(t, c.hook, tf, []byte{1, 2, 3}, len(c.want))
	}

	// A set key and echo read the same indexed member.
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 1, ValueSize: 1, MaxEntries: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	if err := m.Put(uint8(3), uint8(1)); err != nil {
		t.Fatal(err)
	}
	const action = "value->rules[0].action"
	set := &setmap.Set{SpecRef: setmap.SpecRef{Name: "actions", Mapping: []setmap.MapEntry{{Field: "action", Source: "arg:" + action}}},
		Def: &setmap.Definition{Map: m, KeySize: 1, Fields: []setmap.KeyField{{Name: "action", Size: 1}}, ValFields: []setmap.KeyField{{Name: setmap.ValFieldTag, Size: 1}}}}
	sets, err := filter.ResolveSetFilters([]*setmap.Set{set}, []string{"actions"}, f.targets["idx_fw"].Params)
	if err != nil {
		t.Fatal(err)
	}
	got := f.capture(t, "idx_fw", false, filter.TargetFilters{Sets: sets}, []byte{1, 2, 3})
	if want := []argIndexRecord{{2, action + "=3"}}; !slices.Equal(got, want) {
		t.Errorf("set key: %+v, want %+v", got, want)
	}
	if got := f.echo(t, "idx_fw", []string{action, "value->counts[3]"}, []byte{1}); !slices.Equal(got, []uint64{2, 1}) {
		t.Errorf("echo: %v", got)
	}
}

func TestBpfArgFilterStatusFields(t *testing.T) {
	f := loadArgIndexFixture(t)
	const hook = "idx_sessions_update"
	for name, target := range f.targets {
		if !strings.Contains(name, "update") && !strings.Contains(name, "delete") && !strings.Contains(name, "fifo") {
			continue
		}
		var fields []string
		for _, p := range target.Params {
			for _, field := range attach.StatusFields(p) {
				fields = append(fields, field.Name)
			}
		}
		if !slices.Equal(fields, []string{"status.ret", "status.flags"}) {
			t.Fatalf("hook %s lists status fields %v, params %+v", name, fields, target.Params)
		}
	}
	// Key 1 twice: the first update succeeds, the second fails with -EEXIST.
	packets := []byte{1, 1, 2}
	for _, hook := range []string{hook, "idx_copies_update"} {
		for _, c := range []struct {
			exprs []string
			want  []argIndexRecord
		}{
			{[]string{"status.ret==0"}, []argIndexRecord{{1, "status.ret=0"}, {2, "status.ret=0"}}},
			{[]string{"status.ret==-17"}, []argIndexRecord{{1, "status.ret=-17"}}},
			{[]string{"status.ret<=-1"}, []argIndexRecord{{1, "status.ret=-17"}}},
			{[]string{"status.ret==-2"}, nil},
			{[]string{"status.flags==1"}, []argIndexRecord{{1, "status.flags=1"}, {1, "status.flags=1"}, {2, "status.flags=1"}}},
			{[]string{"status.flags==2"}, nil},
			{[]string{"status.ret==0", "status.flags==1"}, []argIndexRecord{{1, "status.ret=0 status.flags=1"}, {2, "status.ret=0 status.flags=1"}}},
			// Plain status keeps its meaning: the whole word, so 0 selects no BPF_NOEXIST update.
			{[]string{"status==0"}, nil},
			{[]string{"status==0x100000000"}, []argIndexRecord{{1, "status=4294967296"}, {2, "status=4294967296"}}},
			// All three read the same argument and record separately.
			{[]string{"status==0x100000000", "status.ret==0", "status.flags==1"},
				[]argIndexRecord{{1, "status=4294967296 status.ret=0 status.flags=1"}, {2, "status=4294967296 status.ret=0 status.flags=1"}}},
		} {
			for _, exit := range []bool{false, true} {
				args, err := filter.ParseAndValidateFilters(c.exprs, f.targets[hook].Params)
				if err != nil {
					t.Fatalf("%v: %v", c.exprs, err)
				}
				got := f.capture(t, hook, exit, filter.TargetFilters{Args: args}, packets)
				if !slices.Equal(got, c.want) {
					t.Errorf("%s %v exit=%v: %+v, want %+v", hook, c.exprs, exit, got, c.want)
				}
			}
			args, err := filter.ParseAndValidateFilters(c.exprs, f.targets[hook].Params)
			if err != nil {
				t.Fatal(err)
			}
			f.checkPlain(t, hook, filter.TargetFilters{Args: args}, packets, len(c.want))
		}
	}

	// The other hooks with a status: an absent key fails the delete, the push
	// passes BPF_EXIST and succeeds, the pop succeeds and empties the queue, and
	// the peek then fails.
	for _, c := range []struct {
		hook, expr string
		want       int
	}{
		{"idx_gone_delete", "status.ret==-2", 1}, {"idx_gone_delete", "status.flags==0", 1}, {"idx_gone_delete", "status.ret==0", 0},
		{"idx_fifo_push", "status.ret==0", 1}, {"idx_fifo_push", "status.flags==2", 1}, {"idx_fifo_push", "status==0", 0},
		{"idx_fifo_pop", "status.ret==0", 1}, {"idx_fifo_pop", "status.flags==0", 1},
		{"idx_fifo_peek", "status.ret==-2", 1}, {"idx_fifo_peek", "status.flags==0", 1},
	} {
		args, err := filter.ParseAndValidateFilters([]string{c.expr}, f.targets[c.hook].Params)
		if err != nil {
			t.Fatalf("%s %s: %v", c.hook, c.expr, err)
		}
		if got := f.capture(t, c.hook, false, filter.TargetFilters{Args: args}, []byte{1}); len(got) != c.want {
			t.Errorf("%s %s: %+v, want %d records", c.hook, c.expr, got, c.want)
		}
	}

	// A set key uses the shifted field.
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	if err := m.Put(uint32(1), uint8(1)); err != nil {
		t.Fatal(err)
	}
	set := &setmap.Set{SpecRef: setmap.SpecRef{Name: "flags", Mapping: []setmap.MapEntry{{Field: "f", Source: "arg:status.flags"}}},
		Def: &setmap.Definition{Map: m, KeySize: 4, Fields: []setmap.KeyField{{Name: "f", Size: 4}}, ValFields: []setmap.KeyField{{Name: setmap.ValFieldTag, Size: 1}}}}
	sets, err := filter.ResolveSetFilters([]*setmap.Set{set}, []string{"flags"}, f.targets[hook].Params)
	if err != nil {
		t.Fatal(err)
	}
	got := f.capture(t, hook, false, filter.TargetFilters{Sets: sets}, []byte{1})
	if want := []argIndexRecord{{1, "status.flags=1"}}; !slices.Equal(got, want) {
		t.Errorf("set key: %+v, want %+v", got, want)
	}

	f.resetSessions()
	if got := f.echo(t, hook, []string{"status.ret", "status.flags", "status"}, []byte{1, 1}); !slices.Equal(got, []uint64{0, 1, 1 << 32, ^uint64(16), 1, 1<<32 | 0xffffffef}) {
		t.Errorf("echo: %#x", got)
	}
}

// checkPlain runs packets under a capture without a record block and a gated
// capture, which read the filter fields on the path without snapshots.
func (f *argIndexFixture) checkPlain(t *testing.T, hook string, tf filter.TargetFilters, packets []byte, want int) {
	t.Helper()
	for _, c := range []struct {
		name   string
		stages []Stage
		want   int
	}{
		{"plain", []Stage{{Expr: "eth"}}, want},
		{"gated", []Stage{{Expr: "eth"}, {Expr: "eth", IsFexit: true}}, 2 * want},
	} {
		f.resetSessions()
		probe, err := LoadMultiPoint([]attach.Target{f.targets[hook]}, c.stages, []filter.TargetFilters{tf}, true, nil, EmitBoth)
		if err != nil {
			t.Fatalf("%s %s: load: %+v", hook, c.name, err)
		}
		for _, p := range packets {
			data := make([]byte, 64)
			data[0] = p
			if _, err := f.root.Program.Run(&ebpf.RunOptions{Data: data}); err != nil {
				t.Fatal(err)
			}
		}
		if err := probe.Quiesce(); err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, m := range probe.InnerMaps {
			rd, err := fastrb.New(m.FD(), int(m.MaxEntries()))
			if err != nil {
				t.Fatal(err)
			}
			rd.ReadBatch(func([]byte) { count++ })
			_ = rd.Close()
		}
		_ = probe.Close()
		if count != c.want {
			t.Errorf("%s %s %+v: %d records, want %d", hook, c.name, tf.Args, count, c.want)
		}
	}
}

// echo runs packets under --arg-echo on hook and returns the values in order.
func (f *argIndexFixture) echo(t *testing.T, hook string, exprs []string, packets []byte) []uint64 {
	t.Helper()
	target := f.targets[hook]
	params, err := attach.ResolveEchoArgs(exprs, target.Params)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := LoadArgEcho(f.root.Program, hook, nil, params, false, false, attach.FuncAvailability{})
	if err != nil {
		t.Fatalf("load echo: %+v", err)
	}
	defer func() { _ = probe.Close() }()
	rd, err := fastrb.New(probe.EchoRing.FD(), EchoRingSize)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rd.Close() }()
	for _, p := range packets {
		data := make([]byte, 64)
		data[0] = p
		if _, err := f.root.Program.Run(&ebpf.RunOptions{Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	var out []uint64
	rd.ReadBatch(func(rec []byte) {
		for i := 0; i+8 <= len(rec); i += 8 {
			out = append(out, binary.NativeEndian.Uint64(rec[i:]))
		}
	})
	return out
}
