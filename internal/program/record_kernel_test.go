package program

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/output"
	"github.com/takehaya/bpf-ninja/internal/record"
	"github.com/takehaya/bpf-ninja/internal/recordbuild"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// The packet's first byte selects a policy. Injection adds a typed lookup
// hook and an update hook (with status) on pols, and, because ro is
// read-only for the program, a static lookup hook on ro.
const recordSource = `
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
struct pol_key { __u32 policy_index; };
struct pol { __u32 pol_rc; __u16 port; __u16 pad; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, struct pol_key);
    __type(value, struct pol);
} pols SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __uint(map_flags, BPF_F_RDONLY_PROG);
    __type(key, __u32);
    __type(value, __u32);
} ro SEC(".maps");
SEC("xdp")
int record_target(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    if (data + 1 > end) return XDP_ABORTED;
    __u32 idx = *(__u8 *)data;
    struct pol_key key = { .policy_index = idx };
    int verdict = XDP_PASS;
    struct pol *p = bpf_map_lookup_elem(&pols, &key);
    if (p && p->pol_rc == 0) verdict = XDP_DROP;
    struct pol nv = { .pol_rc = idx * 10 };
    bpf_map_update_elem(&pols, &key, &nv, BPF_EXIST);
    __u32 *r = bpf_map_lookup_elem(&ro, &idx);
    if (r && *r == 0) verdict = XDP_DROP;
    return verdict;
}
char _license[] SEC("license") = "GPL";
`

// recordEPB is one EPB of a written capture: interface, packet index
// (first data byte) and opt_comment.
type recordEPB struct {
	iface uint32
	idx   byte
	note  string
}

// readRecordEPBs walks a little-endian pcapng file independently of the
// writer.
func readRecordEPBs(t *testing.T, path string) []recordEPB {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []recordEPB
	for off := 0; off+12 <= len(b); {
		n := int(binary.LittleEndian.Uint32(b[off+4:]))
		blk := b[off : off+n]
		off += n
		if binary.LittleEndian.Uint32(blk) != 6 {
			continue
		}
		caplen := int(binary.LittleEndian.Uint32(blk[20:]))
		e := recordEPB{iface: binary.LittleEndian.Uint32(blk[8:]), idx: blk[28]}
		for o := 28 + (caplen+3)&^3; o < len(blk)-4; {
			code, l := binary.LittleEndian.Uint16(blk[o:]), int(binary.LittleEndian.Uint16(blk[o+2:]))
			if code == 1 {
				e.note = string(blk[o+4 : o+4+l])
			}
			o += 4 + (l+3)&^3
		}
		out = append(out, e)
	}
	return out
}

func TestBpfRecordAtHook(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	obj := os.Getenv("BPF_NINJA_RECORD_OBJECT")
	if obj == "" {
		obj = testutil.CompileBPFSource(t, recordSource)
	}
	elf, err := os.ReadFile(obj)
	if err != nil {
		t.Fatal(err)
	}
	res, err := inject.TransformLookup(elf, inject.LookupRequest{
		ELFSHA256: fmt.Sprintf("%x", sha256.Sum256(elf)), ProgramName: "record_target", Auto: true,
		Updates: inject.CallAny, StaticUntrusted: true, HookName: "rec", Stack: inject.StackAudit{LowestOffset: -64},
	})
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(res.Spec)
	if err != nil {
		t.Fatalf("loading the injected program: %v", err)
	}
	defer coll.Close()
	site := map[string]uint32{}
	for _, h := range res.Hooks {
		site[h.Name] = h.Sites[0].SitePC
		t.Logf("hook %s static=%v site=%d", h.Name, h.Static, h.Sites[0].SitePC)
	}
	names := []string{"rec_pols", "rec_pols_update", "rec_ro"}
	for _, n := range names {
		if _, ok := site[n]; !ok {
			t.Fatalf("hooks %+v lack %s", res.Hooks, n)
		}
	}
	prog := coll.Programs["record_target"]
	info, err := prog.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	root, err := attach.FindBPFProgramByID(uint32(id))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Program.Close() }()
	targets, _, err := attach.ResolveTargets([]*attach.ProgInfo{root}, names, false)
	if err != nil || len(targets) != 3 {
		t.Fatalf("targets %+v: %v", targets, err)
	}

	// expect returns the comment of hook h's call for packet idx, and
	// whether the capture records the call at all.
	type expect func(h string, idx uint32) (string, bool)
	pol := func(idx uint32) bool { return idx >= 1 && idx <= 3 }
	status := func(idx uint32) uint64 { // BPF_EXIST << 32 | (u32)ret
		if pol(idx) {
			return 2 << 32
		}
		return 2<<32 | uint64(uint32(0xfffffffe)) // -ENOENT
	}
	cases := []struct {
		name   string
		exit   bool
		opt    recordbuild.Options
		exprs  map[string][]string
		expect expect
	}{
		{"filter", false, recordbuild.Options{Mode: record.ModeFilter}, map[string][]string{
			"rec_pols":        {"value->pol_rc>=3", "key->policy_index<=9"},
			"rec_pols_update": {"value->pol_rc>=20"},
			"rec_ro":          {"value[0]>=14"},
		}, func(h string, idx uint32) (string, bool) {
			switch h {
			case "rec_pols":
				return fmt.Sprintf("value->pol_rc=%d key->policy_index=%d", idx+1, idx), pol(idx) && idx+1 >= 3
			case "rec_pols_update":
				return fmt.Sprintf("value->pol_rc=%d", idx*10), idx*10 >= 20
			}
			return fmt.Sprintf("value[0]=%d", idx*7), pol(idx) && idx*7 >= 14
		}},
		{"entry", false, recordbuild.Options{Mode: record.ModeEntry, MaxBytes: 256}, nil, func(h string, idx uint32) (string, bool) {
			switch h {
			case "rec_pols":
				return fmt.Sprintf("site=%d key->policy_index=%d value->pol_rc=%d value->port=%d value->pad=0", site[h], idx, idx+1, 1000+idx), pol(idx)
			case "rec_pols_update":
				return fmt.Sprintf("site=%d status=0x%016x key->policy_index=%d value->pol_rc=%d value->port=0 value->pad=0", site[h], status(idx), idx, idx*10), true
			}
			return fmt.Sprintf("site=%d key[0]=%d value[0]=%d", site[h], idx, idx*7), pol(idx)
		}},
		{"entry-capped-exit", true, recordbuild.Options{Mode: record.ModeEntry, MaxBytes: 4}, nil, func(h string, idx uint32) (string, bool) {
			switch h {
			case "rec_pols":
				return fmt.Sprintf("site=%d key->policy_index=%d value->pol_rc=%d value_bytes=4/8", site[h], idx, idx+1), pol(idx)
			case "rec_pols_update":
				return fmt.Sprintf("site=%d status=0x%016x key->policy_index=%d value->pol_rc=%d value_bytes=4/8", site[h], status(idx), idx, idx*10), true
			}
			return fmt.Sprintf("site=%d key[0]=%d value[0]=%d", site[h], idx, idx*7), pol(idx)
		}},
		{"none", false, recordbuild.Options{Mode: record.ModeNone}, nil, func(h string, idx uint32) (string, bool) {
			return "", h == "rec_pols_update" || pol(idx)
		}},
	}
	packets := []uint32{1, 2, 3, 5}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for i := uint32(1); i <= 3; i++ {
				if err := coll.Maps["pols"].Put(i, [2]uint32{i + 1, 1000 + i}); err != nil {
					t.Fatal(err)
				}
				if err := coll.Maps["ro"].Put(i, i*7); err != nil {
					t.Fatal(err)
				}
			}
			var filters []filter.TargetFilters
			if c.exprs != nil {
				filters = make([]filter.TargetFilters, len(targets))
				for i, tg := range targets {
					if filters[i].Args, err = filter.ParseAndValidateFilters(c.exprs[tg.FuncName], tg.Params); err != nil {
						t.Fatal(err)
					}
				}
			}
			var layouts []*record.Layout
			if c.opt.Mode != record.ModeNone {
				layouts = make([]*record.Layout, len(targets))
				for i, tg := range targets {
					var tf filter.TargetFilters
					if filters != nil {
						tf = filters[i]
					}
					if layouts[i], err = recordbuild.Build(tg, tf, c.opt); err != nil || layouts[i] == nil {
						t.Fatalf("layout %s: %v", tg.FuncName, err)
					}
				}
			}
			probe, err := LoadMultiPointRecord(targets, []Stage{{IsFexit: c.exit}}, filters, true, nil, EmitBoth, layouts)
			if err != nil {
				t.Fatal(err)
			}
			for _, idx := range packets {
				data := make([]byte, 64)
				data[0] = byte(idx)
				if _, err := prog.Run(&ebpf.RunOptions{Data: data}); err != nil {
					t.Fatal(err)
				}
			}
			var pkts []capture.Packet
			for _, inner := range probe.InnerMaps {
				rd, err := fastrb.New(inner.FD(), int(inner.MaxEntries()))
				if err != nil {
					t.Fatal(err)
				}
				rd.ReadBatch(func(raw []byte) {
					p, err := capture.ParseRawSample(raw)
					if err != nil {
						t.Fatal(err)
					}
					p.Data, p.Record = append([]byte(nil), p.Data...), append([]byte(nil), p.Record...)
					if len(p.Record) == 0 {
						p.Record = nil
					}
					pkts = append(pkts, p)
				})
				_ = rd.Close()
			}
			if err := probe.Close(); err != nil {
				t.Fatal(err)
			}

			want := map[recordEPB]int{}
			for i, tg := range targets {
				for _, idx := range packets {
					if note, ok := c.expect(tg.FuncName, idx); ok {
						if c.exit {
							// The hook returns 0; an exit capture records it first.
							note = "return=0x00000000 " + note
						}
						want[recordEPB{uint32(i), byte(idx), note}]++
					}
				}
			}
			got := map[recordEPB]int{}
			if layouts == nil {
				for _, p := range pkts {
					if p.Record != nil || p.SiteID != 0 || p.Mode != 0 {
						t.Fatalf("plain capture carries a record: %+v", p)
					}
				}
				for k, n := range want {
					got[recordEPB{0, k.idx, ""}] += n
				}
				for _, p := range pkts {
					got[recordEPB{0, p.Data[0], ""}]--
				}
				for k, n := range got {
					if n != 0 {
						t.Fatalf("packet %d: %d records missing (negative: extra)", k.idx, n)
					}
				}
				return
			}
			path := filepath.Join(t.TempDir(), "record.pcapng")
			w, err := output.NewWriter(path, output.Config{Hooks: names, Records: layouts, NoRunIDs: true, RecordReturn: c.exit})
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range pkts {
				if c.exit && p.Mode != 1 {
					t.Fatalf("exit record has mode %d", p.Mode)
				}
			}
			if err := w.WriteBatch(pkts); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			for _, e := range readRecordEPBs(t, path) {
				got[e]++
			}
			for k, n := range want {
				if got[k] != n {
					t.Errorf("%s packet %d: want %q x%d, got x%d", names[k.iface], k.idx, k.note, n, got[k])
				}
			}
			for k, n := range got {
				if want[k] != n {
					t.Errorf("unexpected %s packet %d %q x%d", names[k.iface], k.idx, k.note, n)
				}
			}
		})
	}
}

// recordFixtureELF compiles (or reads) the fixture object once.
func recordFixtureELF(t *testing.T) []byte {
	t.Helper()
	testutil.SkipIfNotRoot(t)
	obj := os.Getenv("BPF_NINJA_RECORD_OBJECT")
	if obj == "" {
		obj = testutil.CompileBPFSource(t, recordSource)
	}
	elf, err := os.ReadFile(obj)
	if err != nil {
		t.Fatal(err)
	}
	return elf
}

// loadInjected transforms and loads the fixture, returning the root prog id.
// It skips when the kernel rejects the transformed load (e.g. arg:untrusted
// unsupported), which is the documented pre-6.18 behaviour.
func loadInjected(t *testing.T, elf []byte, req inject.LookupRequest) (*inject.LookupResult, uint32) {
	t.Helper()
	req.ELFSHA256 = fmt.Sprintf("%x", sha256.Sum256(elf))
	res, err := inject.TransformLookup(elf, req)
	if err != nil {
		t.Fatal(err)
	}
	// Skip only on the arg:untrusted rejection (as pkg/inject's loadHooked
	// does), never on any other load error; the audit allowlist lists these
	// tests for 6.1/6.6/6.12/6.15.
	coll, err := ebpf.NewCollection(res.Spec)
	if err != nil {
		untrusted := false
		for _, h := range res.Hooks {
			untrusted = untrusted || h.Untrusted
		}
		var ve *ebpf.VerifierError
		if untrusted && errors.As(err, &ve) {
			if log := fmt.Sprintf("%+v", ve); strings.Contains(log, "has unsupported set of tags") ||
				strings.Contains(log, "reference type('UNKNOWN ') size cannot be determined") {
				t.Skipf("skipping: kernel lacks arg:untrusted: %v", err)
			}
		}
		t.Fatalf("loading the injected program: %v", err)
	}
	t.Cleanup(coll.Close)
	info, err := coll.Programs["record_target"].Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	return res, uint32(id)
}

// recordRun attaches an entry capture that records on each named hook, runs
// the four packets, writes a pcapng and returns its EPBs.
func recordRun(t *testing.T, id uint32, names []string, opt recordbuild.Options) (*ebpf.Program, []recordEPB) {
	t.Helper()
	root, err := attach.FindBPFProgramByID(id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Program.Close() })
	targets, _, err := attach.ResolveTargets([]*attach.ProgInfo{root}, names, false)
	if err != nil || len(targets) != len(names) {
		t.Fatalf("targets %+v: %v", targets, err)
	}
	layouts := make([]*record.Layout, len(targets))
	for i, tg := range targets {
		if layouts[i], err = recordbuild.Build(tg, filter.TargetFilters{}, opt); err != nil || layouts[i] == nil {
			t.Fatalf("layout %s: %v", tg.FuncName, err)
		}
	}
	probe, err := LoadMultiPointRecord(targets, []Stage{{}}, nil, true, nil, EmitBoth, layouts)
	if err != nil {
		t.Fatal(err)
	}
	prog := root.Program
	for _, idx := range []uint32{1, 2, 3, 5} {
		data := make([]byte, 64)
		data[0] = byte(idx)
		if _, err := prog.Run(&ebpf.RunOptions{Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	var pkts []capture.Packet
	for _, inner := range probe.InnerMaps {
		rd, err := fastrb.New(inner.FD(), int(inner.MaxEntries()))
		if err != nil {
			t.Fatal(err)
		}
		rd.ReadBatch(func(raw []byte) {
			p, err := capture.ParseRawSample(raw)
			if err != nil {
				t.Fatal(err)
			}
			p.Data, p.Record = append([]byte(nil), p.Data...), append([]byte(nil), p.Record...)
			if len(p.Record) == 0 {
				p.Record = nil
			}
			pkts = append(pkts, p)
		})
		_ = rd.Close()
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "r.pcapng")
	w, err := output.NewWriter(path, output.Config{Hooks: names, Records: layouts, NoRunIDs: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteBatch(pkts); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return prog, readRecordEPBs(t, path)
}

// siteOf returns the first site PC of the named hook in a transform result.
func siteOf(res *inject.LookupResult, name string) uint32 {
	for _, h := range res.Hooks {
		if h.Name == name && len(h.Sites) > 0 {
			return h.Sites[0].SitePC
		}
	}
	return 0
}

// seedRecordMaps fills pols and ro of the loaded program with keys 1..3.
func seedRecordMaps(t *testing.T, id uint32) {
	t.Helper()
	root, err := attach.FindBPFProgramByID(id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Program.Close() }()
	info, _ := root.Program.Info()
	ids, _ := info.MapIDs()
	for _, mid := range ids {
		m, err := ebpf.NewMapFromID(mid)
		if err != nil {
			continue
		}
		mi, _ := m.Info()
		for i := uint32(1); i <= 3; i++ {
			var perr error
			switch mi.Name {
			case "pols":
				perr = m.Put(i, [2]uint32{i + 1, 1000 + i})
			case "ro":
				perr = m.Put(i, i*7)
			}
			if perr != nil {
				t.Fatalf("seed %s[%d]: %v", mi.Name, i, perr)
			}
		}
		_ = m.Close()
	}
}

// TestBpfRecordUntrustedHook records at an untrusted (void) lookup hook on a
// read-only map; entry mode must use the key_size/value_size decl tags
// inject-run attached. Skips where the kernel rejects arg:untrusted.
func TestBpfRecordUntrustedHook(t *testing.T) {
	elf := recordFixtureELF(t)
	res, id := loadInjected(t, elf, inject.LookupRequest{ProgramName: "record_target", Auto: true,
		HookName: "rec", Stack: inject.StackAudit{LowestOffset: -64}}) // no StaticUntrusted → untrusted void on 6.18+
	seedRecordMaps(t, id)
	root, err := attach.FindBPFProgramByID(id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Program.Close() })
	tgs, _, err := attach.ResolveTargets([]*attach.ProgInfo{root}, []string{"rec_ro"}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range tgs[0].Params {
		t.Logf("rec_ro param %q kind=%q voidsize=%d", p.Name, p.Kind, p.VoidSize)
	}
	l, err := recordbuild.Build(tgs[0], filter.TargetFilters{}, recordbuild.Options{Mode: record.ModeEntry, MaxBytes: 256})
	if err != nil {
		t.Fatal(err)
	}
	if !l.Key.Pointer || l.Key.Len != 4 || l.Value.Len != 4 {
		t.Fatalf("void key/value not sized from decl tags: key=%+v value=%+v", l.Key, l.Value)
	}
	_, epbs := recordRun(t, id, []string{"rec_ro"}, recordbuild.Options{Mode: record.ModeEntry, MaxBytes: 256})
	site := siteOf(res, "rec_ro")
	le := func(v uint32) string {
		return fmt.Sprintf("%02x%02x%02x%02x", byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	}
	// ro holds keys 1..3; packet 5 misses, so the hit hook never fires for it.
	want := map[string]int{}
	for idx := uint32(1); idx <= 3; idx++ {
		want[fmt.Sprintf("%d site=%d key=%s value=%s", idx, site, le(idx), le(idx*7))]++
	}
	if got := noteCounts(epbs); !maps.Equal(got, want) {
		t.Fatalf("untrusted records %v, want %v", got, want)
	}
}

// noteCounts is the multiset of "packet-index comment" of a capture.
func noteCounts(epbs []recordEPB) map[string]int {
	m := map[string]int{}
	for _, e := range epbs {
		m[fmt.Sprintf("%d %s", e.idx, e.note)]++
	}
	return m
}

// dispatchWant is what a lookup-only dispatch hook records: packets 1..3
// hit both lookups (packet 5 misses, and a miss is not observed), and a
// lookup passes info = its site.
func dispatchWant(res *inject.LookupResult) map[string]int {
	sites := map[uint32]bool{}
	for _, hk := range res.Hooks { // a dispatch result spreads sites across elements
		for _, st := range hk.Sites {
			sites[st.SitePC] = true
		}
	}
	want := map[string]int{}
	for pc := range sites {
		for idx := 1; idx <= 3; idx++ {
			want[fmt.Sprintf("%d site=%d info=0x%016x", idx, pc, pc)]++
		}
	}
	return want
}

// TestBpfRecordDispatchHook records at a dispatch hook (generic, void key and
// value, no size tags), so entry records only site and status; the run must
// load and produce records. Skips where arg:untrusted is unsupported.
func TestBpfRecordDispatchHook(t *testing.T) {
	elf := recordFixtureELF(t)
	res, id := loadInjected(t, elf, inject.LookupRequest{ProgramName: "record_target", Auto: true,
		Dispatch: true, HookName: "rec", Stack: inject.StackAudit{LowestOffset: -448}})
	if len(res.Hooks) == 0 {
		t.Fatal("no dispatch hook")
	}
	seedRecordMaps(t, id)
	_, epbs := recordRun(t, id, []string{res.Hooks[0].Name}, recordbuild.Options{Mode: record.ModeEntry, MaxBytes: 256})
	if got, want := noteCounts(epbs), dispatchWant(res); len(want) != 6 || !maps.Equal(got, want) {
		t.Fatalf("dispatch records %v, want %v", got, want)
	}
}

// TestBpfRecordDispatchStatic records at a static dispatch hook, which loads
// on every kernel (no arg:untrusted), so this case must pass everywhere and
// gives the record path old-kernel coverage. A dispatch hook serves several
// maps and carries no size tags, so entry records only site and status.
func TestBpfRecordDispatchStatic(t *testing.T) {
	elf := recordFixtureELF(t)
	res, id := loadInjected(t, elf, inject.LookupRequest{ProgramName: "record_target", Auto: true,
		Dispatch: true, StaticUntrusted: true, HookName: "rec", Stack: inject.StackAudit{LowestOffset: -448}})
	if len(res.Hooks) == 0 || !res.Hooks[0].Static {
		t.Fatalf("expected a static dispatch hook: %+v", res.Hooks)
	}
	seedRecordMaps(t, id)
	_, epbs := recordRun(t, id, []string{res.Hooks[0].Name}, recordbuild.Options{Mode: record.ModeEntry, MaxBytes: 256})
	if got, want := noteCounts(epbs), dispatchWant(res); len(want) != 6 || !maps.Equal(got, want) {
		t.Fatalf("static dispatch records %v, want %v", got, want)
	}
}

// TestBpfRecordFilterSets records at rec_pols with argument filters on
// value->pol_rc and value!=null, plus either a --set on key->policy_index or
// two --sets on value->pol_rc that reuse the filters' read, in filter and
// exit modes. It checks that only packets matching all are recorded, with
// the values the conditions tested, and that the tested pointer stays out of
// the file.
func TestBpfRecordFilterSets(t *testing.T) {
	elf := recordFixtureELF(t)
	_, id := loadInjected(t, elf, inject.LookupRequest{ProgramName: "record_target", Auto: true,
		Updates: inject.CallAny, StaticUntrusted: true, HookName: "rec", Stack: inject.StackAudit{LowestOffset: -64}})
	seedRecordMaps(t, id)
	root, err := attach.FindBPFProgramByID(id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Program.Close() })
	targets, _, err := attach.ResolveTargets([]*attach.ProgInfo{root}, []string{"rec_pols"}, false)
	if err != nil || len(targets) != 1 {
		t.Fatalf("targets %+v: %v", targets, err)
	}
	idx := map[string]int{}
	for _, p := range targets[0].Params {
		idx[p.Name] = p.Index
	}
	if idx["key"] == 0 || idx["value"] == 0 {
		t.Fatalf("rec_pols params %+v", targets[0].Params)
	}
	// set returns a --set on one u32 field holding keys.
	set := func(param string, paramIdx int, keys ...uint32) filter.SetFilter {
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 4})
		if err != nil {
			t.Skipf("set map: %v", err)
		}
		t.Cleanup(func() { _ = m.Close() })
		for _, k := range keys {
			if err := m.Put(k, uint8(1)); err != nil {
				t.Fatal(err)
			}
		}
		return filter.SetFilter{Map: m, KeySize: 4, StateOff: -1, Fields: []filter.SetKeyField{{
			FieldName: "f", FieldSize: 4, ParamName: param, ParamIdx: paramIdx, ParamSize: 4, Deref: true}}}
	}
	args, err := filter.ParseAndValidateFilters([]string{"value->pol_rc>=3", "value->pol_rc<=9", "value!=null"}, targets[0].Params)
	if err != nil {
		t.Fatal(err)
	}
	// pols[i].pol_rc is i+1 for packets 1..3. key-set: the set reads its own
	// field. shared: both sets key on value->pol_rc, which the argument
	// filters already read, so they take its snapshot.
	cases := []struct {
		name string
		tf   filter.TargetFilters
		want []string
	}{
		{"key-set", filter.TargetFilters{Args: args, Sets: []filter.SetFilter{set("key->policy_index", idx["key"], 2, 3)}},
			[]string{"value->pol_rc=3 value!=null key->policy_index=2", "value->pol_rc=4 value!=null key->policy_index=3"}},
		{"shared", filter.TargetFilters{Args: args, Sets: []filter.SetFilter{
			set("value->pol_rc", idx["value"], 4, 9), set("value->pol_rc", idx["value"], 3, 4)}},
			[]string{"value->pol_rc=4 value!=null"}},
	}
	for _, c := range cases {
		for _, exit := range []bool{false, true} {
			name := c.name + "/filter"
			if exit {
				name = c.name + "/exit"
			}
			tf := c.tf
			t.Run(name, func(t *testing.T) {
				seedRecordMaps(t, id)
				layout, err := recordbuild.Build(targets[0], tf, recordbuild.Options{Mode: record.ModeFilter})
				if err != nil || layout == nil {
					t.Fatalf("layout %v", err)
				}
				probe, err := LoadMultiPointRecord(targets, []Stage{{IsFexit: exit}}, []filter.TargetFilters{tf}, true, nil, EmitBoth, []*record.Layout{layout})
				if err != nil {
					t.Fatal(err)
				}
				for _, idx := range []uint32{1, 2, 3} {
					data := make([]byte, 64)
					data[0] = byte(idx)
					if _, err := root.Program.Run(&ebpf.RunOptions{Data: data}); err != nil {
						t.Fatal(err)
					}
				}
				var pkts []capture.Packet
				for _, inner := range probe.InnerMaps {
					rd, err := fastrb.New(inner.FD(), int(inner.MaxEntries()))
					if err != nil {
						t.Fatal(err)
					}
					rd.ReadBatch(func(raw []byte) {
						p, err := capture.ParseRawSample(raw)
						if err != nil {
							t.Fatal(err)
						}
						p.Data, p.Record = append([]byte(nil), p.Data...), append([]byte(nil), p.Record...)
						pkts = append(pkts, p)
					})
					_ = rd.Close()
				}
				if err := probe.Close(); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "s.pcapng")
				w, err := output.NewWriter(path, output.Config{Hooks: []string{"rec_pols"}, Records: []*record.Layout{layout}, NoRunIDs: true, RecordReturn: exit})
				if err != nil {
					t.Fatal(err)
				}
				if err := w.WriteBatch(pkts); err != nil {
					t.Fatal(err)
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				// The NULL test's slot carries the pointer itself; only its
				// null/!=null rendering may reach the file.
				file, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				for i, f := range layout.Fields {
					if !f.Pointer {
						continue
					}
					for _, p := range pkts {
						v := p.Record[record.HeaderSize+8*i:][:8]
						if bytes.Equal(v, make([]byte, 8)) || bytes.Contains(file, v) {
							t.Fatalf("%s: pointer slot %x is zero or in the file", name, v)
						}
					}
				}
				got := map[string]int{}
				for _, e := range readRecordEPBs(t, path) {
					got[e.note]++
				}
				want := map[string]int{}
				for _, note := range c.want {
					if exit {
						note = "return=0x00000000 " + note
					}
					want[note]++
				}
				if !maps.Equal(got, want) {
					t.Fatalf("%s: got %v want %v", name, got, want)
				}
			})
		}
	}
}
