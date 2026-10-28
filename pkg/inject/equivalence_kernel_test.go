package inject

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"golang.org/x/sys/unix"
)

// Run a longer reproducible corpus with a compiled, privileged test binary:
// BPF_NINJA_EQUIV=1 ./inject.test -test.run '^TestBpfMapCallEquivalence$' -test.v
// SEED is the first independent seed, SEEDS the count (defaults: 1, 14).
// Seeds select features modulo 14; only seeds congruent to 1 randomize the
// entry program. Keep the seed and config from a failure; the case is JSON.
// BPF_NINJA_EQUIV_CONFIG optionally selects one named config for reproduction.
// The generated hooks have no side effects; observer behavior is covered by
// the existing kernel fixtures. Nothing attaches to an interface or is pinned.
func TestBpfMapCallEquivalence(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	seeds := equivDefaultSeeds
	if os.Getenv("BPF_NINJA_EQUIV") == "1" {
		first, count := equivEnv(t, "SEED", 1), equivEnv(t, "SEEDS", len(equivFeatures))
		seeds = make([]int, count)
		for i := range seeds {
			seeds[i] = first + i
		}
	}
	var affinity unix.CPUSet
	if err := unix.SchedGetaffinity(0, &affinity); err != nil {
		t.Fatal(err)
	}
	cpu := 0
	for !affinity.IsSet(cpu) {
		cpu++
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	stats := map[string]int{}
	reasons := map[string]int{}
	shapes := map[string]int{}
	defer func() {
		for _, row := range []struct {
			name string
			data map[string]int
		}{{"counts", stats}, {"reasons", reasons}, {"shapes", shapes}} {
			b, _ := json.Marshal(row.data)
			t.Logf("EQUIV %s %s", row.name, b)
		}
	}()
	t.Logf("EQUIV seeds=%v cpu=%d possible_cpus=%d", seeds, cpu, cpus)
	for _, seed := range seeds {
		c := newEquivCase(uint64(seed))
		stats["generated"]++
		for _, op := range c.Ops {
			shapes[fmt.Sprintf("%s/%s/ro=%t/indirect=%t", c.Types[op.Map], op.Kind, op.ReadOnly, op.Indirect)]++
			if op.ReadOnly {
				shapes["readonly/"+op.Pointer]++
			}
		}
		shapes[fmt.Sprintf("floor=%d", c.Floor)]++
		shapes["feature="+c.Feature]++
		for _, config := range []string{"typed-any", "typed-error", "typed-miss", "static-any", "dispatch-any", "dispatch-static", "copy-readonly"} {
			if selected := os.Getenv("BPF_NINJA_EQUIV_CONFIG"); selected != "" && selected != config {
				continue
			}
			t.Run(fmt.Sprintf("seed=%d/%s", seed, config), func(t *testing.T) {
				equivPinCPU(t, cpu)
				// Queue snapshots consume the map, so each config gets a fresh pair.
				plainSpec := c.spec()
				plain, err := ebpf.NewCollection(plainSpec)
				if err != nil {
					stats["plain_rejected"]++
					equivRejection(t, reasons, "plain", seed, config, c, err)
					return
				}
				defer plain.Close()
				plainResources := c.prepare(t, plain, plainSpec)
				defer plainResources.close()
				stats["plain_loaded"]++
				work := c.spec()
				req := c.request(config)
				plan, err := transformLookup(work, req)
				if err != nil {
					if c.ExpectRefusal {
						if errors.Is(err, ErrRefused) && strings.Contains(err.Error(), "512-byte combined limit") {
							stats["expected_refusal"]++
							reasons["expected transform refusal: "+err.Error()]++
							return
						}
						stats["findings"]++
						equivFailure(t, seed, config, c, "unexpected transform refusal: %+v", err)
						return
					}
					if c.RequireTransform {
						stats["findings"]++
						equivFailure(t, seed, config, c, "unexpected transform refusal: %+v", err)
						return
					}
					stats["transform_refused"]++
					equivRejection(t, reasons, "transform", seed, config, c, err)
					return
				}
				if c.ExpectRefusal {
					if !equivHasExpectedSkips(c, plan.skipped) {
						stats["findings"]++
						equivFailure(t, seed, config, c, "transform did not report the required stack refusal: skipped=%v", plan.skipped)
						return
					}
					stats["expected_refusal"]++
				}
				if c.RequireTransform && len(plan.sites) == 0 {
					stats["findings"]++
					equivFailure(t, seed, config, c, "transform skipped every entry map site: %v", plan.skipped)
					return
				}
				for _, s := range plan.skipped {
					stats["sites_skipped"]++
					reasons["site skipped: "+s.Reason]++
				}
				stats["sites_instrumented"] += len(plan.sites)
				injected, err := ebpf.NewCollection(work)
				if err != nil {
					stats["injected_rejected"]++
					// Match only the known arg:untrusted feature-gap diagnostics.
					// All other plain-accepted/injected-rejected pairs fail.
					log := fmt.Sprintf("%+v", err)
					if slices.ContainsFunc(plan.hooks, func(h LookupHook) bool { return h.Untrusted }) &&
						((errors.Is(err, unix.ENOTSUP) || errors.Is(err, ebpf.ErrNotSupported)) && strings.Contains(log, "Caller passes invalid args") ||
							strings.Contains(log, "has unsupported set of tags") || strings.Contains(log, "reference type('UNKNOWN ') size cannot be determined")) {
						stats["unsupported_untrusted"]++
						equivRejection(t, reasons, "unsupported_untrusted", seed, config, c, err)
						return
					}
					stats["findings"]++
					equivFailure(t, seed, config, c, "injected loader: %+v\nplain:\n%v\ninjected:\n%v", err, plainSpec.Programs["p"].Instructions, work.Programs["p"].Instructions)
					return
				}
				defer injected.Close()
				injectedResources := c.prepare(t, injected, work)
				defer injectedResources.close()
				stats["injected_loaded"]++
				for _, coll := range []*ebpf.Collection{plain, injected} {
					if c.Tail {
						if err := coll.Maps["jmp"].Put(uint32(0), coll.Programs["target"]); err != nil {
							t.Fatal(err)
						}
					}
				}
				bloomProbes := map[uint64]bool{}
				for n, packet := range c.packets(cpus) {
					retA, outA, errA := equivRun(plain.Programs["p"], packet)
					if errA != nil {
						t.Fatalf("plain test run seed=%d packet=%d: %v", seed, n, errA)
					}
					retB, outB, errB := equivRun(injected.Programs["p"], packet)
					stats["packet_pairs"]++
					if errB != nil || retA != retB || !bytes.Equal(outA, outB) {
						stats["findings"]++
						equivFailure(t, seed, config, c, "packet=%d input=%x plain=(%d,%x,%v) injected=(%d,%x,%v)", n, packet, retA, outA, errA, retB, outB, errB)
						return
					}
					for i, op := range c.Ops {
						if c.Types[op.Map] == ebpf.BloomFilter && op.Kind == HookPush {
							bloomProbes[binary.LittleEndian.Uint64(outA[88+16*i:])] = true
						}
					}
				}
				a := equivSnapshot(t, plain, plainResources, c, cpus, bloomProbes)
				b := equivSnapshot(t, injected, injectedResources, c, cpus, bloomProbes)
				if !reflect.DeepEqual(a, b) {
					stats["findings"]++
					equivFailure(t, seed, config, c, "final maps: plain=%v injected=%v", a, b)
					return
				}
				stats["equivalent"]++
			})
		}
		// This also records discarded seeds, without repeating long verifier logs.
		t.Logf("EQUIV seed=%d complete", seed)
	}
	if stats["equivalent"] == 0 && stats["expected_refusal"] == 0 {
		t.Fatal("no executable equivalence pairs; see rejection counts")
	}
}

func equivPinCPU(t *testing.T, cpu int) {
	t.Helper()
	runtime.LockOSThread()
	var affinity, pinned unix.CPUSet
	if err := unix.SchedGetaffinity(0, &affinity); err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	pinned.Set(cpu)
	if err := unix.SchedSetaffinity(0, &pinned); err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.SchedSetaffinity(0, &affinity); err != nil {
			t.Error(err)
		}
		runtime.UnlockOSThread()
	})
}

func equivHasExpectedSkips(c equivCase, skipped []LookupSite) bool {
	const (
		nonEntry = "lookup is not in the entry function; ctx belongs to another stack frame"
		stack    = "after the transform the call chain p -> leaf uses 544 bytes of stack, past the kernel's 512-byte combined limit (frames rounded to 32 bytes)"
	)
	want := []LookupSite{{Op: HookUpdate, MapName: "sessions", FuncName: "p", Reason: stack}}
	if c.Feature == "stack-lookup-fallback" {
		want = append(want, LookupSite{Op: HookLookup, MapName: "sessions", FuncName: "leaf", Reason: nonEntry})
	}
	if len(skipped) != len(want) {
		return false
	}
	for _, expected := range want {
		if !slices.ContainsFunc(skipped, func(site LookupSite) bool {
			return site.Op == expected.Op && site.MapName == expected.MapName && site.FuncName == expected.FuncName && site.Reason == expected.Reason
		}) {
			return false
		}
	}
	return true
}

func equivEnv(t *testing.T, suffix string, fallback int) int {
	t.Helper()
	s := os.Getenv("BPF_NINJA_EQUIV_" + suffix)
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		t.Fatalf("invalid BPF_NINJA_EQUIV_%s=%q", suffix, s)
	}
	return n
}

func equivFailure(t *testing.T, seed int, config string, c equivCase, format string, args ...any) {
	t.Helper()
	b, _ := json.Marshal(c)
	t.Errorf("EQUIV FINDING seed=%d config=%s case=%s\n%s", seed, config, b, fmt.Sprintf(format, args...))
}

func equivRejection(t *testing.T, reasons map[string]int, stage string, seed int, config string, c equivCase, err error) {
	t.Helper()
	key := stage + ": " + err.Error()
	reasons[key]++
	if reasons[key] == 1 {
		b, _ := json.Marshal(c)
		t.Logf("EQUIV rejection seed=%d config=%s stage=%s case=%s\n%+v", seed, config, stage, b, err)
	}
}

func (c equivCase) request(config string) LookupRequest {
	r := LookupRequest{ProgramName: "p", Auto: true, HookName: "eq", Entry: true, TailCalls: c.Tail,
		Lookups: LookupAny, Updates: CallAny, Deletes: CallAny, Pushes: CallAny, Pops: CallAny, Peeks: CallAny,
		Stack: StackAudit{LowestOffset: c.Floor}}
	switch config {
	case "typed-error":
		r.Lookups, r.Updates, r.Deletes, r.Pushes, r.Pops, r.Peeks = LookupHit, CallError, CallError, CallError, CallError, CallError
	case "typed-miss":
		r.Lookups = LookupMiss
	case "static-any":
		r.StaticUntrusted = true
	case "dispatch-any":
		r.Dispatch = true
	case "dispatch-static":
		r.Dispatch, r.StaticUntrusted = true, true
	case "copy-readonly":
		r.CopyReadOnly, r.StaticUntrusted = true, true
	}
	return r
}

func equivRun(p *ebpf.Program, packet []byte) (uint32, []byte, error) {
	opts := ebpf.RunOptions{Data: slices.Clone(packet), DataOut: make([]byte, len(packet)), Repeat: 1}
	ret, err := p.Run(&opts)
	return ret, opts.DataOut, err
}

// Queue/stack inspection is destructive and happens only after the complete
// packet sequence. Bloom maps expose membership, not their bitset: probe the
// deterministic corpus of inserted candidates plus misses using Lookup.
func equivSnapshot(t *testing.T, coll *ebpf.Collection, resources equivResources, c equivCase, cpus int, bloomProbes map[uint64]bool) map[string]any {
	t.Helper()
	if c.Feature != "entry" {
		return c.featureSnapshot(t, coll, resources)
	}
	result := map[string]any{}
	for i, typ := range c.Types {
		name := fmt.Sprintf("m%d", i)
		m := coll.Maps[name]
		switch typ {
		case ebpf.Queue, ebpf.Stack:
			values := []uint64{}
			for {
				var v uint64
				err := m.LookupAndDelete(nil, &v)
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				values = append(values, v)
			}
			result[name] = values
		case ebpf.BloomFilter:
			membership := map[uint64]bool{}
			for v := uint64(0); v < 64; v++ {
				bloomProbes[v] = true
			}
			for v := range bloomProbes {
				probe := v
				err := m.Lookup(nil, &probe)
				if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatal(err)
				}
				membership[v] = err == nil
			}
			result[name] = membership
		case ebpf.PerCPUArray:
			var values [][]uint64
			for key := uint32(0); key < 8; key++ {
				v := make([]uint64, cpus)
				if err := m.Lookup(key, &v); err != nil {
					t.Fatal(err)
				}
				values = append(values, v)
			}
			result[name] = values
		default:
			values := map[uint32]uint64{}
			var key uint32
			var v uint64
			it := m.Iterate()
			for it.Next(&key, &v) {
				values[key] = v
			}
			if err := it.Err(); err != nil {
				t.Fatal(err)
			}
			result[name] = values
		}
	}
	return result
}

type equivResources struct {
	inner *ebpf.Map
}

func (r equivResources) close() {
	if r.inner != nil {
		_ = r.inner.Close()
	}
}

func (c equivCase) prepare(t *testing.T, coll *ebpf.Collection, spec *ebpf.CollectionSpec) equivResources {
	t.Helper()
	if c.Feature != "read-only-inner-array" && c.Feature != "inner-hash" && c.Feature != "inner-queue" {
		return equivResources{}
	}
	inner, err := ebpf.NewMap(spec.Maps["outer"].InnerMap)
	if err != nil {
		t.Fatal(err)
	}
	switch c.Feature {
	case "read-only-inner-array":
		err = inner.Put(uint32(0), uint64(42))
	case "inner-hash":
		if err = inner.Put(uint32(0), uint64(2)); err == nil {
			err = inner.Put(uint32(1), uint64(1))
		}
	}
	if err == nil {
		err = coll.Maps["outer"].Put(uint32(0), inner)
	}
	if err != nil {
		_ = inner.Close()
		t.Fatal(err)
	}
	return equivResources{inner: inner}
}

func (c equivCase) featureSnapshot(t *testing.T, coll *ebpf.Collection, resources equivResources) map[string]any {
	t.Helper()
	result := map[string]any{}
	if q := coll.Maps["q"]; q != nil {
		result["q"] = equivDrainQueue(t, q)
	}
	if sessions := coll.Maps["sessions"]; sessions != nil {
		result["sessions"] = equivU32U64Map(t, sessions)
	}
	if resources.inner == nil {
		return result
	}
	switch c.Feature {
	case "inner-queue":
		result["inner"] = equivDrainQueue(t, resources.inner)
	case "inner-hash":
		result["inner"] = equivU32U64Map(t, resources.inner)
	case "read-only-inner-array":
		var value uint64
		if err := resources.inner.Lookup(uint32(0), &value); err != nil {
			t.Fatal(err)
		}
		result["inner"] = value
	}
	return result
}

func equivDrainQueue(t *testing.T, m *ebpf.Map) []uint64 {
	t.Helper()
	var values []uint64
	for {
		var value uint64
		err := m.LookupAndDelete(nil, &value)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return values
		}
		if err != nil {
			t.Fatal(err)
		}
		values = append(values, value)
	}
}

func equivU32U64Map(t *testing.T, m *ebpf.Map) map[uint32]uint64 {
	t.Helper()
	values := map[uint32]uint64{}
	var key uint32
	var value uint64
	it := m.Iterate()
	for it.Next(&key, &value) {
		values[key] = value
	}
	if err := it.Err(); err != nil {
		t.Fatal(fmt.Errorf("snapshot map: %w", err))
	}
	return values
}
