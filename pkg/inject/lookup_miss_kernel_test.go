package inject

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"golang.org/x/sys/unix"
)

func TestBpfLookupMiss(t *testing.T) { testLookupMissTyped(t, lookupFixture, LookupMiss) }
func TestBpfLookupAny(t *testing.T)  { testLookupMissTyped(t, lookupFixture, LookupAny) }

// The miss hook of a read-only map takes its key as ordinary memory, since
// the key is the program's, so it loads where arg:untrusted does not.
func TestBpfLookupMissReadOnlyMap(t *testing.T) {
	testLookupMissTyped(t, func() *ebpf.CollectionSpec {
		spec := lookupFixture()
		spec.Maps["sessions"].Flags = bpfFRdonlyProg
		return spec
	}, LookupMiss)
}

// A typed hook takes no NULL value, so a miss calls the map's _miss hook
// with the key alone. One fentry per hook sees the hit hook called only for
// the key that is present and the miss hook only for the absent one, and the
// program's results do not change.
func testLookupMissTyped(t *testing.T, fixture func() *ebpf.CollectionSpec, lookups LookupWhen) {
	testutil.SkipIfNotRoot(t)
	work := fixture()
	req := autoReq()
	req.Lookups = lookups
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	load := func(spec *ebpf.CollectionSpec, hooks []LookupHook) *ebpf.Collection {
		c := loadHooked(t, spec, hooks)
		t.Cleanup(c.Close)
		if err := c.Maps["sessions"].Put(uint32(7), [2]uint64{2, 9}); err != nil {
			t.Fatal(err)
		}
		return c
	}
	plain, injected := load(fixture(), nil), load(work, plan.hooks)
	observers := map[LookupWhen]*ebpf.Collection{}
	for _, hook := range plan.hooks {
		obs := loadOrSkip(t, dispatchObserver(t, hook.Name, injected.Programs["p"]))
		t.Cleanup(obs.Close)
		l, err := link.AttachTracing(link.TracingOptions{Program: obs.Programs["observe"], AttachType: ebpf.AttachTraceFEntry})
		if err != nil {
			if errors.Is(err, unix.EPERM) || errors.Is(err, ebpf.ErrNotSupported) {
				t.Skipf("fentry unavailable: %v", err)
			}
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		observers[hook.When] = obs
	}
	for _, hook := range plan.hooks {
		if hook.When == LookupMiss && (hook.Untrusted || hook.Static) {
			t.Fatalf("miss hook: %+v", hook)
		}
	}
	if len(observers) != len(plan.hooks) || (observers[LookupHit] != nil) != lookups.hit() || (observers[LookupMiss] != nil) != lookups.miss() {
		t.Fatalf("hooks: %+v", plan.hooks)
	}
	for _, run := range []struct{ key, action uint32 }{{7, 2}, {99, 1}} {
		packet := make([]byte, 64)
		binary.LittleEndian.PutUint32(packet, run.key)
		for _, c := range []*ebpf.Collection{plain, injected} {
			ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: packet, Repeat: 1})
			if err != nil || ret != run.action {
				t.Fatalf("key=%d: action=%d want %d err=%v", run.key, ret, run.action, err)
			}
		}
	}
	// The hit hook passes the value {2, 9}; the miss hook has no value.
	site := plan.sites[0].SitePC
	for when, want := range map[LookupWhen]dispatchRecord{
		LookupHit:  {Site: site, Seen: 1, Key: 7, Value: 2},
		LookupMiss: {Site: site, Seen: 1, Key: 99},
	} {
		obs := observers[when]
		if obs == nil {
			continue
		}
		var n uint64
		if err := obs.Maps["cnt"].Lookup(uint32(0), &n); err != nil || n != 1 {
			t.Fatalf("%s hook: %d calls, want 1 (err %v)", when, n, err)
		}
		var r dispatchRecord
		if err := obs.Maps["obs"].Lookup(uint32(0), &r); err != nil {
			t.Fatal(err)
		}
		r.Key = uint64(uint32(r.Key)) // the key is a u32 on the stack
		if r != want {
			t.Fatalf("%s hook: %+v, want %+v", when, r, want)
		}
	}
}
