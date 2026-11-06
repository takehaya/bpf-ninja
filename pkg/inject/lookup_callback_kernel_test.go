package inject

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"golang.org/x/sys/unix"
)

func callbackRequest(static bool) LookupRequest {
	req := autoReq()
	req.Stack.LowestOffset, req.Maps = -16, []string{"sessions"}
	if static {
		req.Dispatch, req.StaticUntrusted = true, true
	}
	return req
}

// plantCallbackOffset shifts the prologue's load so it reads the counter at
// [fp-16] of the entry instead of the context.
func plantCallbackOffset(t *testing.T, work *ebpf.CollectionSpec) {
	t.Helper()
	insns := work.Programs["p"].Instructions
	for i := range insns {
		if insns[i].Symbol() == "cb" {
			insns[i].Offset += 8
			return
		}
	}
	t.Fatal("no callback prologue")
}

func TestBpfCallbackSite(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, form := range []string{"loop", "loop_rt0", "foreach"} {
		for _, static := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/static=%v", form, static), func(t *testing.T) {
				plain := loadOrSkip(t, callbackSiteFixture(form, false))
				t.Cleanup(plain.Close)
				work := callbackSiteFixture(form, false)
				plan, err := transformLookup(work, callbackRequest(static))
				if err != nil {
					t.Fatal(err)
				}
				if len(plan.sites) != 1 || plan.sites[0].FuncName != "cb" || len(plan.hooks) != 1 {
					t.Fatalf("plan = %+v", plan)
				}
				target := loadHooked(t, work, plan.hooks)
				t.Cleanup(target.Close)
				observer := loadOrSkip(t, lookupObserverArgs(t, plan.hooks[0].Name, target.Programs["p"], observerArgs{site: true, rawCtx: static}))
				t.Cleanup(observer.Close)
				attached := attachTracingOrSkip(t, observer.Programs["observe"])
				t.Cleanup(func() { _ = attached.Close() })
				for _, c := range []*ebpf.Collection{plain, target} {
					if err := c.Maps["sessions"].Put(uint32(0), [2]uint64{2, 987654321}); err != nil {
						t.Fatal(err)
					}
				}
				packet := make([]byte, 80)
				for i := range packet {
					packet[i] = byte(i)
				}
				run := func(c *ebpf.Collection) (uint32, []byte) {
					out := make([]byte, len(packet))
					ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: packet, DataOut: out, Repeat: 1})
					if err != nil {
						t.Fatal(err)
					}
					return ret, out
				}
				wantRet, wantOut := run(plain)
				gotRet, gotOut := run(target)
				if gotRet != wantRet || !bytes.Equal(gotOut, wantOut) || !bytes.Equal(gotOut, packet) {
					t.Fatalf("original returned %d, rewritten %d; output equal: %v", wantRet, gotRet, bytes.Equal(gotOut, wantOut))
				}
				var got [32]byte
				if err := observer.Maps["obs"].Lookup(uint32(0), &got); err != nil {
					t.Fatal(err)
				}
				seen, length := binary.LittleEndian.Uint64(got[:]), binary.LittleEndian.Uint32(got[8:])
				key, value, site := binary.LittleEndian.Uint32(got[12:]), binary.LittleEndian.Uint64(got[16:]), binary.LittleEndian.Uint32(got[24:])
				if seen != uint64(wantRet) || length != uint32(len(packet)) || key != 0 || value != 987654321 || site != plan.sites[0].SitePC {
					t.Fatalf("record seen=%d (want %d) length=%d key=%d value=%d site=%d", seen, wantRet, length, key, value, site)
				}
			})
		}
	}
}

// A global hook's context is checked by the kernel, so the planted offset does
// not load. Nothing checks a static hook's: the program loads and the context
// is wrong, which the checker rejects before load (TestTranslationValidationCallbackMutations).
func TestBpfCallbackSiteWrongOffset(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	t.Run("global refuses", func(t *testing.T) {
		work := callbackSiteFixture("loop", false)
		if _, err := transformLookup(work, callbackRequest(false)); err != nil {
			t.Fatal(err)
		}
		plantCallbackOffset(t, work)
		_, err := ebpf.NewCollection(work)
		var verifier *ebpf.VerifierError
		if errors.Is(err, unix.EPERM) || errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("BPF unsupported or insufficient privileges: %v", err)
		}
		if !errors.As(err, &verifier) {
			t.Fatalf("planted offset: %v", err)
		}
	})
	t.Run("static loads and passes the wrong value", func(t *testing.T) {
		work := callbackSiteFixture("loop", false)
		plan, err := transformLookup(work, callbackRequest(true))
		if err != nil {
			t.Fatal(err)
		}
		plantCallbackOffset(t, work)
		target := loadHooked(t, work, plan.hooks)
		t.Cleanup(target.Close)
		if err := target.Maps["sessions"].Put(uint32(0), [2]uint64{2, 987654321}); err != nil {
			t.Fatal(err)
		}
		spec := subprogRawArgObserver(target.Programs["p"])
		spec.Programs["observe"].AttachTo = plan.hooks[0].Name
		observer := loadOrSkip(t, spec)
		t.Cleanup(observer.Close)
		attached := attachTracingOrSkip(t, observer.Programs["observe"])
		t.Cleanup(func() { _ = attached.Close() })
		if _, err := target.Programs["p"].Run(&ebpf.RunOptions{Data: make([]byte, 80), Repeat: 1}); err != nil {
			t.Fatal(err)
		}
		// The last of the three iterations reads the counter, 2, as its context.
		var got uint64
		if err := observer.Maps["seen"].Lookup(uint32(0), &got); err != nil || got != 2 {
			t.Fatalf("raw context argument=%#x err=%v, want the planted counter 2", got, err)
		}
	})
}
