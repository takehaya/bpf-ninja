package inject

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// The context reaches leaf's hook through mid, passed in a free register or
// saved from mid's own parameter, with typed and static untrusted hooks.
func TestBpfPassSite(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, saved := range []bool{false, true} {
		for _, static := range []bool{false, true} {
			t.Run(fmt.Sprintf("saved=%v/static=%v", saved, static), func(t *testing.T) {
				plain := loadOrSkip(t, passSiteFixture(saved))
				t.Cleanup(plain.Close)
				work := passSiteFixture(saved)
				req := passRequest()
				if static {
					req.Dispatch, req.StaticUntrusted = true, true
				}
				plan, err := transformLookup(work, req)
				if err != nil {
					t.Fatal(err)
				}
				if len(plan.sites) != 1 || plan.sites[0].FuncName != "leaf" || len(plan.hooks) != 1 {
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
				packet := make([]byte, 72)
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
				if wantRet != 2 || gotRet != wantRet || !bytes.Equal(gotOut, wantOut) {
					t.Fatalf("original returned %d, rewritten %d; output equal: %v", wantRet, gotRet, bytes.Equal(gotOut, wantOut))
				}
				var got [32]byte
				if err := observer.Maps["obs"].Lookup(uint32(0), &got); err != nil {
					t.Fatal(err)
				}
				seen, length := binary.LittleEndian.Uint64(got[:]), binary.LittleEndian.Uint32(got[8:])
				key, value, site := binary.LittleEndian.Uint32(got[12:]), binary.LittleEndian.Uint64(got[16:]), binary.LittleEndian.Uint32(got[24:])
				if seen != 1 || length != uint32(len(packet)) || key != 0 || value != 987654321 || site != plan.sites[0].SitePC {
					t.Fatalf("record seen=%d (want 1) length=%d key=%d value=%d site=%d", seen, length, key, value, site)
				}
			})
		}
	}
}
