package inject

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"golang.org/x/sys/unix"
)

func TestBpfSpecialFieldsLookup(t *testing.T)       { testSpecialFieldsLookup(t, false) }
func TestBpfSpecialFieldsLookupStatic(t *testing.T) { testSpecialFieldsLookup(t, true) }

// A lookup on a value with a bpf_spin_lock, bpf_timer or kptr loads through an
// untrusted or static hook, which the observer reads the key, value and site
// through; a typed one fails "bpf_spin_lock cannot be accessed directly by
// load/store". 6.1 does not know kptr_untrusted and takes it for a plain
// pointer.
func testSpecialFieldsLookup(t *testing.T, static bool) {
	testutil.SkipIfNotRoot(t)
	for _, kind := range []string{"spin_lock", "timer", "kptr"} {
		t.Run(kind, func(t *testing.T) {
			fixture := func() *ebpf.CollectionSpec { return withSpecialValue(lookupFixture(), kind) }
			work := fixture()
			req := autoReq()
			req.StaticUntrusted = static
			plan, err := transformLookup(work, req)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.hooks) != 1 || plan.hooks[0].Untrusted == static || plan.hooks[0].Static != static {
				t.Fatalf("hooks: %+v", plan.hooks)
			}
			plain := loadOrSkip(t, fixture())
			t.Cleanup(plain.Close)
			injected := loadHooked(t, work, plan.hooks)
			t.Cleanup(injected.Close)
			size := work.Maps["sessions"].ValueSize
			for _, c := range []*ebpf.Collection{plain, injected} {
				value := make([]byte, size)
				binary.LittleEndian.PutUint64(value, 2) // seid, the action
				binary.LittleEndian.PutUint64(value[8:], 100000000000001)
				if err := c.Maps["sessions"].Put(uint32(7), value); err != nil {
					t.Fatal(err)
				}
			}
			obs := loadOrSkip(t, lookupObserverArgs(t, plan.hooks[0].Name, injected.Programs["p"], observerArgs{site: true, rawCtx: static}))
			t.Cleanup(obs.Close)
			l, err := link.AttachTracing(link.TracingOptions{Program: obs.Programs["observe"], AttachType: ebpf.AttachTraceFEntry})
			if err != nil {
				if errors.Is(err, unix.EPERM) || errors.Is(err, ebpf.ErrNotSupported) {
					t.Skipf("fentry unavailable: %v", err)
				}
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = l.Close() })
			packet := make([]byte, 64)
			binary.LittleEndian.PutUint32(packet, 7)
			for _, c := range []*ebpf.Collection{plain, injected} {
				if ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: packet, Repeat: 1}); err != nil || ret != 2 {
					t.Fatalf("action=%d err=%v", ret, err)
				}
			}
			var got [32]byte
			if err := obs.Maps["obs"].Lookup(uint32(0), &got); err != nil {
				t.Fatal(err)
			}
			seen, length, key := binary.LittleEndian.Uint64(got[:]), binary.LittleEndian.Uint32(got[8:]), binary.LittleEndian.Uint32(got[12:])
			imsi, site := binary.LittleEndian.Uint64(got[16:]), binary.LittleEndian.Uint32(got[24:])
			if seen != 1 || length != 64 || key != 7 || imsi != 100000000000001 || site != plan.hooks[0].Sites[0].SitePC {
				t.Fatalf("seen=%d length=%d key=%d imsi=%d site=%d", seen, length, key, imsi, site)
			}
		})
	}
}

// specialUpdateFixture is mapCallFixture over a 24-byte value whose third word,
// the special field and padding, the program zeroes before storing the key:
// two instructions more, so the update is at 22 and the delete at 26.
func specialUpdateFixture(kind string) *ebpf.CollectionSpec {
	spec := withSpecialValue(mapCallFixture(), kind)
	insns := spec.Programs["p"].Instructions
	zero := asm.Instructions{asm.Mov.Imm(asm.R5, 0), asm.StoreMem(asm.RFP, -8, asm.R5, asm.DWord)}
	insns = slices.Insert(insns, 8, zero...)
	insns[5].Offset += 2 // short packet
	spec.Programs["p"].Instructions = insns
	return spec
}

// An update with a bpf_spin_lock or kptr in its value keeps the typed hook:
// the value is the program's stack. The hook sees each call's key, value and
// status.
func TestBpfSpecialFieldsUpdate(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, kind := range []string{"spin_lock", "kptr"} {
		t.Run(kind, func(t *testing.T) {
			fixture := func() *ebpf.CollectionSpec { return specialUpdateFixture(kind) }
			work := fixture()
			req := autoReq()
			req.Lookups, req.Updates, req.Deletes, req.Stack.LowestOffset = LookupNone, CallAny, CallAny, -24
			plan, err := transformLookup(work, req)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.hooks) != 2 || plan.hooks[0].Untrusted || plan.hooks[0].Static || plan.hooks[0].Sites[0].SitePC != 22 {
				t.Fatalf("hooks: %+v", plan.hooks)
			}
			plain := loadOrSkip(t, fixture())
			t.Cleanup(plain.Close)
			injected := loadHooked(t, work, plan.hooks)
			t.Cleanup(injected.Close)
			update := attachArgObserver(t, plan.hooks[0].Name, injected.Programs["p"], false, true, true, false)
			del := attachArgObserver(t, plan.hooks[1].Name, injected.Programs["p"], false, true, false)
			eexist := -int64(unix.EEXIST)
			runMapCalls(t, plain, injected, []mapCallStep{{7, 1, 0}, {7, 1, eexist}, {7, selectDelete, 0}})
			wantUpdate := [][4]uint64{{22, 7, 0x1111, 1 << 32}, {22, 7, 0x1111, uint64(uint32(eexist)) | 1<<32}}
			wantDelete := [][4]uint64{{26, 7, 0}}
			for _, check := range []struct {
				name string
				obs  *ebpf.Collection
				want [][4]uint64
			}{{"update", update, wantUpdate}, {"delete", del, wantDelete}} {
				got := observed(t, check.obs)
				for i := range got {
					got[i][1] = uint64(uint32(got[i][1]))
				}
				if !slices.Equal(got, check.want) {
					t.Errorf("%s hook: %x\nwant %x", check.name, got, check.want)
				}
			}
		})
	}
}

const (
	skbSkOffset   = 168 // struct __sk_buff's sk
	sockUpdatePC  = 11
	sockDeletePC  = 17
	sockKeyOffset = -4
)

// sockUpdateFixture updates key 0 of the sockhash m with the context's socket,
// then deletes key 0, and returns the update's result. BPF_PROG_TEST_RUN gives
// the skb a socket that no socket map accepts, so the update fails, and the
// delete fails on the empty map with ENOENT.
func sockUpdateFixture() *ebpf.CollectionSpec {
	noSock := asm.JEq.Imm(asm.R7, 0, "")
	noSock.Offset = 17 // slot 2 -> 20
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),                         // 0
		asm.LoadMem(asm.R7, asm.R6, skbSkOffset, asm.DWord), // 1: skb->sk
		noSock,                 // 2
		asm.Mov.Imm(asm.R2, 0), // 3
		asm.StoreMem(asm.RFP, sockKeyOffset, asm.R2, asm.Word), // 4: key 0
		asm.Mov.Reg(asm.R2, asm.RFP),                           // 5
		asm.Add.Imm(asm.R2, sockKeyOffset),                     // 6
		asm.Mov.Reg(asm.R3, asm.R7),                            // 7: the socket
		asm.Mov.Imm(asm.R4, 0),                                 // 8: BPF_ANY
		asm.LoadMapPtr(asm.R1, 0).WithReference("m"),           // 9-10
		asm.FnMapUpdateElem.Call(),                             // 11
		asm.Mov.Reg(asm.R8, asm.R0),                            // 12
		asm.Mov.Reg(asm.R2, asm.RFP),                           // 13
		asm.Add.Imm(asm.R2, sockKeyOffset),                     // 14
		asm.LoadMapPtr(asm.R1, 0).WithReference("m"),           // 15-16
		asm.FnMapDeleteElem.Call(),                             // 17
		asm.Mov.Reg(asm.R0, asm.R8),                            // 18
		asm.Return(),                                           // 19
		asm.Mov.Imm(asm.R0, 1),                                 // 20: no socket
		asm.Return(),                                           // 21
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("sock update fixture")), xdpFunc("p"))
	return asTC(&ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps:     map[string]*ebpf.MapSpec{"m": {Name: "m", Type: ebpf.SockHash, KeySize: 4, ValueSize: 8, MaxEntries: 1}},
		Programs: map[string]*ebpf.ProgramSpec{"p": {Name: "p", Type: ebpf.XDP, License: "GPL", Instructions: insns}},
	})
}

func TestBpfSockHashUpdateTC(t *testing.T)       { testSockHashUpdate(t, false) }
func TestBpfSockHashUpdateTCStatic(t *testing.T) { testSockHashUpdate(t, true) }

// A tc program's sockhash update passes a socket, not memory, so it goes to
// the generic hook, which sees info, the key, the socket and the map; the
// delete passes NULL for the value. Both calls fail, and the program's result
// does not change. 7.3 no longer lets tc update a socket map.
func testSockHashUpdate(t *testing.T, static bool) {
	testutil.SkipIfNotRoot(t)
	work := sockUpdateFixture()
	plan, err := transformLookup(work, LookupRequest{ProgramName: "p", Auto: true, Lookups: LookupNone, Updates: CallError, Deletes: CallError,
		StaticUntrusted: static, HookName: "obs", Stack: StackAudit{LowestOffset: -8}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 2 || !plan.hooks[0].Generic || plan.hooks[0].Static != static || plan.hooks[1].Name != "obs_any_delete" {
		t.Fatalf("hooks: %+v", plan.hooks)
	}
	if probe, err := ebpf.NewCollection(sockUpdateFixture()); err == nil {
		probe.Close()
	} else if ve := (*ebpf.VerifierError)(nil); errors.As(err, &ve) && strings.Contains(fmt.Sprintf("%+v", ve), "cannot update sockmap in this context") {
		t.Skipf("kernel forbids sockmap updates from tc: %v", err) // 7.3
	}
	plain := loadOrSkip(t, sockUpdateFixture())
	t.Cleanup(plain.Close)
	injected := loadHooked(t, work, plan.hooks)
	t.Cleanup(injected.Close)
	update := attachArgObserver(t, "obs_any_update", injected.Programs["p"], false, true, false, false)
	del := attachArgObserver(t, "obs_any_delete", injected.Programs["p"], false, true, false, false)
	var results []uint32
	for _, c := range []*ebpf.Collection{plain, injected} {
		ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1})
		if err != nil {
			t.Fatal(err)
		}
		results = append(results, ret)
	}
	if results[0] != results[1] || int32(results[0]) >= 0 {
		t.Fatalf("update results plain, injected = %d, want one error", results)
	}
	calls := map[string][][4]uint64{"update": observed(t, update), "delete": observed(t, del)}
	for name, want := range map[string]struct {
		pc  uint64
		op  uint64
		ret int32
	}{"update": {sockUpdatePC, InfoOpUpdate, int32(results[0])}, "delete": {sockDeletePC, InfoOpDelete, -int32(unix.ENOENT)}} {
		got := calls[name]
		info := want.pc | want.op<<32 | uint64(uint16(want.ret))<<48
		if len(got) != 1 || got[0][0] != info || uint32(got[0][1]) != 0 || (got[0][2] != 0) != (name == "update") || got[0][3] == 0 {
			t.Errorf("%s hook: %x, want info %x, key 0, a socket for an update, and the map", name, got, info)
		}
	}
}
