package program

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

//go:embed testdata/pruned_subprog.c
var prunedSubprogSource string

// BPF_NINJA_SUBPROG_OBJECT can supply the same fixture compiled before booting
// a VM without clang: clang -target bpf -O2 -g -c testdata/pruned_subprog.c -o hooks.o.
func TestBpfPrunedSubprog(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	object := os.Getenv("BPF_NINJA_SUBPROG_OBJECT")
	if object == "" {
		object = testutil.CompileBPFSource(t, prunedSubprogSource)
	}
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatal(err)
	}
	kernel := strings.TrimSpace(string(release))
	if !strings.HasPrefix(kernel, "7.0.") && !strings.HasPrefix(kernel, "6.1.") {
		t.Logf("no absolute retention expectation for kernel %s; checking func_info consistency only", kernel)
	}
	t.Logf("kernel=%s", kernel)
	for _, enabled := range []uint32{0, 1} {
		t.Run(fmt.Sprintf("enabled=%d", enabled), func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpec(object)
			if err != nil {
				t.Fatal(err)
			}
			if err := spec.Variables["enabled"].Set(enabled); err != nil {
				t.Fatal(err)
			}
			coll, err := ebpf.NewCollection(spec)
			if err != nil {
				t.Fatal(err)
			}
			defer coll.Close()
			target := coll.Programs["entry"]
			info := progInfoFor(t, target, "entry")
			pi, err := target.Info()
			if err != nil {
				t.Fatal(err)
			}
			funcs, err := pi.FuncInfos()
			if err != nil {
				t.Fatal(err)
			}
			present := map[string]bool{}
			for _, f := range funcs {
				present[f.Func.Name] = true
			}
			for _, name := range []string{"global_dead", "static_dead", "static_dead_other", "live_hook"} {
				a := info.FuncAvailability(name)
				want := attach.FuncAbsent
				if present[name] {
					want = attach.FuncPresent
				}
				if a.Reason != want || !a.BTFFuncPresent || a.FuncTypeID == 0 {
					t.Fatalf("%s: %+v, func_info=%v", name, a, funcs)
				}
				if strings.HasPrefix(kernel, "7.0.") || strings.HasPrefix(kernel, "6.1.") {
					wantPresent := (name == "live_hook") == (enabled == 0)
					if strings.HasPrefix(kernel, "6.1.") && !strings.HasPrefix(name, "static_dead") {
						wantPresent = true
					}
					if present[name] != wantPresent {
						t.Fatalf("%s: present=%t want=%t", name, present[name], wantPresent)
					}
				}
				for _, typ := range []ebpf.AttachType{ebpf.AttachTraceFEntry, ebpf.AttachTraceFExit} {
					t.Run(fmt.Sprintf("%s/%s", name, typ), func(t *testing.T) {
						insns := asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}
						probe := &Probe{}
						defer func() { _ = probe.Close() }()
						err := attachTracingProbe(probe, target, "subprog_probe", name, typ, insns, false, a)
						if a.Reason == attach.FuncPresent {
							if err != nil {
								t.Fatal(err)
							}
							if probe.AttachCount() != 1 {
								t.Fatal("no tracing link")
							}
						} else {
							if err == nil || !strings.Contains(err.Error(), attach.FuncAbsent) || !strings.Contains(err.Error(), "again with that feature enabled") {
								t.Fatalf("diagnostic: %v", err)
							}
							// The static prototype probe must also explain absence before loading.
							if _, probeErr := staticXDPNeedsProbeRead(target, name, typ, a); probeErr == nil || !strings.Contains(probeErr.Error(), attach.FuncAbsent) {
								t.Fatalf("context probe diagnostic: %v", probeErr)
							}
							// Also verify the kernel's original failure independently of the preflight.
							raw, rawErr := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "raw_probe", Type: ebpf.Tracing, AttachType: typ, AttachTarget: target, AttachTo: name, License: "GPL", Instructions: insns})
							if raw != nil {
								_ = raw.Close()
							}
							var ve *ebpf.VerifierError
							if !errors.As(rawErr, &ve) || !strings.Contains(strings.Join(ve.Log, "\n"), "doesn't exist") {
								t.Fatalf("original verifier error: %v", rawErr)
							}
						}
						t.Logf("name=%s attach_type=%s reason=%s type_id=%d", name, typ, a.Reason, a.FuncTypeID)
					})
				}
			}
			// A list keeps functions reported by the independent func_info oracle
			// and records a diagnostic for each pruned target.
			targets, ds, err := attach.ResolveTargets([]*attach.ProgInfo{info}, []string{"global_dead", "live_hook"}, false)
			if err != nil {
				t.Fatal(err)
			}
			wantCount := 0
			for _, n := range []string{"global_dead", "live_hook"} {
				if present[n] {
					wantCount++
				}
			}
			if len(targets) != wantCount || len(ds) != 2-wantCount {
				t.Fatalf("targets=%v diagnostics=%v", targets, ds)
			}
			_, _, err = attach.ResolveTargets([]*attach.ProgInfo{info}, []string{"global_dead"}, false)
			if present["global_dead"] {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), attach.FuncAbsent) {
				t.Fatalf("single target: %v", err)
			}
		})
	}
}

func TestTracingLoadErrorUnknown(t *testing.T) {
	original := &ebpf.VerifierError{Cause: errors.New("kernel rejected target"), Log: []string{"Subprog dead doesn't exist", "processed 0 insns"}}
	wrapped := tracingLoadError("probe", "dead", attach.FuncAvailability{Reason: attach.FuncUnknown, BTFFuncPresent: true, Detail: "permission denied"}, original)
	var ve *ebpf.VerifierError
	if !errors.As(wrapped, &ve) || ve != original {
		t.Fatal("lost original verifier error")
	}
	for _, text := range []string{"unknown", "permission denied", "Subprog dead doesn't exist", "processed 0 insns"} {
		if !strings.Contains(wrapped.Error(), text) {
			t.Fatalf("lost %q: %s", text, wrapped)
		}
	}
}

func TestCachedAvailability(t *testing.T) {
	a := attach.FuncAvailability{Reason: attach.FuncAbsent}
	// A nil program proves these guards use only the result supplied by resolution.
	p := &Probe{}
	if err := attachTracingProbe(p, nil, "probe", "dead", ebpf.AttachTraceFEntry, nil, false, a); err == nil || !strings.Contains(err.Error(), attach.FuncAbsent) {
		t.Fatalf("%v", err)
	}
	if _, err := staticXDPNeedsProbeRead(nil, "dead", ebpf.AttachTraceFEntry, a); err == nil || !strings.Contains(err.Error(), attach.FuncAbsent) {
		t.Fatalf("%v", err)
	}
}
