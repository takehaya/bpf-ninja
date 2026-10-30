package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

func TestBpfPrunedSubprogCLI(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	object := os.Getenv("BPF_NINJA_SUBPROG_OBJECT")
	if object == "" {
		source, err := os.ReadFile("../../internal/program/testdata/pruned_subprog.c")
		if err != nil {
			t.Fatal(err)
		}
		object = testutil.CompileBPFSource(t, string(source))
	}
	// Load both configurations so the same function can be present in one
	// program and absent in the other, even on kernels which keep global funcs.
	var infos []*attach.ProgInfo
	for _, enabled := range []uint32{0, 1} {
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
		p := coll.Programs["entry"]
		pi, err := p.Info()
		if err != nil {
			t.Fatal(err)
		}
		id, _ := pi.ID()
		infos = append(infos, &attach.ProgInfo{Program: p, ProgID: uint32(id)})
	}
	run := func(programs []*attach.ProgInfo, args ...string) (string, string, error) {
		t.Helper()
		argv := []string{"bpf-ninja"}
		for _, p := range programs {
			argv = append(argv, "-p", fmt.Sprint(p.ProgID))
		}
		argv = append(argv, args...)
		return captureStdio(t, func() error { return newRootCommand().Run(context.Background(), argv) })
	}
	t.Run("availability listing", func(t *testing.T) {
		release, err := os.ReadFile("/proc/sys/kernel/osrelease")
		if err != nil {
			t.Fatal(err)
		}
		wantReasons := map[string]string{
			"entry": "present", "live_hook": "present",
			"static_dead": "absent_from_loaded_func_info", "static_dead_other": "absent_from_loaded_func_info",
			"global_dead": "",
		}
		if strings.HasPrefix(string(release), "6.1.") {
			wantReasons["global_dead"] = "present"
		} else if strings.HasPrefix(string(release), "7.0.") {
			wantReasons["global_dead"] = "absent_from_loaded_func_info"
		}
		for _, tree := range []bool{false, true} {
			args := []string{"--list-funcs"}
			if tree {
				args = append(args, "--list-progs")
			}
			stdout, stderr, err := run(infos[:1], append(args, "--json")...)
			if err != nil || stderr != "" {
				t.Fatalf("%s %s %v", stdout, stderr, err)
			}
			var rows []struct {
				ID    uint32 `json:"id"`
				Funcs []struct {
					Name         string `json:"name"`
					Availability struct {
						Reason         string `json:"reason"`
						BTFFuncPresent bool   `json:"btf_func_present"`
						FuncTypeID     uint32 `json:"func_type_id"`
						Detail         string `json:"detail"`
					} `json:"availability"`
				} `json:"funcs"`
				Reachable []json.RawMessage `json:"reachable"`
			}
			if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || rows[0].ID != infos[0].ProgID || len(rows[0].Funcs) != len(wantReasons) || (tree && rows[0].Reachable == nil) {
				t.Fatal(stdout)
			}
			seen := map[string]bool{}
			ids := map[uint32]bool{}
			for _, f := range rows[0].Funcs {
				want, ok := wantReasons[f.Name]
				a := f.Availability
				if !ok || seen[f.Name] || ids[a.FuncTypeID] || !a.BTFFuncPresent || a.FuncTypeID == 0 || a.Detail != "" {
					t.Fatal(stdout)
				}
				seen[f.Name], ids[a.FuncTypeID] = true, true
				if (want != "" && a.Reason != want) || (want == "" && a.Reason != "present" && a.Reason != "absent_from_loaded_func_info") {
					t.Fatal(stdout)
				}
			}
			t.Logf("tree=%t json=%s", tree, stdout)
			stdout, stderr, err = run(infos[:1], args...)
			if err != nil || stdout != "" || !regexp.MustCompile(`(?m)^\s+static_dead\s+\[static\] absent_from_loaded_func_info$`).MatchString(stderr) || strings.Contains(stderr, "type_id") || strings.Contains(stderr, "unreachable") {
				t.Fatalf("%s %s %v", stdout, stderr, err)
			}
			t.Logf("tree=%t text=%s", tree, stderr)
		}
	})
	for _, tc := range []struct {
		name     string
		programs []*attach.ProgInfo
		funcs    []string
	}{
		{"list", infos[:1], []string{"global_dead", "static_dead", "live_hook"}},
		{"multiple programs", infos, []string{"static_dead"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"--list-params", "--json"}
			wantIDs := map[string]bool{}
			skipped := 0
			for _, name := range tc.funcs {
				args = append(args, "--func", name)
				for _, info := range tc.programs {
					if info.FuncAvailability(name).Unavailable() {
						skipped++
					} else {
						wantIDs[fmt.Sprintf("%d/%s", info.ProgID, name)] = true
					}
				}
			}
			stdout, stderr, err := run(tc.programs, args...)
			if err != nil {
				t.Fatal(err)
			}
			var rows []map[string]json.RawMessage
			if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
				t.Fatal(err)
			}
			if len(rows) != len(wantIDs) {
				t.Fatalf("rows=%s want=%v", stdout, wantIDs)
			}
			for _, row := range rows {
				var id uint32
				var name string
				if err := json.Unmarshal(row["id"], &id); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(row["func"], &name); err != nil {
					t.Fatal(err)
				}
				key := fmt.Sprintf("%d/%s", id, name)
				if len(row) != 3 || row["params"] == nil || !wantIDs[key] {
					t.Fatalf("unexpected row: %s", stdout)
				}
				delete(wantIDs, key)
			}
			if len(wantIDs) != 0 || !strings.Contains(stderr, fmt.Sprintf("Skipped %d target(s)", skipped)) {
				t.Fatalf("%v %s", wantIDs, stderr)
			}
			if strings.Contains(stderr, "type_id") || strings.Contains(stderr, "unreachable") {
				t.Fatal(stderr)
			}
			t.Logf("stdout=%s stderr=%s", stdout, stderr)
		})
	}
	stdout, stderr, err := run(infos[:1], "--func", "static_dead", "--func", "static_dead_other", "--list-params", "--json")
	if err == nil || !strings.Contains(err.Error(), "no attachable") || strings.Count(err.Error(), "attach-troubleshooting.md") != 1 || stdout != "" || !strings.Contains(stderr, "Skipped 2 target(s)") {
		t.Fatalf("all skipped: %s %s %v", stdout, stderr, err)
	}
	for _, funcs := range [][]string{{"--func", "static_dead"}, {"--func", "static_dead", "--func", "static_dead"}} {
		stdout, stderr, err = run(infos[:1], append(funcs, "--list-params", "--json")...)
		if err == nil || stdout != "" || stderr != "" || !strings.Contains(err.Error(), "again with that feature enabled") {
			t.Fatalf("single: %s %s %v", stdout, stderr, err)
		}
	}
	_, _, err = run(infos[:1], "--func", "does_not_exist", "--list-params")
	if err == nil || !strings.Contains(err.Error(), attach.FuncMissing) {
		t.Fatalf("missing: %v", err)
	}
	_, _, err = run(infos[:1], "--func", "*", "--list-params")
	if err == nil || !strings.Contains(err.Error(), attach.FuncMissing) {
		t.Fatalf("glob must remain unsupported: %v", err)
	}
}
