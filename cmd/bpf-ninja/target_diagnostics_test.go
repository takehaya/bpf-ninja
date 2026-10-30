package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/internal/attach"
)

func TestTargetDiagnosticsOutput(t *testing.T) {
	ds := []attach.TargetDiagnostic{
		{ProgID: 42, FuncName: "dead", Availability: attach.FuncAvailability{Reason: attach.FuncAbsent, FuncTypeID: 9}, Skipped: true},
		{ProgID: 43, FuncName: "unknown", Availability: attach.FuncAvailability{Reason: attach.FuncUnknown, Detail: "func_info unavailable (count=0); missing CAP_BPF is a likely cause"}},
		{ProgID: 44, FuncName: "external", Availability: attach.FuncAvailability{Reason: attach.FuncNotInTarget}, Skipped: true},
		{ProgID: 45, FuncName: "unknown", Availability: attach.FuncAvailability{Reason: attach.FuncUnknown, Detail: "BPF_OBJ_GET_INFO_BY_FD: permission denied"}},
		{ProgID: 46, FuncName: "unknown", Availability: attach.FuncAvailability{Reason: attach.FuncUnknown}},
	}
	var out bytes.Buffer
	printTargetDiagnostics(&out, ds)
	want := "warning: skipping program (id=42) function \"dead\": absent_from_loaded_func_info\n" +
		"warning: program (id=43) function \"unknown\": unknown; could not check func_info: func_info unavailable (count=0); missing CAP_BPF is a likely cause; letting the kernel verify it\n" +
		"warning: skipping program (id=44) function \"external\": not_in_target_program\n" +
		"warning: program (id=45) function \"unknown\": unknown; could not check func_info: BPF_OBJ_GET_INFO_BY_FD: permission denied; letting the kernel verify it\n" +
		"warning: program (id=46) function \"unknown\": unknown; could not check func_info; letting the kernel verify it\n" +
		"Skipped 2 target(s): 1 absent from loaded func_info, 1 external declaration(s).\n"
	if out.String() != want {
		t.Fatalf("got %s want %s", &out, want)
	}
	out.Reset()
	printTargetDiagnostics(&out, nil)
	if out.Len() != 0 {
		t.Fatal(out.String())
	}
}

func TestParamsJSONKeys(t *testing.T) {
	// Availability and skipped diagnostics never enter the list-params array.
	row := paramsToJSON(attach.Target{ProgID: 42, FuncName: "live", Availability: attach.FuncAvailability{Reason: attach.FuncPresent}}, false, 0)
	raw, err := json.Marshal([]paramsTargetJSON{row})
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{{"id": float64(42), "func": "live", "params": []any{}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s", raw)
	}
	if strings.Contains(string(raw), "availability") || strings.Contains(string(raw), "skipped") {
		t.Fatal(string(raw))
	}
}
