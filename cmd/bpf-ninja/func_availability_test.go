package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/internal/attach"
)

func TestFuncAvailabilityJSONKeys(t *testing.T) {
	funcs := funcsToJSON([]attach.FuncInfo{{Name: "dead", Linkage: "global", Availability: attach.FuncAvailability{Reason: attach.FuncAbsent, BTFFuncPresent: true, FuncTypeID: 9}}})
	// Literal keys pin the public schema independently of the emitting structs.
	want := `[{"name":"dead","linkage":"global","availability":{"reason":"absent_from_loaded_func_info","btf_func_present":true,"func_type_id":9}}]`
	raw, err := json.Marshal(funcs)
	if err != nil || string(raw) != want {
		t.Fatalf("%s %v", raw, err)
	}
	unknown := funcsToJSON([]attach.FuncInfo{{Name: "live", Linkage: "global", Availability: attach.FuncAvailability{Reason: attach.FuncUnknown, BTFFuncPresent: true, FuncTypeID: 2, Detail: "permission denied"}}})
	raw, err = json.Marshal(unknown)
	want = `[{"name":"live","linkage":"global","availability":{"reason":"unknown","btf_func_present":true,"func_type_id":2,"detail":"permission denied"}}]`
	if err != nil || string(raw) != want {
		t.Fatalf("%s %v", raw, err)
	}
	noID := funcsToJSON([]attach.FuncInfo{{Name: "unresolved", Linkage: "static", Availability: attach.FuncAvailability{Reason: attach.FuncUnknown, Detail: "unavailable"}}})
	raw, err = json.Marshal(noID)
	want = `[{"name":"unresolved","linkage":"static","availability":{"reason":"unknown","btf_func_present":false,"detail":"unavailable"}}]`
	if err != nil || string(raw) != want {
		t.Fatalf("%s %v", raw, err)
	}
	// Standalone and reachable-tree views use exactly the same function rows.
	tree := progsTargetJSON{ID: 42, Func: "entry", Funcs: &funcs, Reachable: []progNodeJSON{{ID: 43, Funcs: &funcs}}}
	raw, err = json.Marshal([]progsTargetJSON{tree})
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, fs := range []any{rows[0]["funcs"], rows[0]["reachable"].([]any)[0].(map[string]any)["funcs"]} {
		a := fs.([]any)[0].(map[string]any)["availability"].(map[string]any)
		if a["reason"] != attach.FuncAbsent || a["func_type_id"] != float64(9) || a["btf_func_present"] != true {
			t.Fatal(string(raw))
		}
	}
}

func TestPrintFuncRows(t *testing.T) {
	funcs := []attach.FuncInfo{
		{Name: "entry", Linkage: "global", Availability: attach.FuncAvailability{Reason: attach.FuncPresent, BTFFuncPresent: true, FuncTypeID: 1}},
		{Name: "static_dead", Linkage: "static", Availability: attach.FuncAvailability{Reason: attach.FuncAbsent, BTFFuncPresent: true, FuncTypeID: 9}},
	}
	for _, indent := range []string{"  ", "      "} {
		var out bytes.Buffer
		printFuncRows(&out, funcs, indent)
		want := indent + "entry                                    [global] present\n" +
			indent + "static_dead                              [static] absent_from_loaded_func_info\n"
		if out.String() != want || strings.Contains(out.String(), "type_id") {
			t.Fatalf("got %q want %q", out.String(), want)
		}
	}
}

func TestPrintFuncRowsUnknown(t *testing.T) {
	var out bytes.Buffer
	printFuncRows(&out, []attach.FuncInfo{
		{Name: "entry", Linkage: "global", Availability: attach.FuncAvailability{Reason: attach.FuncUnknown, Detail: "func_info\nunavailable"}},
		{Name: "helper", Linkage: "static", Availability: attach.FuncAvailability{Reason: attach.FuncUnknown, Detail: "func_info\nunavailable"}},
	}, "  ")
	want := "  entry                                    [global] unknown\n" +
		"  helper                                   [static] unknown\n" +
		"  availability unknown: func_info unavailable\n"
	if out.String() != want {
		t.Fatalf("got %q want %q", out.String(), want)
	}
}
