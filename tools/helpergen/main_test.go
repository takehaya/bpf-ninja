package main

import (
	"reflect"
	"strings"
	"testing"
)

const testUAPI = `
#define ___BPF_FUNC_MAPPER(FN, ctx...)			\
	FN(unspec, 0, ##ctx)				\
	FN(map_lookup_elem, 1, ##ctx)			\
	FN(tail_call, 2, ##ctx)				\
	FN(get_stack, 3, ##ctx)				\
	FN(bind, 4, ##ctx)				\
	FN(trace_printk, 5, ##ctx)			\
	/* */

#define __BPF_FUNC_MAPPER(FN) ___BPF_FUNC_MAPPER(FN)
`

const testC = `
const struct bpf_func_proto bpf_map_lookup_elem_proto = {
	.func		= bpf_map_lookup_elem,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
};

static const struct bpf_func_proto bpf_tail_call_proto = {
	.func		= NULL,
	.ret_type	= RET_VOID,
};

struct bpf_func_proto bpf_get_stack_proto = {
	.ret_type	= RET_INTEGER,
};

static const struct bpf_func_proto bpf_get_stack_proto_raw_tp = {
	.ret_type	= RET_INTEGER,
};

static const struct bpf_func_proto bpf_bind_proto = {
	.ret_type	= RET_PTR_TO_BTF_ID | PTR_MAYBE_NULL,
};

static const struct bpf_func_proto *
base_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
	case BPF_FUNC_tail_call:
		return &bpf_tail_call_proto;
	case BPF_FUNC_get_stack:
		return prog->x ? &bpf_get_stack_proto_raw_tp
			       : &bpf_get_stack_proto;
	case BPF_FUNC_bind:
		switch (prog->expected_attach_type) {
		case BPF_CGROUP_INET4_CONNECT:
			return NULL;
		default:
			return &bpf_bind_proto;
		}
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
	default:
		return NULL;
	}
}

static const struct bpf_func_proto *
other_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return &bpf_map_lookup_elem_proto;
}
`

func TestParseMapper(t *testing.T) {
	hs, err := parseMapper(testUAPI)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for i, h := range hs {
		if h.ID != i {
			t.Errorf("row %d has id %d", i, h.ID)
		}
		names = append(names, h.Name)
	}
	want := []string{"unspec", "map_lookup_elem", "tail_call", "get_stack", "bind", "trace_printk"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("names %v, want %v", names, want)
	}
	if _, err := parseMapper(strings.Replace(testUAPI, "tail_call, 2", "tail_call, 7", 1)); err == nil {
		t.Error("id gap accepted")
	}
}

func TestParseProtos(t *testing.T) {
	got := parseProtos(testC)
	want := map[string]string{
		"bpf_map_lookup_elem_proto":  kindPointer,
		"bpf_tail_call_proto":        kindVoid,
		"bpf_get_stack_proto":        kindScalar,
		"bpf_get_stack_proto_raw_tp": kindScalar,
		"bpf_bind_proto":             kindPointer,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseProtos = %v, want %v", got, want)
	}
}

func TestParseJoins(t *testing.T) {
	got := parseJoins(testC)
	want := map[string]map[string]bool{
		"map_lookup_elem": {"bpf_tail_call_proto": true},
		"tail_call":       {"bpf_tail_call_proto": true},
		"get_stack":       {"bpf_get_stack_proto": true, "bpf_get_stack_proto_raw_tp": true},
		"bind":            {"bpf_bind_proto": true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseJoins = %v, want %v", got, want)
	}
}

func TestParseResolve(t *testing.T) {
	hs, err := parseMapper(testUAPI)
	if err != nil {
		t.Fatal(err)
	}
	protos := map[string]map[string]bool{}
	for p, k := range parseProtos(testC) {
		add(protos, p, k)
	}
	joins := parseJoins(testC)
	if err := resolve(hs, protos, joins, nil); err == nil || !strings.Contains(err.Error(), "5 trace_printk: no prototype joined") {
		t.Fatalf("resolve without override: %v", err)
	}
	overrides, err := parseOverrides("5 scalar # returned by bpf_get_trace_printk_proto()\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := resolve(hs, protos, joins, overrides); err != nil {
		t.Fatal(err)
	}
	src, err := render(hs, "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	table := parseTable(string(src))
	if d := compare(hs, table); len(d) > 0 {
		t.Errorf("rendered table differs: %v", d)
	}
	kinds := []string{kindUnsupported, kindVoid, kindVoid, kindScalar, kindPointer, kindScalar}
	for i, h := range table {
		if h.Kind != kinds[i] {
			t.Errorf("id %d %s: kind %s, want %s", i, h.Name, h.Kind, kinds[i])
		}
	}
	if !strings.Contains(string(src), "Linux 1.2.3") {
		t.Error("version missing from rendered table")
	}

	// A contradicting override fails.
	bad, _ := parseOverrides("2 scalar # wrong\n")
	if err := resolve(hs, protos, joins, bad); err == nil {
		t.Error("contradicting override accepted")
	}
	if _, err := parseOverrides("2 maybe\n"); err == nil {
		t.Error("bad override kind accepted")
	}
}
