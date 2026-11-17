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
	.arg1_type	= ARG_PTR_TO_CTX,
};

static const struct bpf_func_proto bpf_get_stack_proto_raw_tp = {
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};

static const struct bpf_func_proto bpf_bind_proto = {
	.ret_type	= RET_PTR_TO_BTF_ID | PTR_MAYBE_NULL,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_DONTCARE,
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
	want := map[string]map[string]bool{
		"bpf_map_lookup_elem_proto":  {kindPointer: true},
		"bpf_tail_call_proto":        {kindVoid: true},
		"bpf_get_stack_proto":        {kindScalar: true},
		"bpf_get_stack_proto_raw_tp": {kindScalar: true},
		"bpf_bind_proto":             {kindPointer: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseProtos = %v, want %v", got, want)
	}
}

// Every variant of a prototype name in one file counts, as under #ifdef,
// and a prototype without .ret_type returns RET_INTEGER.
func TestParseProtosVariants(t *testing.T) {
	src := `
#ifdef CONFIG_X
const struct bpf_func_proto bpf_x_proto = {
	.ret_type	= RET_PTR_TO_MEM_OR_NULL,
};
#else
const struct bpf_func_proto bpf_x_proto = {
	.ret_type	= RET_INTEGER,
};
#endif
static const struct bpf_func_proto bpf_y_proto = {
	.func		= bpf_y,
	.arg1_type	= ARG_ANYTHING,
};
`
	want := map[string]map[string]bool{"bpf_x_proto": {kindPointer: true, kindScalar: true}, "bpf_y_proto": {kindScalar: true}}
	if got := parseProtos(src); !reflect.DeepEqual(got, want) {
		t.Errorf("parseProtos = %v, want %v", got, want)
	}
}

func TestParseProtoArgs(t *testing.T) {
	got := parseProtoArgs(testC)
	want := map[string]int{
		"bpf_map_lookup_elem_proto":  1,
		"bpf_tail_call_proto":        0,
		"bpf_get_stack_proto":        1,
		"bpf_get_stack_proto_raw_tp": 4,
		"bpf_bind_proto":             2,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseProtoArgs = %v, want %v", got, want)
	}
}

// The argument count is the union over a helper's prototypes; an override
// gives the count of an unjoined id and may raise but not lower a count.
func TestResolveArgs(t *testing.T) {
	hs, err := parseMapper(testUAPI)
	if err != nil {
		t.Fatal(err)
	}
	protoArgs, joins := parseProtoArgs(testC), parseJoins(testC)
	if err := resolveArgs(hs, protoArgs, joins, nil); err == nil || !strings.Contains(err.Error(), "5 trace_printk: no prototype joined") {
		t.Fatalf("resolveArgs without override: %v", err)
	}
	overrides, err := parseArgOverrides("5 5 # reads r3-r5\n2 3 # reads past its prototype\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := resolveArgs(hs, protoArgs, joins, overrides); err != nil {
		t.Fatal(err)
	}
	var got []int
	for _, h := range hs {
		got = append(got, h.Args)
	}
	if want := []int{0, 0, 3, 4, 2, 5}; !reflect.DeepEqual(got, want) {
		t.Errorf("args %v, want %v", got, want)
	}
	src, err := renderArgs(hs, "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if d := compare(argsOnly(hs), parseArgsTable(string(src))); len(d) > 0 || len(parseArgsTable(string(src))) != 5 {
		t.Errorf("rendered argument table differs: %v\n%s", d, src)
	}
	if strings.Contains(string(src), "// unspec") {
		t.Error("id 0 has a row")
	}

	lower, _ := parseArgOverrides("3 3 # fewer than get_stack_proto_raw_tp\n")
	if err := resolveArgs(hs, protoArgs, joins, lower); err == nil || !strings.Contains(err.Error(), "reads fewer registers") {
		t.Errorf("lowering override: %v", err)
	}
	for _, bad := range []string{"2 6\n", "2\n", "2 scalar\n"} {
		if _, err := parseArgOverrides(bad); err == nil {
			t.Errorf("bad argument override %q accepted", bad)
		}
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
	protos := parseProtos(testC)
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

	// Prototypes of different kinds need an override, which must be one of them.
	add(protos, "bpf_get_stack_proto_raw_tp", kindPointer)
	if err := resolve(hs, protos, joins, overrides); err == nil || !strings.Contains(err.Error(), "3 get_stack: prototypes disagree") {
		t.Errorf("disagreeing prototypes: %v", err)
	}
	for _, tc := range []struct{ txt, want string }{
		{"5 scalar #\n3 void # neither kind\n", "3 get_stack: override RetVoid is none of the joined kinds"},
	} {
		o, err := parseOverrides(tc.txt)
		if err != nil {
			t.Fatal(err)
		}
		if err := resolve(hs, protos, joins, o); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v", tc.txt, err)
		}
	}
	o, _ := parseOverrides("5 scalar #\n3 pointer # one of them\n")
	if err := resolve(hs, protos, joins, o); err != nil || hs[3].Kind != kindPointer {
		t.Errorf("joined-kind override: %v, kind %s", err, hs[3].Kind)
	}
}

// A second override of an id, and an override of an id the tree does not
// have, are errors.
func TestOverrideIDs(t *testing.T) {
	if _, err := parseOverrides("5 scalar # a\n5 scalar # b\n"); err == nil || !strings.Contains(err.Error(), "a second override of id 5") {
		t.Errorf("duplicate override: %v", err)
	}
	if _, err := parseArgOverrides("5 5 # a\n5 4 # b\n"); err == nil || !strings.Contains(err.Error(), "a second count of id 5") {
		t.Errorf("duplicate argument override: %v", err)
	}
	for _, ids := range [][]int{{0}, {6}, {2, 9}} {
		if err := checkOverrideIDs("overrides.txt", 6, ids); err == nil || !strings.Contains(err.Error(), "is not a helper of this tree") {
			t.Errorf("ids %v: %v", ids, err)
		}
	}
	if err := checkOverrideIDs("overrides.txt", 6, []int{1, 5}); err != nil {
		t.Error(err)
	}
}
