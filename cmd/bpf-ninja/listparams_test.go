package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/urfave/cli/v3"
)

func memberListTarget() attach.Target {
	u32 := &btf.Typedef{Name: "__u32", Type: &btf.Int{Name: "unsigned int", Size: 4}}
	q := &btf.Struct{Name: "query", Size: 16, Members: []btf.Member{
		{Name: "imsi", Type: &btf.Int{Name: "u64", Size: 8}},
		{Name: "target", Offset: 64, Type: &btf.Struct{Name: "target", Size: 4, Members: []btf.Member{{Name: "pdr_id", Type: u32}}}},
		{Name: "flags", Offset: 96, BitfieldSize: 3, Type: u32},
	}}
	return attach.Target{FuncName: "classify", ProgID: 42, Params: []attach.FuncParamInfo{
		{Name: "q", Index: 1, Size: 8, Kind: "ptr-struct", TypeName: "query", Type: &btf.Pointer{Target: q}},
	}}
}

func TestListParamsMembersOutput(t *testing.T) {
	target := memberListTarget()
	view := paramsToJSON(target, true, 3)
	var text bytes.Buffer
	printParams(&text, view)
	wantText := `Filterable parameters for classify (id=42):
  q: struct query * (arg index 1)
    q->imsi  u64  off 0  size 8  unsigned  filterable
    q->target  struct target  off 8  size 4  (not filterable: final member must be an integer or enum, got struct (select one of its members))
      q->target.pdr_id  __u32  off 8  size 4  unsigned  filterable
    q->flags  __u32:3  off 12  size 4  unsigned  (not filterable: bitfield member "flags" is not supported)
`
	if text.String() != wantText {
		t.Fatalf("text output:\n%s\nwant:\n%s", text.String(), wantText)
	}
	raw, err := json.MarshalIndent([]paramsTargetJSON{view}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	wantJSON := `[{"func":"classify","id":42,"params":[{
  "name":"q","index":1,"size":8,"signed":false,"kind":"ptr-struct","type_name":"query","type":"struct query *",
  "members":[
    {"expression":"q->imsi","type":"u64","offset":0,"size":8,"signed":false,"filterable":true},
    {"expression":"q->target","type":"struct target","offset":8,"size":4,"filterable":false,
     "reason":"final member must be an integer or enum, got struct (select one of its members)",
     "members":[{"expression":"q->target.pdr_id","type":"__u32","offset":8,"size":4,"signed":false,"filterable":true}]},
    {"expression":"q->flags","type":"__u32","offset":12,"size":4,"signed":false,"bitfield_size":3,"filterable":false,
     "reason":"bitfield member \"flags\" is not supported"}
  ]}]}]`
	var got, want any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(wantJSON), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("JSON output:\n%s", raw)
	}
	t.Logf("text sample:\n%s", text.String())
	t.Logf("JSON sample:\n%s", raw)
	stdout, stderr, err := captureStdio(t, func() error {
		return emitJSON([]paramsTargetJSON{view})
	})
	if err != nil || stderr != "" || stdout != string(raw)+"\n" {
		t.Fatalf("JSON streams: stdout=%q stderr=%q error=%v", stdout, stderr, err)
	}
	stdout, stderr, err = captureStdio(t, func() error {
		printParams(os.Stderr, view)
		return nil
	})
	if err != nil || stdout != "" || stderr != wantText {
		t.Fatalf("text streams: stdout=%q stderr=%q error=%v", stdout, stderr, err)
	}

	legacy, err := json.Marshal(paramsToJSON(target, false, 3))
	if err != nil {
		t.Fatal(err)
	}
	if string(legacy) != `{"func":"classify","id":42,"params":[{"name":"q","index":1,"size":8,"signed":false,"kind":"ptr-struct","type_name":"query"}]}` {
		t.Fatalf("legacy JSON changed: %s", legacy)
	}
	shallow := paramsToJSON(target, true, 1)
	text.Reset()
	printParams(&text, shallow)
	raw, err = json.Marshal(shallow)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text.String(), "q->target.pdr_id") || !strings.Contains(text.String(), "... (depth limit; members omitted)") || !bytes.Contains(raw, []byte(`"members_truncated":"depth limit"`)) {
		t.Fatalf("truncation missing: %s\n%s", text.String(), raw)
	}
}

func TestMembersFlags(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--members"}, "--members requires --list-params"},
		{[]string{"--members-depth", "2"}, "--members-depth requires --list-params --members"},
		{[]string{"--list-params", "--members-depth", "2"}, "--members-depth requires"},
		{[]string{"--list-params", "--members", "--members-depth", "0"}, "must be between 1 and 32"},
		{[]string{"--list-params", "--members", "--members-depth", "-1"}, "must be between 1 and 32"},
		{[]string{"--list-params", "--members", "--members-depth", "33"}, "must be between 1 and 32"},
		{[]string{"--list-params", "--members", "--list-funcs"}, "cannot be combined"},
		{[]string{"--list-params", "--members", "--list-progs"}, "cannot be combined"},
		{[]string{"--list-params", "--members", "--dump-asm", "filter"}, "cannot be combined"},
		{[]string{"--list-params", "--members", "--mode", "xdp", "-i", "no-such-ninja"}, "only valid with --mode entry/exit"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			err := newRootCommand().Run(context.Background(), append([]string{"bpf-ninja"}, tc.args...))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	for _, depth := range []string{"", "1", "32"} {
		t.Run("valid depth "+depth, func(t *testing.T) {
			cmd := newRootCommand()
			cmd.Action = func(_ context.Context, cmd *cli.Command) error {
				if depth == "" && cmd.Int("members-depth") != 3 {
					t.Fatal("unexpected default depth")
				}
				return validateMembersFlags(cmd)
			}
			args := []string{"bpf-ninja", "--list-params", "--members"}
			if depth != "" {
				args = append(args, "--members-depth", depth)
			}
			if err := cmd.Run(context.Background(), args); err != nil {
				t.Fatal(err)
			}
		})
	}
}
