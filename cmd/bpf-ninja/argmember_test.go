package main

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/internal/attach"
)

func TestMemberParamJSON(t *testing.T) {
	plain, err := json.Marshal(paramJSON{Name: "n", Index: 2, Size: 4, Signed: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != `{"name":"n","index":2,"size":4,"signed":true}` {
		t.Fatalf("integer JSON changed: %s", plain)
	}
	ptr, err := json.Marshal(paramJSON{Name: "q", Index: 1, Size: 8, Kind: "ptr-struct", TypeName: "classifier_query"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ptr), `"kind":"ptr-struct","type_name":"classifier_query"`) {
		t.Fatalf("pointer JSON: %s", ptr)
	}
}

func TestFormatEchoMembers(t *testing.T) {
	params := []attach.FuncParamInfo{{Name: "q->imsi", Size: 8, Deref: true}, {Name: "q->target.pdr_id", Size: 4, Signed: true, Deref: true}}
	raw := make([]byte, 16)
	binary.NativeEndian.PutUint64(raw, 262010000000001)
	binary.NativeEndian.PutUint64(raw[8:], ^uint64(2))
	got := formatEchoArgs("sdf_classify", params, raw)
	if !strings.Contains(got, "q->imsi=262010000000001") || !strings.Contains(got, "q->target.pdr_id=-3") {
		t.Fatalf("echo: %s", got)
	}
}
