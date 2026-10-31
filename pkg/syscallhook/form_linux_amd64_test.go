//go:build linux && amd64

package syscallhook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/pkg/inject"
	"golang.org/x/sys/unix"
)

func boolPtr(b bool) *bool { return &b }

func TestHookFormChoice(t *testing.T) {
	unsupported := &ebpf.VerifierError{Cause: unix.EOPNOTSUPP, Log: []string{"arg#2 has unsupported set of tags"}}
	for _, tc := range []struct {
		force        *bool
		err          error
		form, reason string
		calls        int
	}{
		{nil, nil, "global", "probe_arg_untrusted_supported", 1},
		{nil, unsupported, "static", "probe_arg_untrusted_unsupported", 1},
		{nil, unix.EPERM, "global", "probe_inconclusive", 1},
		{boolPtr(true), nil, "static", "config_static_untrusted_true", 0},
		{boolPtr(false), unsupported, "global", "config_static_untrusted_false", 0},
	} {
		calls := 0
		got := chooseHookForm(tc.force, func() error { calls++; return tc.err })
		if got.Form != tc.form || got.Reason != tc.reason || calls != tc.calls {
			t.Fatalf("got %+v calls=%d, want %+v", got, calls, tc)
		}
	}
}

func TestStaticRetryDecision(t *testing.T) {
	result := &inject.LookupResultRaw{Hooks: []inject.LookupHook{{Untrusted: true}}}
	for _, tc := range []struct {
		line  string
		cause error
		want  bool
	}{
		{"arg#2 has unsupported set of tags", unix.EOPNOTSUPP, true},
		{"arg#1 reference type('UNKNOWN ') size cannot be determined: -22", unix.EINVAL, true},
		{"arg#2 has unsupported set of tags", unix.EPERM, false},
		{"R6 invalid mem access 'scalar'", unix.EACCES, false},
		{"invalid map access", unix.EINVAL, false},
		{"Caller passes invalid args into func", unix.EOPNOTSUPP, false},
	} {
		err := fmt.Errorf("load: %w", &ebpf.VerifierError{Cause: tc.cause, Log: []string{tc.line}})
		if got := retryStatic(nil, HookForm{Form: "global"}, result, err); got != tc.want {
			t.Errorf("%q: %v want %v", tc.line, got, tc.want)
		}
		for _, force := range []*bool{boolPtr(true), boolPtr(false)} {
			if retryStatic(force, HookForm{Form: "global"}, result, err) {
				t.Fatal("overrode explicit config")
			}
		}
		if retryStatic(nil, HookForm{Form: "static"}, result, err) {
			t.Fatal("retried twice")
		}
		if retryStatic(nil, HookForm{Form: "global"}, &inject.LookupResultRaw{}, err) {
			t.Fatal("retried without untrusted hooks")
		}
	}
	if retryStatic(nil, HookForm{Form: "global"}, result, errors.New("arg#2 has unsupported set of tags")) {
		t.Fatal("retried without verifier error")
	}
}

func TestStaticUntrustedConfig(t *testing.T) {
	for _, value := range []string{"", ",\"static_untrusted\":true", ",\"static_untrusted\":false"} {
		input := `[{"program":"p","auto":true,"hook":"obs","stack_lowest_offset":-8` + value + `}]`
		rules, err := ParseConfig(strings.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		r := rules[0]
		if (r.StaticUntrusted == nil) != (value == "") {
			t.Fatalf("lost unset: %+v", r)
		}
		if value != "" && *r.StaticUntrusted != strings.Contains(value, "true") {
			t.Fatal("lost forced form")
		}
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "static_untrusted") != (value != "") {
			t.Fatalf("roundtrip: %s", data)
		}
	}
}

func TestGlobalUntrustedProbeEncoding(t *testing.T) {
	spec := globalUntrustedProbeSpec()
	var encoded bytes.Buffer
	if err := spec.Instructions.Marshal(&encoded, wire); err != nil {
		t.Fatal(err)
	}
	if encoded.Len() != len(spec.Instructions)*8 {
		t.Fatalf("probe encoding length %d", encoded.Len())
	}
}
