//go:build linux && amd64

package syscallhook

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestHookFormChoice(t *testing.T) {
	unsupported := &ebpf.VerifierError{Cause: unix.EOPNOTSUPP, Log: []string{"arg#0 has unsupported set of tags"}}
	unsized := fmt.Errorf("probe: %w", &ebpf.VerifierError{Cause: unix.EINVAL, Log: []string{"arg#0 reference type('UNKNOWN ') size cannot be determined: -22"}})
	for _, tc := range []struct {
		static       bool
		err          error
		form, reason string
		calls        int
	}{
		{false, nil, "global", "probe_arg_untrusted_supported", 1},
		{false, unsupported, "static", "probe_arg_untrusted_unsupported", 1},
		{false, unsized, "static", "probe_arg_untrusted_unsupported", 1},
		{false, unix.EPERM, "global", "probe_inconclusive", 1},
		// The errno or the message alone is not evidence of missing support.
		{false, &ebpf.VerifierError{Cause: unix.EPERM, Log: []string{"arg#0 has unsupported set of tags"}}, "global", "probe_inconclusive", 1},
		{false, &ebpf.VerifierError{Cause: unix.EINVAL, Log: []string{"R1 invalid mem access 'scalar'"}}, "global", "probe_inconclusive", 1},
		{false, errors.New("arg#0 has unsupported set of tags"), "global", "probe_inconclusive", 1},
		{true, unsupported, "static", "config_static_untrusted_true", 0},
	} {
		calls := 0
		got := chooseHookForm(tc.static, func() error { calls++; return tc.err })
		if got.Form != tc.form || got.Reason != tc.reason || calls != tc.calls {
			t.Fatalf("got %+v calls=%d, want %+v", got, calls, tc)
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
