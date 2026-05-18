package codegen

import (
	"strings"
	"testing"

	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// TestVariableTailForPanicsOnUnresolvedWriteBack pins the loader-bug
// guard at variableTailFor: a WriteBackSpec whose Resolved flag is
// false (= the loader's pass-2 didn't run) must panic with a clear
// "vocab loader bug" message rather than silently treating
// ParentByteOff=0 as a real first-byte target.
func TestVariableTailForPanicsOnUnresolvedWriteBack(t *testing.T) {
	spec := &vocab.ProtocolSpec{
		Name:       "fake",
		HeaderName: "fake_h",
		HeaderAnnotations: map[string]*vocab.HeaderAnnotations{
			"fake_ext_h": {
				VariableTail: &vocab.VariableTailSpec{
					LenFieldByteOff: 1,
					LenMask:         0x03,
					LenShift:        0,
					Scale:           8,
				},
				WriteBack: &vocab.WriteBackSpec{
					SourceField:   "next_header",
					ParentProto:   "fake",
					ParentField:   "next_header",
					SourceByteOff: 0,
					ParentByteOff: 0,
					Resolved:      false, // simulating loader-bypass bug
				},
			},
		},
	}
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on unresolved WriteBackSpec, got nil")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value is %T, want string", r)
		}
		if !strings.Contains(msg, "vocab loader bug") {
			t.Errorf("panic %q should mention vocab loader bug", msg)
		}
	}()
	_, _ = variableTailFor(spec, "fake_ext_h")
}
