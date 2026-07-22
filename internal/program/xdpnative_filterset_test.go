package program

// Native-XDP verifier-load coverage for the canonical F1-F10 set.
//
// The native path runs the kunai filter directly on ctx->data
// (PTR_TO_PACKET) instead of the fentry/tc scratch-window copy
// (PTR_TO_MAP_VALUE). Aux-walk filters (GTP / Geneve / TCP options)
// used to fail here: dispatch read-backs and the option-walk kind
// load assumed a map-value bound that the verifier will not carry
// across a freshly built packet pointer. genFieldDispatch /
// emitDynamicAuxSlotPrelude now switch to the bounded idiom when R4
// is a range scalar, so every FilterSet entry must load natively.

import (
	"testing"

	"github.com/takehaya/bpf-ninja/internal/testutil"
)

func TestBpfXDPNativeFilterSet(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, fs := range FilterSet {
		t.Run(fs.ID, func(t *testing.T) {
			loadXDPNativeOrFail(t, fs.Expr, true)
		})
	}
}
