package program

import (
	"testing"

	"github.com/takehaya/xdp-ninja/internal/capture"
)

// TestMetadataSizeMatchesCapture pins the program-side metadataSize
// constant to capture.MetadataSize so a wire-format change cannot
// drift the two apart silently.
func TestMetadataSizeMatchesCapture(t *testing.T) {
	if metadataSize != capture.MetadataSize {
		t.Fatalf("metadataSize=%d != capture.MetadataSize=%d", metadataSize, capture.MetadataSize)
	}
}
