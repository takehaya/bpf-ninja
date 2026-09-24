package capture

import (
	"slices"
	"testing"
)

func TestReaderCPUsSeparatePlacementFromShardIDs(t *testing.T) {
	for _, tc := range []struct {
		allowed []int
		split   int
		want    []int
	}{
		{[]int{3}, 0, []int{3, 3, 3, 3, 3}},
		{[]int{0, 2, 4}, 0, []int{0, 2, 2, 0, 4}},
		{[]int{0, 2, 4}, 2, []int{2, 4, 2, 4, 2}},
	} {
		got, err := planReaderCPUs(5, tc.allowed, tc.split)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("got %v, %v; want %v", got, err, tc.want)
		}
	}
	if _, err := planReaderCPUs(5, []int{0, 2}, 3); err == nil {
		t.Fatal("empty consumer set accepted")
	}
}
func TestReaderAffinityFailureIsRecorded(t *testing.T) {
	before := ReaderAffinityFailures()
	pinReaderToCPU(-1)
	if ReaderAffinityFailures() != before+1 {
		t.Fatal("pin error not recorded")
	}
}
