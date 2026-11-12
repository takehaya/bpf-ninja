package main

import (
	"runtime"
	"slices"
	"testing"
)

func TestRunTrafficContinuesOldGenerationDuringLoad(t *testing.T) {
	loaded, release := make(chan struct{}), make(chan struct{})
	generation := 1
	var old, next []int
	first, sent := runTraffic(400, 100, func() <-chan struct{} {
		go func() {
			<-release
			close(loaded)
		}()
		return loaded
	}, func() {
		generation = 2
	}, func(seq int) {
		if generation == 1 {
			old = append(old, seq)
			if seq == 102 {
				close(release)
			}
		} else {
			next = append(next, seq)
		}
	}, runtime.Gosched)

	if first < 103 || len(next) != 300 || sent != first+300 {
		t.Fatalf("first next=%d sent=%d old=%d next=%d", first, sent, len(old), len(next))
	}
	if !slices.Equal(old, sequence(0, first)) || !slices.Equal(next, sequence(first, sent)) {
		t.Fatalf("non-contiguous traffic: old=%v next=%v", old, next)
	}
}

func sequence(first, last int) []int {
	out := make([]int, last-first)
	for i := range out {
		out[i] = first + i
	}
	return out
}
