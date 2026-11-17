package injectcheck

import (
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/cilium/ebpf/asm"
)

// TestHelperReadsMatchValidator compares helperReads with the region
// validator's helperArgs, which tools/helpergen generates from the kernel
// source. The two tables stay independent. For every helper id both must
// give the same read set: a register one of them drops, the other may say is
// read. An id missing from helperArgs reads r1-r5 there.
func TestHelperReadsMatchValidator(t *testing.T) {
	src, err := os.ReadFile("../../tools/regionval/core/helperargs_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	// lastHelper is the largest helper id of Linux 7.0.13, the tree the
	// table is generated from.
	const lastHelper = 211
	args := map[int64]int{}
	rows := regexp.MustCompile(`(?m)^\s*\d+:`).FindAllIndex(src, -1)
	for _, m := range regexp.MustCompile(`(?m)^\s*(\d+):\s*([0-5]),\s*// \w+$`).FindAllStringSubmatch(string(src), -1) {
		id, _ := strconv.ParseInt(m[1], 10, 64)
		n, _ := strconv.Atoi(m[2])
		if _, dup := args[id]; dup {
			t.Fatalf("helperArgs has two rows for id %d", id)
		}
		args[id] = n
	}
	if len(args) != len(rows) {
		t.Fatalf("parsed %d of the %d rows of helperArgs", len(args), len(rows))
	}
	for id := int64(0); id <= lastHelper; id++ {
		n, ok := args[id]
		if !ok {
			n = 5
		}
		if ok == (id == 0) {
			t.Errorf("%v (%d): row in helperArgs %v, want a row for every helper and none for id 0", asm.BuiltinFunc(id), id, ok)
		}
		want := uint16(0)
		for r := 1; r <= n; r++ {
			want |= 1 << r
		}
		if got := helperReads(id); got != want {
			t.Errorf("%v (%d): helperReads %#x, validator reads r1-r%d (%#x)", asm.BuiltinFunc(id), id, got, n, want)
		}
	}
	if len(args) != lastHelper {
		t.Errorf("helperArgs has %d rows, want %d", len(args), lastHelper)
	}
}
