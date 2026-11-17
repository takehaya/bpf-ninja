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
	args := map[int64]int{}
	for _, m := range regexp.MustCompile(`(?m)^\s*(\d+):\s*(\d),`).FindAllStringSubmatch(string(src), -1) {
		id, _ := strconv.ParseInt(m[1], 10, 64)
		n, _ := strconv.Atoi(m[2])
		args[id] = n
	}
	for id := int64(0); ; id++ {
		if asm.BuiltinFunc(id).String() == "BuiltinFunc("+strconv.FormatInt(id, 10)+")" {
			if id != 212 {
				t.Fatalf("cilium/ebpf names helper ids 0 to %d, want 0 to 211", id-1)
			}
			break
		}
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
	if len(args) != 211 {
		t.Errorf("helperArgs has %d rows, want 211", len(args))
	}
}
