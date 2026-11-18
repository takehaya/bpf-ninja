package inject

import (
	"bufio"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// Every helper id 1 to 211 has a row in testdata/helper_premise.tsv, with
// the name the generated table gives it, and the helpers helperPremise marks
// are exactly the rows whose rule column names a clause, that clause's
// reason: a helper cannot be left out on either side.
func TestHelperPremiseTable(t *testing.T) {
	f, err := os.Open("testdata/helper_premise.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	reasons := map[string]string{"-": "", "code": premiseCodeReason, "counter": premiseCounterReason,
		"callback": callbackReason, "lock": premiseLockReason}
	seen := map[int64]bool{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(nil, 1<<20)
	scanner.Scan() // header
	if !strings.HasPrefix(scanner.Text(), "id\tname\trule\tclass\t") || !strings.Contains(scanner.Text(), "\tevidence\t") {
		t.Fatalf("header %q", scanner.Text())
	}
	for scanner.Scan() {
		cols := strings.Split(scanner.Text(), "\t")
		id, err := strconv.ParseInt(cols[0], 10, 64)
		if err != nil || len(cols) < 8 || seen[id] {
			t.Fatalf("row %q: %v", scanner.Text(), err)
		}
		seen[id] = true
		h, ok := helperByID(id)
		if !ok || h.Name != cols[1] {
			t.Errorf("id %d: table name %q, generated %q", id, cols[1], h.Name)
		}
		want, ok := reasons[cols[2]]
		if !ok {
			t.Errorf("%s: unknown rule %q", cols[1], cols[2])
		}
		if got := helperPremise(cols[1]); got != want {
			t.Errorf("%s: helperPremise %q, table rule %q", cols[1], got, cols[2])
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	for id := int64(1); id <= 211; id++ {
		if !seen[id] {
			t.Errorf("helper id %d has no row", id)
		}
	}
	if len(seen) != 211 {
		t.Errorf("%d rows, want 211", len(seen))
	}
}

// A load is reported as not reviewed for every kernel function without a
// review record for where it is defined, the receive-metadata functions
// among them with the driver's note, and for a call that cannot be named;
// the conntrack lookups and their release are reviewed in vmlinux and in
// the nf_conntrack module, a function of the same name in another module
// is not, and helpers never count.
func TestNotReviewed(t *testing.T) {
	fn := func(name string) *btf.Func {
		return &btf.Func{Name: name, Type: &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}}, Linkage: btf.GlobalFunc}
	}
	kernel := specOf(t, fn("bpf_xdp_ct_lookup"), fn("bpf_skb_ct_lookup"), fn("bpf_ct_release"), fn("bpf_xdp_metadata_rx_hash"), fn("k_int"))
	insns := asm.Instructions{
		testKfunc(t, kernel, "bpf_xdp_ct_lookup"), asm.FnKtimeGetNs.Call(), testKfunc(t, kernel, "bpf_xdp_metadata_rx_hash"),
		testKfunc(t, kernel, "bpf_ct_release"), testKfunc(t, kernel, "k_int"), testKfunc(t, kernel, "bpf_xdp_metadata_rx_hash"),
		testKfunc(t, kernel, "bpf_skb_ct_lookup"), asm.FnLoop.Call(),
	}
	if got := NotReviewed(insns, kernel, nil, nil); !slices.Equal(got, []string{"bpf_xdp_metadata_rx_hash" + DriverNote, "k_int"}) {
		t.Errorf("not reviewed %v", got)
	}
	if got := NotReviewed(insns, nil, nil, nil); !slices.Equal(got, []string{UnnamedKfunc}) {
		t.Errorf("without kernel BTF: %v", got)
	}
	if got := NotReviewed(insns[:2], kernel, nil, nil); got != nil {
		t.Errorf("reviewed calls only: %v", got)
	}
	module := specOf(t, fn("bpf_xdp_ct_lookup"), fn("bpf_ct_release"))
	lookup, release := testKfunc(t, module, "bpf_xdp_ct_lookup"), testKfunc(t, module, "bpf_ct_release")
	lookup.Offset, release.Offset = 1, 2
	modules := map[int16]*btf.Spec{1: module, 2: module}
	for _, tc := range []struct {
		homes map[int16]string
		want  []string
	}{
		{map[int16]string{1: "nf_conntrack", 2: "nf_conntrack"}, nil},
		{map[int16]string{1: "other", 2: "nf_conntrack"}, []string{"bpf_xdp_ct_lookup (in other)"}},
		{map[int16]string{2: "nf_conntrack"}, []string{"bpf_xdp_ct_lookup (in a module not named)"}},
	} {
		if got := NotReviewed(asm.Instructions{lookup, release}, kernel, modules, tc.homes); !slices.Equal(got, tc.want) {
			t.Errorf("module calls with homes %v: %v, want %v", tc.homes, got, tc.want)
		}
	}
}
