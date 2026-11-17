package inject

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
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
