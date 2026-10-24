package syscallhook

import (
	"strings"
	"testing"
)

func TestConfig(t *testing.T) {
	valid := `[{"program":"p","map":"sessions","func":"p","line":42,"hook":"lookup_hook","stack_lowest_offset":-8}]`
	rules, err := ParseConfig(strings.NewReader(valid))
	if err != nil || len(rules) != 1 || rules[0].Line != 42 || *rules[0].StackLowestOffset != -8 {
		t.Fatalf("%+v: %v", rules, err)
	}
	for input, check := range map[string]func(Rule) bool{
		strings.Replace(valid, `"line":42`, `"line":42,"all_matches":true`, 1): func(r Rule) bool { return r.AllMatches },
		strings.Replace(valid, `"line":42`, `"line":42,"site_pcs":[3,9]`, 1):   func(r Rule) bool { return len(r.SitePCs) == 2 && r.SitePCs[1] == 9 },
		`[{"program":"p","auto":true,"hook":"h","stack_lowest_offset":-8}]`:    func(r Rule) bool { return r.Auto && r.Map == "" },
		`[{"program":"p","entry":true,"tail_calls":true,"hook":"h","stack_lowest_offset":-8}]`: func(r Rule) bool {
			return r.Entry && r.TailCalls && r.Map == ""
		},
		strings.Replace(valid, `"line":42`, `"line":42,"entry":true`, 1):                                         func(r Rule) bool { return r.Entry && r.Map == "sessions" },
		`[{"program":"p","tail_calls":true,"hook":"` + strings.Repeat("h", 117) + `","stack_lowest_offset":-8}]`: func(r Rule) bool { return r.TailCalls },
	} {
		if rules, err := ParseConfig(strings.NewReader(input)); err != nil || !check(rules[0]) {
			t.Errorf("%s: %+v: %v", input, rules, err)
		}
	}
	for _, input := range []string{
		`[]`, `null`, valid + ` {}`, valid + strings.Repeat(" ", 1<<20) + ` {}`, strings.Replace(valid, `"line":42`, `"lines":42`, 1),
		strings.Replace(valid, `,"stack_lowest_offset":-8`, "", 1), strings.Replace(valid, `:-8`, `:1`, 1),
		strings.Replace(valid, `:-8`, `:-489`, 1), strings.Replace(valid, `"lookup_hook"`, `"bad-name"`, 1),
		strings.Replace(valid, `"sessions"`, `""`, 1), `[` + valid[1:len(valid)-1] + `,` + valid[1:len(valid)-1] + `]`,
		strings.Replace(valid, `"line":42`, `"line":42,"all_matches":true,"site_pcs":[3]`, 1),
		strings.Replace(valid, `"line":42`, `"line":42,"site_pcs":3`, 1),
		strings.Replace(valid, `"line":42`, `"line":42,"auto":true`, 1),
		`[{"program":"p","auto":true,"line":4,"hook":"h","stack_lowest_offset":-8}]`,
		`[{"program":"p","auto":true,"site_pcs":[1],"hook":"h","stack_lowest_offset":-8}]`,
		`[{"program":"p","auto":false,"hook":"h","stack_lowest_offset":-8}]`,
		`[{"program":"p","entry":true,"line":3,"hook":"h","stack_lowest_offset":-8}]`,
		`[{"program":"p","tail_calls":true,"hook":"` + strings.Repeat("h", 118) + `","stack_lowest_offset":-8}]`,
	} {
		if _, err := ParseConfig(strings.NewReader(input)); err == nil {
			t.Errorf("accepted %s", input)
		}
	}
}

func validAttr() []byte {
	b := make([]byte, 168)
	put32(b, 0, 6)
	put32(b, 4, 10)
	put64(b, 8, 0x1234567887654321)
	copy(b[48:64], "p")
	put32(b, 72, 42)
	put32(b, 76, 8)
	put64(b, 80, 0x23456789)
	put32(b, 88, 1)
	put32(b, 92, 16)
	put64(b, 96, 0x34567890)
	put32(b, 104, 1)
	return b
}
func TestProgAttr(t *testing.T) {
	b := validAttr()
	if err := parseProgAttr(b); err != nil {
		t.Fatal(err)
	}
	if u64(b, 8) != 0x1234567887654321 || cstring(b[48:64]) != "p" {
		t.Fatal("wire decoding")
	}
	for _, n := range []int{0, 8, 64, 72, 80, 104, 107} {
		if err := parseProgAttr(b[:n]); err == nil {
			t.Errorf("accepted length %d", n)
		}
	}
	for _, field := range []struct {
		off   int
		value uint32
	}{
		{4, 0}, {4, ^uint32(0)}, {72, 0}, {76, 12}, {88, ^uint32(0)}, {92, 20}, {104, ^uint32(0)},
		{116, 1}, {120, 1}, {128, 1}, {136, 1}, {144, 1}, {148, 1}, {152, 1}, {160, 1}, {164, 1},
	} {
		b := validAttr()
		put32(b, field.off, field.value)
		if err := parseProgAttr(b); err == nil {
			t.Errorf("accepted field %d=%d", field.off, field.value)
		}
	}
	// A loader may pass the historical attr size, no line rows, or an output-only
	// log_true_size from an earlier attempt. None requires relocating a new input.
	b = validAttr()
	put32(b, 104, 0)
	put32(b, 92, 0)
	put32(b, 140, 123)
	if err := parseProgAttr(b); err != nil {
		t.Fatal(err)
	}
	if err := parseProgAttr(b[:108]); err != nil {
		t.Fatal(err)
	}
}
