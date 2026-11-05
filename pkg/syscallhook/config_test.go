package syscallhook

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// fillNonZero sets every field reachable from v to a non-zero value.
func fillNonZero(t *testing.T, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(true)
	case reflect.String:
		v.SetString("x")
	case reflect.Uint32:
		v.SetUint(7)
	case reflect.Uint8:
		v.SetUint(1)
	case reflect.Int16:
		v.SetInt(-8)
	case reflect.Int:
		v.SetInt(16)
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fillNonZero(t, s.Index(0))
		v.Set(s)
	case reflect.Struct:
		for i := range v.NumField() {
			fillNonZero(t, v.Field(i))
		}
	case reflect.Pointer:
		p := reflect.New(v.Type().Elem())
		fillNonZero(t, p.Elem())
		v.Set(p)
	default:
		t.Fatalf("fillNonZero: add a value for kind %s", v.Kind())
	}
}

// Every transform field of a Rule reaches the raw transform request: with
// every field set, clearing any one of them changes the request, so a new
// option cannot be silently dropped when the rule is converted.
func TestRuleRequestForwardsOptions(t *testing.T) {
	var full Rule
	v := reflect.ValueOf(&full).Elem()
	for i := range v.NumField() {
		fillNonZero(t, v.Field(i))
	}
	full.Ops = []string{"lookup:miss", "update:any", "delete", "push", "pop:any", "peek"} // ops parseOps accepts
	want := full.request()
	for i := range v.NumField() {
		name := v.Type().Field(i).Name
		r := full
		f := reflect.ValueOf(&r).Elem().Field(i)
		f.Set(reflect.Zero(f.Type()))
		if forwarded := !reflect.DeepEqual(r.request(), want); forwarded != (name != "Program" && name != "MapBTF" && name != "StackLowestOffset") {
			t.Errorf("%s: forwarded=%v", name, forwarded)
		}
	}
}

func TestRuleWithStackLowestOffsetRejected(t *testing.T) {
	for _, value := range []string{"-8", "null"} {
		_, err := ParseConfig(strings.NewReader(`[{"program":"p","map":"sessions","hook":"h","stack_lowest_offset":` + value + `}]`))
		if err == nil || !strings.Contains(err.Error(), "stack_lowest_offset is no longer accepted") || !strings.Contains(err.Error(), "remove the field") {
			t.Fatalf("value %s: error = %v", value, err)
		}
	}
}

func TestParseConfigAppliesFrameRoundingBeforeValidation(t *testing.T) {
	config := `[{"program":"p","auto":true,"ops":["lookup:any","update:any"],"hook":"h"}]`
	rules, err := ParseConfigWithFrameRounding(strings.NewReader(config), 16)
	if err != nil || len(rules) != 1 || rules[0].FrameRounding != 16 {
		t.Fatalf("16-byte default: %+v, %v", rules, err)
	}
	explicit := strings.Replace(config, `"hook":"h"`, `"frame_rounding":32,"hook":"h"`, 1)
	if rules, err := ParseConfigWithFrameRounding(strings.NewReader(explicit), 16); err != nil || rules[0].FrameRounding != 32 {
		t.Fatalf("explicit rounding: %+v %v", rules, err)
	}
	for _, value := range []string{"0", "null"} {
		explicit = strings.Replace(config, `"hook":"h"`, `"frame_rounding":`+value+`,"hook":"h"`, 1)
		if _, err := ParseConfigWithFrameRounding(strings.NewReader(explicit), 16); err == nil || !strings.Contains(err.Error(), "frame_rounding must be 16 or 32") {
			t.Fatalf("explicit %s: %v", value, err)
		}
	}
}

func TestConfig(t *testing.T) {
	valid := `[{"program":"p","map":"sessions","func":"p","line":42,"hook":"lookup_hook"}]`
	rules, err := ParseConfig(strings.NewReader(valid))
	if err != nil || len(rules) != 1 || rules[0].Line != 42 {
		t.Fatalf("%+v: %v", rules, err)
	}
	for input, check := range map[string]func(Rule) bool{
		strings.Replace(valid, `"line":42`, `"line":42,"all_matches":true`, 1): func(r Rule) bool { return r.AllMatches },
		strings.Replace(valid, `"line":42`, `"line":42,"site_pcs":[3,9]`, 1):   func(r Rule) bool { return len(r.SitePCs) == 2 && r.SitePCs[1] == 9 },
		`[{"program":"p","auto":true,"hook":"h"}]`:                             func(r Rule) bool { return r.Auto && r.Map == "" },
		`[{"program":"p","auto":true,"maps":["a","b"],"hook":"h"}]`: func(r Rule) bool {
			return r.Auto && slices.Equal(r.Maps, []string{"a", "b"})
		},
		`[{"program":"p","entry":true,"tail_calls":true,"hook":"h"}]`: func(r Rule) bool {
			return r.Entry && r.TailCalls && r.Map == ""
		},
		`[{"program":"p","auto":true,"ops":["lookup:any"],"hook":"h"}]`: func(r Rule) bool {
			return r.request().Lookups == inject.LookupAny
		},
		strings.Replace(valid, `"line":42`, `"line":42,"ops":["lookup:miss"]`, 1): func(r Rule) bool { return r.request().Lookups == inject.LookupMiss },
		strings.Replace(valid, `"line":42`, `"line":42,"ops":["lookup"]`, 1):      func(r Rule) bool { return r.request().Lookups == inject.LookupHit },
		`[{"program":"p","auto":true,"ops":["update"],"hook":"h"}]`: func(r Rule) bool {
			req := r.request()
			return req.Lookups == inject.LookupNone && req.Updates == inject.CallError && req.Deletes == ""
		},
		`[{"program":"p","auto":true,"ops":["delete:any","lookup","update:any"],"hook":"h"}]`: func(r Rule) bool {
			req := r.request()
			return req.Lookups == inject.LookupHit && req.Updates == inject.CallAny && req.Deletes == inject.CallAny
		},
		`[{"program":"p","auto":true,"ops":["push","pop:any","peek:error"],"hook":"h"}]`: func(r Rule) bool {
			req := r.request()
			return req.Lookups == inject.LookupNone && req.Pushes == inject.CallError && req.Pops == inject.CallAny && req.Peeks == inject.CallError
		},
		// With dispatch an update keeps its value pointer in a fifth slot.
		`[{"program":"p","auto":true,"dispatch":true,"ops":["update"],"hook":"h"}]`: func(r Rule) bool { return r.Dispatch },
		// _0_update counts toward the name limit.
		`[{"program":"p","auto":true,"ops":["update"],"hook":"` + strings.Repeat("h", 118) + `"}]`: func(r Rule) bool { return r.Auto },
		// The miss hook's suffix counts toward the name limit: _0_miss.
		`[{"program":"p","auto":true,"ops":["lookup:miss"],"hook":"` + strings.Repeat("h", 120) + `"}]`: func(r Rule) bool { return r.Auto },
		strings.Replace(valid, `"line":42`, `"line":42,"entry":true`, 1):                                func(r Rule) bool { return r.Entry && r.Map == "sessions" },
		`[{"program":"p","tail_calls":true,"hook":"` + strings.Repeat("h", 117) + `"}]`:                 func(r Rule) bool { return r.TailCalls },
		`[{"program":"p","auto":true,"hook":"` + strings.Repeat("h", 125) + `"}]`:                       func(r Rule) bool { return r.Auto },
		`[{"program":"p","entry":true,"hook":"` + strings.Repeat("h", 121) + `"}]`:                      func(r Rule) bool { return r.Entry },
		`[{"program":"p","auto":true,"tail_calls":true,"dispatch":true,"hook":"` + strings.Repeat("h", 127) + `"}]`: func(r Rule) bool {
			return r.Dispatch && r.TailCalls
		},
	} {
		if rules, err := ParseConfig(strings.NewReader(input)); err != nil || !check(rules[0]) {
			t.Errorf("%s: %+v: %v", input, rules, err)
		}
	}
	for _, input := range []string{
		`[]`, `null`, valid + ` {}`, valid + strings.Repeat(" ", 1<<20) + ` {}`, strings.Replace(valid, `"line":42`, `"lines":42`, 1),
		strings.Replace(valid, `"lookup_hook"`, `"bad-name"`, 1),
		strings.Replace(valid, `"sessions"`, `""`, 1), `[` + valid[1:len(valid)-1] + `,` + valid[1:len(valid)-1] + `]`,
		strings.Replace(valid, `"line":42`, `"line":42,"all_matches":true,"site_pcs":[3]`, 1),
		strings.Replace(valid, `"line":42`, `"line":42,"site_pcs":3`, 1),
		strings.Replace(valid, `"line":42`, `"line":42,"auto":true`, 1),
		`[{"program":"p","auto":true,"line":4,"hook":"h"}]`,
		`[{"program":"p","auto":true,"site_pcs":[1],"hook":"h"}]`,
		`[{"program":"p","auto":false,"hook":"h"}]`,
		strings.Replace(valid, `"line":42`, `"line":42,"maps":["sessions"]`, 1),
		`[{"program":"p","entry":true,"maps":["a"],"hook":"h"}]`,
		`[{"program":"p","entry":true,"line":3,"hook":"h"}]`,
		`[{"program":"p","tail_calls":true,"hook":"` + strings.Repeat("h", 118) + `"}]`,
		`[{"program":"p","auto":true,"hook":"` + strings.Repeat("h", 126) + `"}]`,
		`[{"program":"p","entry":true,"hook":"` + strings.Repeat("h", 122) + `"}]`,
		`[{"program":"p","map":"m","hook":"` + strings.Repeat("h", 128) + `"}]`,
		`[{"program":"p","auto":true,"dispatch":true,"copy_read_only":true,"hook":"h"}]`,
		`[{"program":"p","auto":true,"ops":["lookup:miss"],"hook":"` + strings.Repeat("h", 121) + `"}]`,
		`[{"program":"p","auto":true,"ops":["update"],"hook":"` + strings.Repeat("h", 119) + `"}]`,
		`[{"program":"p","map":"m","ops":["update"],"hook":"h"}]`,
		`[{"program":"p","map":"m","ops":["lookup","delete"],"hook":"h"}]`,
		`[{"program":"p","auto":true,"ops":["update:miss"],"hook":"h"}]`,
		`[{"program":"p","auto":true,"ops":["delete","delete:any"],"hook":"h"}]`,
		`[{"program":"p","auto":true,"ops":["lookup:sometimes"],"hook":"h"}]`,
		`[{"program":"p","auto":true,"ops":["lookup","lookup:miss"],"hook":"h"}]`,
		`[{"program":"p","auto":true,"ops":["splice"],"hook":"h"}]`,
		`[{"program":"p","auto":true,"ops":["push:miss"],"hook":"h"}]`,
		`[{"program":"p","map":"m","ops":["pop"],"hook":"h"}]`,
		`[{"program":"p","entry":true,"ops":["lookup"],"hook":"h"}]`,
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

func testRule() Rule {
	return Rule{Program: "p", Map: "sessions", Hook: "lookup_hook"}
}
