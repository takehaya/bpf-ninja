package program

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/internal/hook"
)

// TestDumpAsmFilter checks that DumpAsm in filter scope renders the
// kunai/cbpfc Main without panicking and includes the expected
// structural section markers.
func TestDumpAsmFilter(t *testing.T) {
	cases := []struct {
		name   string
		expr   string
		useDSL bool
		mode   string
		// substrings the rendered output must contain
		want []string
	}{
		{
			name:   "DSL eth/ipv4/tcp",
			expr:   "eth/ipv4/tcp",
			useDSL: true,
			mode:   "entry",
			want: []string{
				"DSL → eBPF (kunai)",
				"=== Main",
				"=== Callbacks",
				"=== CaptureInfo",
			},
		},
		{
			name:   "tcpdump tcp port 443",
			expr:   "tcp port 443",
			useDSL: false,
			mode:   "entry",
			want: []string{
				"tcpdump → cBPF → eBPF (cbpfc)",
				"=== Main",
				"=== Callbacks",
				"(none)",
			},
		},
		{
			name:   "DSL with capture clause sets MaxCapLen",
			expr:   "eth/ipv4/tcp capture headers+64",
			useDSL: true,
			mode:   "entry",
			want: []string{
				"MaxCapLen: ", // any non-zero value
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := DumpAsm(&buf, io.Discard, DumpScopeFilter, tc.expr, tc.useDSL, tc.mode, hook.KindXDP); err != nil {
				t.Fatalf("DumpAsm: %v", err)
			}
			got := buf.String()
			for _, s := range tc.want {
				if !strings.Contains(got, s) {
					t.Errorf("output missing %q\n--- got ---\n%s", s, got)
				}
			}
		})
	}
}

// TestDumpAsmFull checks that the full-program scope wraps the filter
// with the loadProbe prologue (xdp_buff load, scratch lookup) and
// the bpf_xdp_output epilogue, with map FDs left at 0.
func TestDumpAsmFull(t *testing.T) {
	var buf bytes.Buffer
	if err := DumpAsm(&buf, io.Discard, DumpScopeFull, "eth/ipv4/tcp", true, "exit", hook.KindXDP); err != nil {
		t.Fatalf("DumpAsm full: %v", err)
	}
	got := buf.String()

	// Tracing-wrapper markers — present only when full scope wraps the filter.
	wrapperMarkers := []string{
		"=== Full tracing program",
		"mode=exit",
		"FnMapLookupElem",  // scratch lookup in runFilter
		"FnRingbufReserve", // capture epilogue: reserve+submit
		"FnRingbufSubmit",
		"fd: 0", // placeholder map FDs
	}
	for _, s := range wrapperMarkers {
		if !strings.Contains(got, s) {
			t.Errorf("full scope output missing %q", s)
		}
	}
}

// TestDumpAsmFullXDP checks that mode=xdp produces the XDP-native
// shape (direct packet access for filter, FnRingbufReserve +
// FnRingbufSubmit epilogue) instead of the tracing wrapper.
func TestDumpAsmFullXDP(t *testing.T) {
	var buf bytes.Buffer
	if err := DumpAsm(&buf, io.Discard, DumpScopeFull, "tcp port 443", false, "xdp", hook.KindXDP); err != nil {
		t.Fatalf("DumpAsm full xdp: %v", err)
	}
	got := buf.String()

	wantMarkers := []string{
		"=== Full XDP-native program",
		"mode=xdp",
		"FnGetSmpProcessorId",
		"FnMapLookupElem",
		"FnRingbufReserve",
		"FnRingbufSubmit",
	}
	for _, s := range wantMarkers {
		if !strings.Contains(got, s) {
			t.Errorf("xdp full scope output missing %q", s)
		}
	}

	wrongMarkers := []string{
		"FnXdpOutput",
	}
	for _, s := range wrongMarkers {
		if strings.Contains(got, s) {
			t.Errorf("xdp full scope output unexpectedly contains tracing marker %q", s)
		}
	}
}

func TestDumpAsmErrors(t *testing.T) {
	cases := []struct {
		name    string
		scope   DumpScope
		expr    string
		useDSL  bool
		wantSub string
	}{
		{
			name:    "empty expression",
			scope:   DumpScopeFilter,
			expr:    "",
			wantSub: "requires a filter expression",
		},
		{
			// The expression warns, so this case also checks that an
			// error after a successful compile drops the warnings.
			name:    "invalid scope",
			scope:   DumpScope("bogus"),
			expr:    "eth/ipv4/(tcp|tcp)",
			useDSL:  true,
			wantSub: `unknown scope "bogus"`,
		},
		{
			name:    "invalid DSL",
			scope:   DumpScopeFilter,
			expr:    "eth/garbage_proto",
			useDSL:  true,
			wantSub: "unknown protocol",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf, warn bytes.Buffer
			err := DumpAsm(&buf, &warn, tc.scope, tc.expr, tc.useDSL, "entry", hook.KindXDP)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
			if warn.Len() != 0 {
				t.Errorf("an error must drop warnings, got %q", warn.String())
			}
		})
	}
}

// TestDumpAsmWarnings checks that resolver warnings reach warnW as
// "warning:" lines in both scopes while w carries only the asm, and
// that the cbpfc path, which has no warnings, writes none.
func TestDumpAsmWarnings(t *testing.T) {
	for _, scope := range []DumpScope{DumpScopeFilter, DumpScopeFull} {
		t.Run(string(scope), func(t *testing.T) {
			var asm, warn bytes.Buffer
			if err := DumpAsm(&asm, &warn, scope, "eth/ipv4/(tcp|tcp)", true, "entry", hook.KindXDP); err != nil {
				t.Fatalf("DumpAsm: %v", err)
			}
			got := warn.String()
			if n := strings.Count(got, "\n"); n != 1 {
				t.Errorf("want one warning line, got %d:\n%s", n, got)
			}
			if !strings.HasPrefix(got, "warning: tcp at 1:11 and tcp at 1:15 are members of one alternation") ||
				!strings.HasSuffix(got, "Keep one of them.\n") {
				t.Errorf("unexpected warning:\n%s", got)
			}
			if !strings.Contains(asm.String(), "===") {
				t.Errorf("asm output missing section markers:\n%s", asm.String())
			}
			if strings.Contains(asm.String(), "warning:") {
				t.Errorf("asm output must not carry warnings:\n%s", asm.String())
			}
		})
	}

	t.Run("before the asm", func(t *testing.T) {
		var out bytes.Buffer
		if err := DumpAsm(&out, &out, DumpScopeFilter, "eth/ipv4/(tcp|tcp)", true, "entry", hook.KindXDP); err != nil {
			t.Fatalf("DumpAsm: %v", err)
		}
		got := out.String()
		if w, a := strings.Index(got, "warning:"), strings.Index(got, "==="); w < 0 || a < 0 || w > a {
			t.Errorf("warning must precede the asm:\n%s", got)
		}
	})

	t.Run("cbpf", func(t *testing.T) {
		var asm, warn bytes.Buffer
		if err := DumpAsm(&asm, &warn, DumpScopeFilter, "tcp port 443", false, "entry", hook.KindXDP); err != nil {
			t.Fatalf("DumpAsm: %v", err)
		}
		if warn.Len() != 0 {
			t.Errorf("cbpfc path wrote warnings: %q", warn.String())
		}
	})
}

func TestWriteWarnings(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"a"}, "warning: a\n"},
		{[]string{"a", "b"}, "warning: a\nwarning: b\n"},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		WriteWarnings(&buf, tc.in)
		if got := buf.String(); got != tc.want {
			t.Errorf("WriteWarnings(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
