package main

import (
	"fmt"
	"io"

	"github.com/takehaya/bpf-ninja/internal/attach"
)

func printTargetDiagnostics(w io.Writer, diagnostics []attach.TargetDiagnostic) {
	absent, external := 0, 0
	for _, d := range diagnostics {
		if d.Skipped {
			if d.Availability.Reason == attach.FuncNotInTarget {
				external++
			} else {
				absent++
			}
			_, _ = fmt.Fprintf(w, "warning: skipping %s\n", d)
			continue
		}
		detail := ""
		if d.Availability.Detail != "" {
			detail = ": " + d.Availability.Detail
		}
		_, _ = fmt.Fprintf(w, "warning: %s; could not check func_info%s; letting the kernel verify it\n", d, detail)
	}
	if skipped := absent + external; skipped > 0 {
		_, _ = fmt.Fprintf(w, "Skipped %d target(s): %d absent from loaded func_info, %d external declaration(s).\n", skipped, absent, external)
	}
}
