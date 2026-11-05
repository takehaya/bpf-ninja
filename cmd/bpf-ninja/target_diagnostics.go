package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/takehaya/bpf-ninja/internal/attach"
)

func printTargetDiagnostics(w io.Writer, diagnostics []attach.TargetDiagnostic) {
	absent, external, ctxRefused, ctxUnchecked, loadFailed := 0, 0, 0, 0, 0
	for _, d := range diagnostics {
		if d.Skipped {
			switch {
			case d.Reason == attach.TargetStaticCtxRefused:
				ctxRefused++
			case d.Reason == attach.TargetObserverLoadFailed:
				loadFailed++
			case d.Availability.Reason == attach.FuncNotInTarget:
				external++
			default:
				absent++
			}
			_, _ = fmt.Fprintf(w, "warning: skipping %s\n", d)
			continue
		}
		if d.Reason == attach.TargetStaticCtxUnchecked {
			ctxUnchecked++
			continue
		}
		detail := ""
		if d.Availability.Detail != "" {
			detail = ": " + d.Availability.Detail
		}
		_, _ = fmt.Fprintf(w, "warning: %s; could not check func_info%s; letting the kernel verify it\n", d, detail)
	}
	if skipped := absent + external + ctxRefused + loadFailed; skipped > 0 {
		_, _ = fmt.Fprintf(w, "Skipped %d target(s): %d absent from loaded func_info, %d external declaration(s), %d refused by the static context check, %d observer load failure(s).\n", skipped, absent, external, ctxRefused, loadFailed)
	}
	if ctxUnchecked > 0 {
		_, _ = fmt.Fprintf(w, "%d generated hook(s): context check rests on the stack floor.\n", ctxUnchecked)
	}
}

func printPartialCoverage(w io.Writer, requested int, attached []int) {
	if len(attached) == requested {
		return
	}
	_, _ = fmt.Fprintf(w, "warning: PARTIAL COVERAGE: coverage=partial requested=%d attached=%d skipped=%d\n", requested, len(attached), requested-len(attached))
}

func attachedTargets(targets []attach.Target, indexes []int) []attach.Target {
	out := make([]attach.Target, len(indexes))
	for i, index := range indexes {
		out[i] = targets[index]
	}
	return out
}

func captureTargetLabel(targets []attach.Target, iface string) string {
	if len(targets) == 1 {
		label := fmt.Sprintf("prog %q id=%d", targets[0].FuncName, targets[0].ProgID)
		if iface != "" {
			label += " on " + iface
		}
		return label
	}
	names := make([]string, len(targets))
	for i, t := range targets {
		names[i] = fmt.Sprintf("%s@%d", t.FuncName, t.ProgID)
	}
	return fmt.Sprintf("%d attach points: %s", len(targets), strings.Join(names, ", "))
}
