//go:build linux && amd64

package syscallhook

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/pkg/inject"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
)

func loadCheckPolicy(err error, failClosed bool) (bool, error) {
	if err == nil {
		return true, nil
	}
	if errors.Is(err, inject.ErrCheckerNotApplicable) {
		if failClosed {
			return false, err
		}
		return false, nil
	}
	return false, fmt.Errorf("checker rejected the transform: %w; probe was not installed", err)
}

// Layout hints remain untrusted; injectcheck accounts for every instruction.
func loadCheckInputs(original asm.Instructions, result *inject.LookupResultRaw, floor int16) (injectcheck.Certificate, injectcheck.Premises, error) {
	names := map[string]bool{}
	for _, h := range result.Hooks {
		names[h.Name] = true
	}
	var spans []injectcheck.Span
	for i := 0; i < len(result.Instructions); i++ {
		fn := btf.FuncMetadata(&result.Instructions[i])
		if fn == nil || !names[fn.Name] {
			continue
		}
		end := i + 1
		for end < len(result.Instructions) && btf.FuncMetadata(&result.Instructions[end]) == nil {
			end++
		}
		spans = append(spans, injectcheck.Span{Start: i, End: end})
		i = end - 1
	}
	cert, err := injectcheck.FromLabels(result.Instructions, len(original), spans)
	if err != nil {
		return cert, injectcheck.Premises{}, fmt.Errorf("checker cannot build instruction correspondence: %w", err)
	}
	targets, err := inject.BuildLookupTargets(result.Instructions, result.Hooks)
	if err != nil {
		if errors.Is(err, inject.ErrCheckerNotApplicable) {
			return cert, injectcheck.Premises{}, err
		}
		return cert, injectcheck.Premises{}, fmt.Errorf("checker cannot build site targets: %w", err)
	}
	return cert, injectcheck.Premises{LowestOffset: floor, Targets: targets}, nil
}

// checkLoad validates the assembled wire stream, not the transformer's symbolic projection.
func checkLoad(original asm.Instructions, encoded []byte, cert injectcheck.Certificate, premises injectcheck.Premises) (injectcheck.Verdict, error) {
	out, err := asm.AppendInstructions(nil, bytes.NewReader(encoded), wire, "linux")
	if err != nil {
		cause := fmt.Errorf("decode load stream: %w", err)
		return injectcheck.Verdict{Kind: "load_encoding", Premises: premises, Reason: cause.Error()}, cause
	}
	verdict, err := (injectcheck.Pair{Format: injectcheck.FormatVersion, Original: injectcheck.Instructions(original),
		Transformed: injectcheck.Instructions(out), Certificate: cert, Premises: premises}).Validate()
	if err != nil {
		return verdict, fmt.Errorf("checker rejected [%s]: %w", verdict.Kind, err)
	}
	return verdict, nil
}
