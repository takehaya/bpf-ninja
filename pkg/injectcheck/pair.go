package injectcheck

import (
	"encoding/json"
	"errors"

	"github.com/cilium/ebpf/asm"
)

// FormatVersion pins the decoded cilium/ebpf v0.22 instruction representation.
const FormatVersion = 1

// Pair is the shared, versioned input for the offline checker and its CLI.
// Request, Result and Reason carry optional census evidence and are not premises.
type Pair struct {
	Format      int             `json:"format"`
	Original    Instructions    `json:"original"`
	Transformed Instructions    `json:"transformed"`
	Certificate Certificate     `json:"certificate"`
	Premises    Premises        `json:"premises"`
	Request     json.RawMessage `json:"request,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
	Reason      string          `json:"reason,omitempty"`
}

func (p *Pair) UnmarshalJSON(data []byte) error {
	type wire Pair
	var next wire
	if err := strictJSON(data, &next); err != nil {
		return err
	}
	if err := requiredFields(data, "original", "transformed", "certificate", "premises", "format"); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return inputError(InputJSON, "%v", err)
	}
	if err := requiredFields(fields["certificate"], "original"); err != nil {
		return inputError(InputMissing, "certificate: %v", err)
	}
	if err := requiredFields(fields["premises"], "lowest_offset"); err != nil {
		return inputError(InputMissing, "premises: %v", err)
	}
	if next.Format != FormatVersion {
		return inputError(InputVersion, "format must be %d, got %d", FormatVersion, next.Format)
	}
	*p = Pair(next)
	return nil
}

// Verdict binds a decision to its trusted premise and the number of checked sites.
type Verdict struct {
	Accepted bool     `json:"accepted"`
	Kind     Kind     `json:"kind"`
	Counts   Counts   `json:"counts"`
	Premises Premises `json:"premises"`
	Reason   string   `json:"reason"`
}

// Validate runs the API check on the same projection decoded by the CLI.
func (p Pair) Validate() (Verdict, error) {
	v := Verdict{Premises: p.Premises}
	if p.Format != FormatVersion {
		err := inputError(InputVersion, "format must be %d, got %d", FormatVersion, p.Format)
		v.Kind = InputVersion
		v.Reason = err.Error()
		return v, err
	}
	counts, err := Check(asm.Instructions(p.Original), asm.Instructions(p.Transformed), p.Certificate, p.Premises)
	v.Counts = counts
	v.Accepted = err == nil
	if err != nil {
		v.Reason = err.Error()
		var rejection *Rejection
		var input *InputError
		if errors.As(err, &rejection) {
			v.Kind = rejection.Kind
		}
		if errors.As(err, &input) {
			v.Kind = input.Kind
		}
	}
	return v, err
}
