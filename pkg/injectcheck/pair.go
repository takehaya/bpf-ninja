package injectcheck

import (
	"encoding/json"
	"errors"
	"slices"

	"github.com/cilium/ebpf/asm"
)

// FormatVersion adds passed context sources. Readers continue to accept v2
// through v6 pairs.
const FormatVersion = 7

func supportedFormat(format int) bool { return format >= 2 && format <= FormatVersion }

func wrapperPremise(c Certificate, targets []SiteTarget) bool {
	return len(c.Wrappers) != 0 || slices.ContainsFunc(targets, func(t SiteTarget) bool { return len(t.Args) != 0 || t.SitePC != 0 })
}

func callbackPremise(targets []SiteTarget) bool {
	return slices.ContainsFunc(targets, func(t SiteTarget) bool { return t.Ctx != nil && t.Ctx.Param != 0 })
}

func hasPassPremise(targets []SiteTarget) bool {
	return slices.ContainsFunc(targets, func(t SiteTarget) bool { return t.Ctx != nil && len(t.Ctx.Pass) != 0 })
}

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
	if !supportedFormat(next.Format) {
		return inputError(InputVersion, "format must be 2 through %d, got %d", FormatVersion, next.Format)
	}
	if next.Format < 3 {
		for _, target := range next.Premises.Targets {
			if target.Ctx != nil {
				return inputError(InputVersion, "format 2 does not support target context provenance")
			}
		}
	}
	if next.Format < 5 && callbackPremise(next.Premises.Targets) {
		return inputError(InputVersion, "format %d does not support callback context sources", next.Format)
	}
	if next.Format < 7 && hasPassPremise(next.Premises.Targets) {
		return inputError(InputVersion, "format %d does not support passed context sources", next.Format)
	}
	if next.Format < 4 && len(next.Premises.Frames) != 0 {
		return inputError(InputVersion, "format %d does not support per-frame stack floors", next.Format)
	}
	if next.Format < 6 && wrapperPremise(next.Certificate, next.Premises.Targets) {
		return inputError(InputVersion, "format %d does not support wrappers or planned lookup arguments", next.Format)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return inputError(InputJSON, "%v", err)
	}
	if err := requiredFields(fields["certificate"], "original"); err != nil {
		return inputError(InputMissing, "certificate: %v", err)
	}
	if err := requiredFields(fields["premises"], "lowest_offset", "targets"); err != nil {
		return inputError(InputMissing, "premises: %v", err)
	}
	var premiseFields map[string]json.RawMessage
	if err := json.Unmarshal(fields["premises"], &premiseFields); err != nil {
		return inputError(InputJSON, "premises: %v", err)
	}
	if rawFrames, ok := premiseFields["frames"]; ok && string(rawFrames) != "null" {
		var frames []json.RawMessage
		if err := json.Unmarshal(rawFrames, &frames); err != nil {
			return inputError(InputJSON, "premises.frames: %v", err)
		}
		for i, frame := range frames {
			if err := requiredFields(frame, "start", "lowest_offset"); err != nil {
				return inputError(InputMissing, "premises.frames[%d]: %v", i, err)
			}
		}
	}
	*p = Pair(next)
	return nil
}

// MarshalJSON keeps an empty trusted target plan representable as an array.
func (p Premises) MarshalJSON() ([]byte, error) {
	type wire Premises
	if p.Targets == nil {
		p.Targets = []SiteTarget{}
	}
	return json.Marshal(wire(p))
}

// Verdict binds a decision to its trusted stack audit and plan-derived targets.
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
	if !supportedFormat(p.Format) {
		err := inputError(InputVersion, "format must be 2 through %d, got %d", FormatVersion, p.Format)
		v.Kind = InputVersion
		v.Reason = err.Error()
		return v, err
	}
	if p.Format < 3 {
		for _, target := range p.Premises.Targets {
			if target.Ctx != nil {
				err := inputError(InputVersion, "format 2 does not support target context provenance")
				v.Kind, v.Reason = InputVersion, err.Error()
				return v, err
			}
		}
	}
	if p.Format < 5 && callbackPremise(p.Premises.Targets) {
		err := inputError(InputVersion, "format %d does not support callback context sources", p.Format)
		v.Kind, v.Reason = InputVersion, err.Error()
		return v, err
	}
	if p.Format < 4 && len(p.Premises.Frames) != 0 {
		err := inputError(InputVersion, "format %d does not support per-frame stack floors", p.Format)
		v.Kind, v.Reason = InputVersion, err.Error()
		return v, err
	}
	if p.Format < 6 && wrapperPremise(p.Certificate, p.Premises.Targets) {
		err := inputError(InputVersion, "format %d does not support wrappers or planned lookup arguments", p.Format)
		v.Kind, v.Reason = InputVersion, err.Error()
		return v, err
	}
	if p.Format < 7 && hasPassPremise(p.Premises.Targets) {
		err := inputError(InputVersion, "format %d does not support passed context sources", p.Format)
		v.Kind, v.Reason = InputVersion, err.Error()
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
