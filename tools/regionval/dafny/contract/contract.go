// Package contract judges one window with the Dafny core. It makes the
// checks a caller keeps outside Validate (README.md, Dafny core), maps the
// window kind to its Spec and calls the Dafny Validate. Where the Go core
// checks the instructions a path executes, these checks look at every
// instruction of the window, which is at least as strict.
package contract

import (
	"github.com/takehaya/bpf-ninja/tools/regionval/core"
	rd "github.com/takehaya/bpf-ninja/tools/regionval/dafny/regionvaldafny"
)

const tailCallID = 12 // bpf_tail_call

// Validate judges window cw with the Dafny core. insns are the wire bytes of
// the window, body those of the wrapper W and helper the 8 bytes of the
// original helper call O[i]; body and helper are used for site-P8 only. The
// bytes must decode to the instructions in cw, so the Dafny core judges the
// same window as the Go core. A window that fails the contract has PC -1 and
// a reason starting with "contract: ".
func Validate(cw core.Window, insns, body, helper []byte) rd.Verdict {
	why := Check(cw)
	if why == "" && (!same(insns, cw.Insns) || cw.Kind == core.KindWrap && (!same(body, cw.Callee) || !same(helper, []core.Insn{cw.Helper}))) {
		why = "bytes differ from the decoded window"
	}
	var sp rd.Spec
	if why == "" {
		var ok bool
		if sp, ok = Spec(cw, body, helper); !ok {
			why = "no Dafny spec for the window"
		}
	}
	if why != "" {
		return rd.Verdict{PC: -1, Reason: "contract: " + why}
	}
	return rd.Validate(insns, sp)
}

// Spec maps a window kind to its Dafny Spec (README.md, Dafny core). body
// and helper are W's wire bytes and the original helper call O[i]; they are
// used for site-P8 only. ok is false when the Dafny core has no spec for the
// window.
func Spec(cw core.Window, body, helper []byte) (rd.Spec, bool) {
	f := int(cw.Floor)
	// CustomSpec arguments: no central helper call (so no argument or r0
	// check), no hook call, not a hook body.
	const centre, checkArgs, restoreR0, hookCalls, exitMode = false, false, false, false, false
	switch cw.Kind {
	case core.KindWrap:
		if cw.Callee == nil || len(helper) != 8 {
			return rd.Spec{}, false
		}
		return rd.WrapSiteSpec(f, body, helper), true
	case core.KindSite:
		return rd.SiteSpec(f), true
	case core.KindTail:
		return rd.TailSiteSpec(f), true
	case core.KindEntry:
		return rd.EntryPrologueSpec(f), true
	case core.KindCallback:
		return rd.CallbackPrologueSpec(f), true
	case core.KindPass: // no register changes; stores allowed
		return rd.CustomSpec(f, nil, centre, checkArgs, restoreR0, true, hookCalls, exitMode), true
	case core.KindPassLoad: // only r_G changes; no store
		g := core.SpillSource(cw.PassPrologue)
		if g == 0 {
			return rd.Spec{}, false
		}
		return rd.CustomSpec(f, []int{g}, centre, checkArgs, restoreR0, false, hookCalls, exitMode), true
	case core.KindHook:
		return rd.HookBodySpec(), true
	}
	return rd.Spec{}, false
}

// Check returns why a window fails the checks a caller of the Dafny core
// makes outside Validate (README.md, Dafny core), or "" if it passes them.
func Check(cw core.Window) string {
	switch cw.Kind {
	case core.KindSite, core.KindTail, core.KindWrap, core.KindEntry, core.KindCallback, core.KindPass, core.KindPassLoad, core.KindHook:
	default:
		return "kind not supported by the Dafny core"
	}
	if cw.Kind != core.KindHook && !cw.HasFloor {
		return "no floor"
	}
	site := cw.Kind == core.KindSite || cw.Kind == core.KindTail
	wrap := cw.Kind == core.KindWrap
	for i, x := range cw.Insns {
		if x.IsPseudoCall() && !cw.Hook[i] && (!wrap || i != len(cw.Insns)-1) {
			return "pseudo call not to a hook"
		}
		if x.IsHelperCall() && (!site || i != cw.Center) {
			return "helper call not at the centre"
		}
	}
	switch cw.Kind {
	case core.KindSite, core.KindTail:
		if cw.Center < 0 || cw.Center >= len(cw.Insns) || !cw.Insns[cw.Center].IsHelperCall() {
			return "no centre"
		}
		if (cw.Kind == core.KindTail) != (cw.Insns[cw.Center].Imm == tailCallID) {
			return "centre is not this kind's helper"
		}
	case core.KindWrap:
		// The last instruction is call W, whose target the layout resolved;
		// every pseudo call inside W must be a hook call.
		if cw.Center != len(cw.Insns)-1 || cw.Callee == nil {
			return "P8 shape"
		}
		for i, x := range cw.Callee {
			if x.IsPseudoCall() && !cw.CalleeHook[i] {
				return "pseudo call in W not to a hook"
			}
		}
	case core.KindCallback:
		if writesOutside(cw.Insns, 1) {
			return "P1b: writes a register other than r0"
		}
	case core.KindPass:
		if core.SpillSource(cw.Insns) == 0 {
			return "P9 certificate"
		}
		if writesOutside(cw.Insns, 0) {
			return "P9: pass prologue writes a register"
		}
		// Branches go forward only, so the store runs on every path when
		// no branch comes before it.
		for _, x := range cw.Insns {
			if x.Class() == core.ClassSTX {
				break
			}
			if x.IsJump() {
				return "P9: a branch may skip the store"
			}
		}
	case core.KindPassLoad:
		g := core.SpillSource(cw.PassPrologue)
		if g == 0 {
			return "P9 certificate"
		}
		if cw.PassLive&(1<<uint(g)) != 0 {
			return "S10"
		}
		if writesOutside(cw.Insns, 1<<uint(g)) {
			return "P9: pass load writes a register other than r_G"
		}
	case core.KindHook:
		for _, x := range cw.Insns {
			if x.Class() == core.ClassLDX && x.Dst > 5 {
				return "P7: load into r6-r9"
			}
		}
	}
	return ""
}

// writesOutside reports whether an instruction may write a register outside
// allowed.
func writesOutside(xs []core.Insn, allowed uint16) bool {
	for _, x := range xs {
		if core.Writes(x)&^allowed != 0 {
			return true
		}
	}
	return false
}

// same reports whether raw decodes to exactly the instructions xs.
func same(raw []byte, xs []core.Insn) bool {
	ys, err := core.Decode(raw)
	if err != nil || len(ys) != len(xs) {
		return false
	}
	for i := range xs {
		if !xs[i].Same(ys[i]) {
			return false
		}
	}
	return true
}
