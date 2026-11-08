// Package Api
// Dafny module Api compiled into Go

package Api

import (
	os "os"

	m__System "github.com/dafny-lang/DafnyRuntimeGo/v4/System_"
	_dafny "github.com/dafny-lang/DafnyRuntimeGo/v4/dafny"
	m_Bits "github.com/takehaya/bpf-ninja/tools/regionval/dafny/gen-go/Bits"
	m_Checker "github.com/takehaya/bpf-ninja/tools/regionval/dafny/gen-go/Checker"
	m_Obligations "github.com/takehaya/bpf-ninja/tools/regionval/dafny/gen-go/Obligations"
	m_Semantics "github.com/takehaya/bpf-ninja/tools/regionval/dafny/gen-go/Semantics"
	m_Terms "github.com/takehaya/bpf-ninja/tools/regionval/dafny/gen-go/Terms"
)

var _ = os.Args
var _ _dafny.Dummy__
var _ m__System.Dummy__
var _ m_Bits.Dummy__
var _ m_Semantics.Dummy__
var _ m_Obligations.Dummy__
var _ m_Terms.Dummy__
var _ m_Checker.Dummy__

type Dummy__ struct{}

// Definition of class Default__
type Default__ struct {
	dummy byte
}

func New_Default___() *Default__ {
	_this := Default__{}

	return &_this
}

type CompanionStruct_Default___ struct {
}

var Companion_Default___ = CompanionStruct_Default___{}

func (_this *Default__) Equals(other *Default__) bool {
	return _this == other
}

func (_this *Default__) EqualsGeneric(x interface{}) bool {
	other, ok := x.(*Default__)
	return ok && _this.Equals(other)
}

func (*Default__) String() string {
	return "_module.Default__"
}
func (_this *Default__) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Default__{}

func (_static *CompanionStruct_Default___) SiteSpec(floor _dafny.Int) m_Obligations.Spec {
	return m_Obligations.Companion_Spec_.Create_Spec_(floor, _dafny.SetOf(_dafny.One, _dafny.IntOfInt64(2), _dafny.IntOfInt64(3), _dafny.IntOfInt64(4), _dafny.IntOfInt64(5)), m_Obligations.Companion_HelperMode_.Create_Helper_(true, true), true, true, false, m_Obligations.Companion_WrapMode_.Create_NoWrap_())
}
func (_static *CompanionStruct_Default___) TailSiteSpec(floor _dafny.Int) m_Obligations.Spec {
	return m_Obligations.Companion_Spec_.Create_Spec_(floor, _dafny.SetOf(_dafny.Zero, _dafny.One, _dafny.IntOfInt64(2), _dafny.IntOfInt64(3), _dafny.IntOfInt64(4), _dafny.IntOfInt64(5)), m_Obligations.Companion_HelperMode_.Create_Helper_(false, false), true, true, false, m_Obligations.Companion_WrapMode_.Create_NoWrap_())
}
func (_static *CompanionStruct_Default___) EntryPrologueSpec(floor _dafny.Int) m_Obligations.Spec {
	return m_Obligations.Companion_Spec_.Create_Spec_(floor, _dafny.SetOf(_dafny.Zero, _dafny.IntOfInt64(2), _dafny.IntOfInt64(3), _dafny.IntOfInt64(4), _dafny.IntOfInt64(5)), m_Obligations.Companion_HelperMode_.Create_NoHelper_(), true, false, false, m_Obligations.Companion_WrapMode_.Create_NoWrap_())
}
func (_static *CompanionStruct_Default___) CallbackPrologueSpec(floor _dafny.Int) m_Obligations.Spec {
	return m_Obligations.Companion_Spec_.Create_Spec_(floor, _dafny.SetOf(_dafny.Zero), m_Obligations.Companion_HelperMode_.Create_NoHelper_(), true, false, false, m_Obligations.Companion_WrapMode_.Create_NoWrap_())
}
func (_static *CompanionStruct_Default___) PassSpec(floor _dafny.Int, g _dafny.Int) m_Obligations.Spec {
	return m_Obligations.Companion_Spec_.Create_Spec_(floor, _dafny.SetOf(g), m_Obligations.Companion_HelperMode_.Create_NoHelper_(), true, false, false, m_Obligations.Companion_WrapMode_.Create_NoWrap_())
}
func (_static *CompanionStruct_Default___) HookBodySpec() m_Obligations.Spec {
	return m_Obligations.Companion_Spec_.Create_Spec_(_dafny.Zero, _dafny.SetOf(_dafny.Zero, _dafny.One, _dafny.IntOfInt64(2), _dafny.IntOfInt64(3), _dafny.IntOfInt64(4), _dafny.IntOfInt64(5)), m_Obligations.Companion_HelperMode_.Create_NoHelper_(), false, false, true, m_Obligations.Companion_WrapMode_.Create_NoWrap_())
}
func (_static *CompanionStruct_Default___) WrapSiteSpec(floor _dafny.Int, body _dafny.Sequence, helper _dafny.Sequence) m_Obligations.Spec {
	return m_Obligations.Companion_Spec_.Create_Spec_(floor, _dafny.SetOf(_dafny.One, _dafny.IntOfInt64(2), _dafny.IntOfInt64(3), _dafny.IntOfInt64(4), _dafny.IntOfInt64(5)), m_Obligations.Companion_HelperMode_.Create_Helper_(false, true), false, true, false, m_Obligations.Companion_WrapMode_.Create_Wrap_(body, helper))
}
func (_static *CompanionStruct_Default___) Validate(raw _dafny.Sequence, sp m_Obligations.Spec) m_Checker.Verdict {
	return m_Checker.Companion_Default___.Validate(raw, sp)
}
func (_static *CompanionStruct_Default___) ConcreteStep(raw _dafny.Sequence, floor _dafny.Int, s m_Semantics.CState, oracle _dafny.Sequence) m_Semantics.StepRes {
	if (((!(m_Semantics.Companion_Default___.CWF(s))) || (!((((_dafny.Zero).Minus(m_Semantics.Companion_Default___.STACK())).Cmp(floor) <= 0) && ((floor).Sign() != 1)))) || (((s).Dtor_pc()).Sign() == -1)) || (((s).Dtor_pc()).Cmp(m_Semantics.Companion_Default___.NumInsns(raw)) >= 0) {
		return m_Semantics.Companion_StepRes_.Create_Stuck_()
	} else {
		var _source0 m_Bits.Option = m_Semantics.Companion_Default___.Decode(m_Semantics.Companion_Default___.InsnAt(raw, (s).Dtor_pc()))
		_ = _source0
		{
			if _source0.Is_None() {
				return m_Semantics.Companion_StepRes_.Create_Stuck_()
			}
		}
		{
			var _0_ins m_Semantics.Instr = _source0.Get_().(m_Bits.Option_Some).Value.(m_Semantics.Instr)
			_ = _0_ins
			return m_Semantics.Companion_Default___.Step(floor, _0_ins, s, oracle)
		}
	}
}
func (_static *CompanionStruct_Default___) ConcreteRun(raw _dafny.Sequence, floor _dafny.Int, s m_Semantics.CState, oracle _dafny.Sequence, fuel _dafny.Int) m_Semantics.Outcome {
	if (!(m_Semantics.Companion_Default___.CWF(s))) || (!((((_dafny.Zero).Minus(m_Semantics.Companion_Default___.STACK())).Cmp(floor) <= 0) && ((floor).Sign() != 1))) {
		return m_Semantics.Companion_Outcome_.Create_Escaped_(s)
	} else {
		return m_Semantics.Companion_Default___.Run(raw, floor, s, oracle, fuel)
	}
}
func (_static *CompanionStruct_Default___) ConcreteWindowRun(raw _dafny.Sequence, sp m_Obligations.Spec, s m_Semantics.CState, oracle _dafny.Sequence, fuel _dafny.Int) m_Semantics.Outcome {
	if (!(m_Semantics.Companion_Default___.CWF(s))) || (!((((_dafny.Zero).Minus(m_Semantics.Companion_Default___.STACK())).Cmp((sp).Dtor_floor()) <= 0) && (((sp).Dtor_floor()).Sign() != 1))) {
		return m_Semantics.Companion_Outcome_.Create_Escaped_(s)
	} else {
		return m_Obligations.Companion_Default___.WindowRun(raw, sp, s, oracle, fuel)
	}
}

// End of class Default__
