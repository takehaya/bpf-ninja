// Package Soundness
// Dafny module Soundness compiled into Go

package Soundness

import (
	os "os"

	m__System "github.com/dafny-lang/DafnyRuntimeGo/v4/System_"
	_dafny "github.com/dafny-lang/DafnyRuntimeGo/v4/dafny"
	m_Api "github.com/takehaya/bpf-ninja/tools/regionval/dafny/gen-go/Api"
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
var _ m_Api.Dummy__

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
	return "Soundness.Default__"
}
func (_this *Default__) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Default__{}

func (_static *CompanionStruct_Default___) EnvOf(s0 m_Semantics.CState, sigma _dafny.Sequence) m_Terms.Env {
	return m_Terms.Companion_Env_.Create_Env_((s0).Dtor_regs(), (s0).Dtor_stack(), sigma)
}
func (_static *CompanionStruct_Default___) LogOf(o m_Semantics.Outcome) _dafny.Sequence {
	return ((o).Dtor_s()).Dtor_log()
}
func (_static *CompanionStruct_Default___) HelperStacksWF(evs _dafny.Sequence) bool {
	return _dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((evs).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_forall_var_0).(_dafny.Int)
		return !((((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32((evs).Cardinality())) < 0)) && (((evs).Select((_0_i).Uint32()).(m_Semantics.Event)).Is_EHelper())) || ((_dafny.IntOfUint32((((evs).Select((_0_i).Uint32()).(m_Semantics.Event)).Dtor_stackAfter()).Cardinality())).Cmp(m_Semantics.Companion_Default___.STACK()) == 0)
	})
}
func (_static *CompanionStruct_Default___) Sim(sp m_Obligations.Spec, ss m_Checker.SState, cs m_Semantics.CState, s0 m_Semantics.CState, sigma _dafny.Sequence) bool {
	return ((((((((((((((((((m_Checker.Companion_Default___.SWF(ss)) && (m_Semantics.Companion_Default___.CWF(cs))) && (m_Semantics.Companion_Default___.CWF(s0))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, m_Semantics.Companion_Default___.NREGS()), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_k _dafny.Int
		_0_k = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_0_k).Sign() != -1) && ((_0_k).Cmp(m_Semantics.Companion_Default___.NREGS()) < 0)) || ((m_Terms.Companion_Default___.Eval(((ss).Dtor_regs()).Select((_0_k).Uint32()).(m_Terms.Term), Companion_Default___.EnvOf(s0, sigma))) == (((cs).Dtor_regs()).Select((_0_k).Uint32()).(uint64)))
	}))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, m_Semantics.Companion_Default___.STACK()), true, func(_forall_var_1 _dafny.Int) bool {
		var _1_i _dafny.Int
		_1_i = interface{}(_forall_var_1).(_dafny.Int)
		return !(((_1_i).Sign() != -1) && ((_1_i).Cmp(m_Semantics.Companion_Default___.STACK()) < 0)) || ((m_Terms.Companion_Default___.EvalB(((ss).Dtor_stack()).Select((_1_i).Uint32()).(m_Terms.BTerm), Companion_Default___.EnvOf(s0, sigma))) == (((cs).Dtor_stack()).Select((_1_i).Uint32()).(uint8)))
	}))) && (Companion_Default___.HelperStacksWF((cs).Dtor_events()))) && ((_dafny.IntOfUint32((m_Obligations.Companion_Default___.UpperBase((cs).Dtor_events(), (s0).Dtor_stack())).Cardinality())).Cmp(m_Semantics.Companion_Default___.STACK()) == 0)) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, m_Semantics.Companion_Default___.STACK()), true, func(_forall_var_2 _dafny.Int) bool {
		var _2_i _dafny.Int
		_2_i = interface{}(_forall_var_2).(_dafny.Int)
		return !(((_2_i).Sign() != -1) && ((_2_i).Cmp(m_Semantics.Companion_Default___.STACK()) < 0)) || ((m_Terms.Companion_Default___.EvalB(((ss).Dtor_snap()).Select((_2_i).Uint32()).(m_Terms.BTerm), Companion_Default___.EnvOf(s0, sigma))) == ((m_Obligations.Companion_Default___.UpperBase((cs).Dtor_events(), (s0).Dtor_stack())).Select((_2_i).Uint32()).(uint8)))
	}))) && (((ss).Dtor_next()).Cmp(_dafny.IntOfUint32(((cs).Dtor_log()).Cardinality())) == 0)) && (_dafny.Companion_Sequence_.IsPrefixOf((cs).Dtor_log(), sigma))) && (((ss).Dtor_helpers()).Cmp(m_Obligations.Companion_Default___.CountHelpers((cs).Dtor_events())) == 0)) && (((ss).Dtor_hooks()).Cmp(m_Obligations.Companion_Default___.CountHooks((cs).Dtor_events())) == 0)) && (((ss).Dtor_helpers()).Cmp(_dafny.One) <= 0)) && (((ss).Dtor_hooks()).Cmp(_dafny.One) <= 0)) && ((m_Terms.Companion_Default___.Eval((ss).Dtor_ret(), Companion_Default___.EnvOf(s0, sigma))) == (m_Obligations.Companion_Default___.HelperRet((cs).Dtor_events())))) && ((m_Terms.Companion_Default___.Eval((ss).Dtor_hkey(), Companion_Default___.EnvOf(s0, sigma))) == (m_Obligations.Companion_Default___.HelperKey((cs).Dtor_events())))) && (m_Obligations.Companion_Default___.AllBound(sp, (cs).Dtor_events()))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32(((cs).Dtor_events()).Cardinality())), true, func(_forall_var_3 _dafny.Int) bool {
		var _3_i _dafny.Int
		_3_i = interface{}(_forall_var_3).(_dafny.Int)
		return !(((_3_i).Sign() != -1) && ((_3_i).Cmp(_dafny.IntOfUint32(((cs).Dtor_events()).Cardinality())) < 0)) || (m_Obligations.Companion_Default___.EventOk(sp, s0, ((cs).Dtor_events()).Select((_3_i).Uint32()).(m_Semantics.Event)))
	}))) && ((((cs).Dtor_regs()).Select(10).(uint64)) == (((s0).Dtor_regs()).Select(10).(uint64)))
}
func (_static *CompanionStruct_Default___) Decoded(raw _dafny.Sequence, prog _dafny.Sequence) bool {
	return ((((_dafny.IntOfUint32((raw).Cardinality())).Modulo(_dafny.IntOfInt64(8))).Sign() == 0) && ((_dafny.IntOfUint32((prog).Cardinality())).Cmp(m_Semantics.Companion_Default___.NumInsns(raw)) == 0)) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((prog).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_j _dafny.Int
		_0_j = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_0_j).Sign() != -1) && ((_0_j).Cmp(_dafny.IntOfUint32((prog).Cardinality())) < 0)) || ((m_Semantics.Companion_Default___.Decode(m_Semantics.Companion_Default___.InsnAt(raw, _0_j))).Equals(m_Bits.Companion_Option_.Create_Some_((prog).Select((_0_j).Uint32()).(m_Semantics.Instr))))
	}))
}
func (_static *CompanionStruct_Default___) ModeOf(ph Phase) m_Checker.Mode {
	var _source0 Phase = ph
	_ = _source0
	{
		if _source0.Is_PTop() {
			return m_Checker.Companion_Mode_.Create_Top_()
		}
	}
	{
		if _source0.Is_PWP() {
			var _0_wprog _dafny.Sequence = _source0.Get_().(Phase_PWP).Wprog
			_ = _0_wprog
			return m_Checker.Companion_Mode_.Create_WP_(_0_wprog)
		}
	}
	{
		var _1_caller _dafny.Sequence = _source0.Get_().(Phase_PW).Caller
		_ = _1_caller
		return m_Checker.Companion_Mode_.Create_WBody_(_1_caller)
	}
}
func (_static *CompanionStruct_Default___) CodeOf(raw _dafny.Sequence, ph Phase) _dafny.Sequence {
	var _source0 Phase = ph
	_ = _source0
	{
		if _source0.Is_PTop() {
			return raw
		}
	}
	{
		if _source0.Is_PWP() {
			if (m_Semantics.Companion_Default___.NumInsns(raw)).Cmp(_dafny.One) >= 0 {
				return m_Semantics.Companion_Default___.WPart(raw)
			} else {
				return raw
			}
		}
	}
	{
		var _0_wraw _dafny.Sequence = _source0.Get_().(Phase_PW).Wraw
		_ = _0_wraw
		return _0_wraw
	}
}
func (_static *CompanionStruct_Default___) Post(raw _dafny.Sequence, sp m_Obligations.Spec, ph Phase, oracle _dafny.Sequence, o m_Semantics.Outcome) m_Semantics.Outcome {
	var _source0 Phase = ph
	_ = _source0
	{
		if _source0.Is_PTop() {
			return o
		}
	}
	{
		if _source0.Is_PWP() {
			var _0_wraw _dafny.Sequence = _source0.Get_().(Phase_PWP).Wraw
			_ = _0_wraw
			var _1_F _dafny.Int = _source0.Get_().(Phase_PWP).F
			_ = _1_F
			if (m_Semantics.Companion_Default___.NumInsns(raw)).Cmp(_dafny.One) >= 0 {
				return m_Semantics.Companion_Default___.WPPost(raw, _0_wraw, (sp).Dtor_floor(), oracle, _1_F, o)
			} else {
				return o
			}
		}
	}
	{
		var _2_s1 m_Semantics.CState = _source0.Get_().(Phase_PW).S1
		_ = _2_s1
		return m_Semantics.Companion_Default___.WPost(_2_s1, oracle, o)
	}
}
func (_static *CompanionStruct_Default___) Out(raw _dafny.Sequence, sp m_Obligations.Spec, ph Phase, cs m_Semantics.CState, oracle _dafny.Sequence, fuel _dafny.Int) m_Semantics.Outcome {
	return Companion_Default___.Post(raw, sp, ph, oracle, m_Semantics.Companion_Default___.Run(Companion_Default___.CodeOf(raw, ph), (sp).Dtor_floor(), cs, oracle, fuel))
}
func (_static *CompanionStruct_Default___) Rank(ph Phase) _dafny.Int {
	if (ph).Is_PWP() {
		return _dafny.One
	} else {
		return _dafny.Zero
	}
}
func (_static *CompanionStruct_Default___) PhaseOk(raw _dafny.Sequence, sp m_Obligations.Spec, ph Phase, s0 m_Semantics.CState, sigma _dafny.Sequence) bool {
	var _source0 Phase = ph
	_ = _source0
	{
		if _source0.Is_PTop() {
			return ((sp).Dtor_wrap()).Is_NoWrap()
		}
	}
	{
		if _source0.Is_PWP() {
			var _0_wraw _dafny.Sequence = _source0.Get_().(Phase_PWP).Wraw
			_ = _0_wraw
			var _1_wprog _dafny.Sequence = _source0.Get_().(Phase_PWP).Wprog
			_ = _1_wprog
			var _2_F _dafny.Int = _source0.Get_().(Phase_PWP).F
			_ = _2_F
			return ((((((sp).Dtor_wrap()).Is_Wrap()) && (_dafny.Companion_Sequence_.Equal(((sp).Dtor_wrap()).Dtor_body(), _0_wraw))) && (m_Obligations.Companion_Default___.WrapStatic(raw, sp))) && (Companion_Default___.Decoded(_0_wraw, _1_wprog))) && ((_2_F).Cmp(_dafny.IntOfUint32((_1_wprog).Cardinality())) > 0)
		}
	}
	{
		var _3_s1 m_Semantics.CState = _source0.Get_().(Phase_PW).S1
		_ = _3_s1
		var _4_caller _dafny.Sequence = _source0.Get_().(Phase_PW).Caller
		_ = _4_caller
		return (((((((((sp).Dtor_wrap()).Is_Wrap()) && (m_Obligations.Companion_Default___.WrapStatic(raw, sp))) && (m_Semantics.Companion_Default___.CWF(_3_s1))) && (m_Semantics.Companion_Default___.CWF(s0))) && ((_dafny.IntOfUint32((_4_caller).Cardinality())).Cmp(m_Semantics.Companion_Default___.NREGS()) == 0)) && (((_3_s1).Dtor_pc()).Cmp((m_Semantics.Companion_Default___.NumInsns(raw)).Minus(_dafny.One)) == 0)) && ((((_3_s1).Dtor_regs()).Select(10).(uint64)) == (((s0).Dtor_regs()).Select(10).(uint64)))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, m_Semantics.Companion_Default___.NREGS()), true, func(_forall_var_0 _dafny.Int) bool {
			var _5_k _dafny.Int
			_5_k = interface{}(_forall_var_0).(_dafny.Int)
			return !(((_5_k).Sign() != -1) && ((_5_k).Cmp(m_Semantics.Companion_Default___.NREGS()) < 0)) || ((m_Terms.Companion_Default___.Eval((_4_caller).Select((_5_k).Uint32()).(m_Terms.Term), Companion_Default___.EnvOf(s0, sigma))) == (((_3_s1).Dtor_regs()).Select((_5_k).Uint32()).(uint64)))
		}))
	}
}
func (_static *CompanionStruct_Default___) ExecPre(raw _dafny.Sequence, ph Phase, prog _dafny.Sequence, sp m_Obligations.Spec, pc _dafny.Int, ss m_Checker.SState, cs m_Semantics.CState, s0 m_Semantics.CState, oracle _dafny.Sequence, fuel _dafny.Int) bool {
	return ((((((((((m_Obligations.Companion_Default___.SpecWF(sp)) && (Companion_Default___.Decoded(Companion_Default___.CodeOf(raw, ph), prog))) && ((pc).Cmp(_dafny.IntOfUint32((prog).Cardinality())) <= 0)) && (m_Checker.Companion_Default___.SWF(ss))) && ((m_Checker.Companion_Default___.SymExec(prog, sp, pc, ss, Companion_Default___.ModeOf(ph))).Equals(m_Checker.Companion_Verdict_.Create_Validated_()))) && (m_Semantics.Companion_Default___.CWF(cs))) && (m_Semantics.Companion_Default___.CWF(s0))) && (((cs).Dtor_pc()).Cmp(pc) == 0)) && ((fuel).Cmp((_dafny.IntOfUint32((prog).Cardinality())).Minus(pc)) > 0)) && (Companion_Default___.PhaseOk(raw, sp, ph, s0, Companion_Default___.LogOf(Companion_Default___.Out(raw, sp, ph, cs, oracle, fuel))))) && (Companion_Default___.Sim(sp, ss, cs, s0, Companion_Default___.LogOf(Companion_Default___.Out(raw, sp, ph, cs, oracle, fuel))))
}

// End of class Default__

// Definition of datatype Phase
type Phase struct {
	Data_Phase_
}

func (_this Phase) Get_() Data_Phase_ {
	return _this.Data_Phase_
}

type Data_Phase_ interface {
	isPhase()
}

type CompanionStruct_Phase_ struct {
}

var Companion_Phase_ = CompanionStruct_Phase_{}

type Phase_PTop struct {
}

func (Phase_PTop) isPhase() {}

func (CompanionStruct_Phase_) Create_PTop_() Phase {
	return Phase{Phase_PTop{}}
}

func (_this Phase) Is_PTop() bool {
	_, ok := _this.Get_().(Phase_PTop)
	return ok
}

type Phase_PWP struct {
	Wraw  _dafny.Sequence
	Wprog _dafny.Sequence
	F     _dafny.Int
}

func (Phase_PWP) isPhase() {}

func (CompanionStruct_Phase_) Create_PWP_(Wraw _dafny.Sequence, Wprog _dafny.Sequence, F _dafny.Int) Phase {
	return Phase{Phase_PWP{Wraw, Wprog, F}}
}

func (_this Phase) Is_PWP() bool {
	_, ok := _this.Get_().(Phase_PWP)
	return ok
}

type Phase_PW struct {
	Wraw   _dafny.Sequence
	S1     m_Semantics.CState
	Caller _dafny.Sequence
}

func (Phase_PW) isPhase() {}

func (CompanionStruct_Phase_) Create_PW_(Wraw _dafny.Sequence, S1 m_Semantics.CState, Caller _dafny.Sequence) Phase {
	return Phase{Phase_PW{Wraw, S1, Caller}}
}

func (_this Phase) Is_PW() bool {
	_, ok := _this.Get_().(Phase_PW)
	return ok
}

func (CompanionStruct_Phase_) Default() Phase {
	return Companion_Phase_.Create_PTop_()
}

func (_this Phase) Dtor_wraw() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case Phase_PWP:
		return data.Wraw
	default:
		return data.(Phase_PW).Wraw
	}
}

func (_this Phase) Dtor_wprog() _dafny.Sequence {
	return _this.Get_().(Phase_PWP).Wprog
}

func (_this Phase) Dtor_F() _dafny.Int {
	return _this.Get_().(Phase_PWP).F
}

func (_this Phase) Dtor_s1() m_Semantics.CState {
	return _this.Get_().(Phase_PW).S1
}

func (_this Phase) Dtor_caller() _dafny.Sequence {
	return _this.Get_().(Phase_PW).Caller
}

func (_this Phase) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Phase_PTop:
		{
			return "Soundness.Phase.PTop"
		}
	case Phase_PWP:
		{
			return "Soundness.Phase.PWP" + "(" + _dafny.String(data.Wraw) + ", " + _dafny.String(data.Wprog) + ", " + _dafny.String(data.F) + ")"
		}
	case Phase_PW:
		{
			return "Soundness.Phase.PW" + "(" + _dafny.String(data.Wraw) + ", " + _dafny.String(data.S1) + ", " + _dafny.String(data.Caller) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Phase) Equals(other Phase) bool {
	switch data1 := _this.Get_().(type) {
	case Phase_PTop:
		{
			_, ok := other.Get_().(Phase_PTop)
			return ok
		}
	case Phase_PWP:
		{
			data2, ok := other.Get_().(Phase_PWP)
			return ok && data1.Wraw.Equals(data2.Wraw) && data1.Wprog.Equals(data2.Wprog) && data1.F.Cmp(data2.F) == 0
		}
	case Phase_PW:
		{
			data2, ok := other.Get_().(Phase_PW)
			return ok && data1.Wraw.Equals(data2.Wraw) && data1.S1.Equals(data2.S1) && data1.Caller.Equals(data2.Caller)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Phase) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Phase)
	return ok && _this.Equals(typed)
}

func Type_Phase_() _dafny.TypeDescriptor {
	return type_Phase_{}
}

type type_Phase_ struct {
}

func (_this type_Phase_) Default() interface{} {
	return Companion_Phase_.Default()
}

func (_this type_Phase_) String() string {
	return "Soundness.Phase"
}
func (_this Phase) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Phase{}

// End of datatype Phase
