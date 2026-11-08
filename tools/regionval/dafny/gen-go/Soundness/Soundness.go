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
	return ((((((((((((((((m_Checker.Companion_Default___.SWF(ss)) && (m_Semantics.Companion_Default___.CWF(cs))) && (m_Semantics.Companion_Default___.CWF(s0))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, m_Semantics.Companion_Default___.NREGS()), true, func(_forall_var_0 _dafny.Int) bool {
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
	}))) && (((ss).Dtor_next()).Cmp(_dafny.IntOfUint32(((cs).Dtor_log()).Cardinality())) == 0)) && (_dafny.Companion_Sequence_.IsPrefixOf((cs).Dtor_log(), sigma))) && (((ss).Dtor_helpers()).Cmp(m_Obligations.Companion_Default___.CountHelpers((cs).Dtor_events())) == 0)) && (((ss).Dtor_hooks()).Cmp(m_Obligations.Companion_Default___.CountHooks((cs).Dtor_events())) == 0)) && (((ss).Dtor_helpers()).Cmp(_dafny.One) <= 0)) && (((ss).Dtor_hooks()).Cmp(_dafny.One) <= 0)) && ((m_Terms.Companion_Default___.Eval((ss).Dtor_ret(), Companion_Default___.EnvOf(s0, sigma))) == (m_Obligations.Companion_Default___.HelperRet((cs).Dtor_events())))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32(((cs).Dtor_events()).Cardinality())), true, func(_forall_var_3 _dafny.Int) bool {
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

// End of class Default__
