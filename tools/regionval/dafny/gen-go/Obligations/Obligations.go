// Package Obligations
// Dafny module Obligations compiled into Go

package Obligations

import (
	os "os"

	m__System "github.com/dafny-lang/DafnyRuntimeGo/v4/System_"
	_dafny "github.com/dafny-lang/DafnyRuntimeGo/v4/dafny"
	m_Bits "github.com/takehaya/bpf-ninja/tools/regionval/dafny/gen-go/Bits"
	m_Semantics "github.com/takehaya/bpf-ninja/tools/regionval/dafny/gen-go/Semantics"
)

var _ = os.Args
var _ _dafny.Dummy__
var _ m__System.Dummy__
var _ m_Bits.Dummy__
var _ m_Semantics.Dummy__

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
	return "Obligations.Default__"
}
func (_this *Default__) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Default__{}

func (_static *CompanionStruct_Default___) SpecWF(sp Spec) bool {
	return (((((_dafny.Zero).Minus(m_Semantics.Companion_Default___.STACK())).Cmp((sp).Dtor_floor()) <= 0) && (((sp).Dtor_floor()).Sign() != 1)) && (_dafny.Quantifier(((sp).Dtor_free()).Elements(), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_k _dafny.Int
		_0_k = interface{}(_forall_var_0).(_dafny.Int)
		return !(((sp).Dtor_free()).Contains(_0_k)) || ((_0_k).Cmp(_dafny.IntOfInt64(5)) <= 0)
	}))) && (!((sp).Dtor_exitMode()) || (((sp).Dtor_helper()).Is_NoHelper()))
}
func (_static *CompanionStruct_Default___) R0Special(sp Spec) bool {
	return ((sp).Dtor_exitMode()) || ((((sp).Dtor_helper()).Is_Helper()) && (((sp).Dtor_helper()).Dtor_restoreR0()))
}
func (_static *CompanionStruct_Default___) EventOk(sp Spec, s0 m_Semantics.CState, e m_Semantics.Event) bool {
	var _source0 m_Semantics.Event = e
	_ = _source0
	{
		if _source0.Is_EStore() {
			var _0_a uint64 = _source0.Get_().(m_Semantics.Event_EStore).Addr
			_ = _0_a
			var _1_w _dafny.Int = _source0.Get_().(m_Semantics.Event_EStore).Width
			_ = _1_w
			return (((sp).Dtor_allowStore()) && (((_dafny.Zero).Minus(m_Semantics.Companion_Default___.STACK())).Cmp(m_Semantics.Companion_Default___.Rel(_0_a, ((s0).Dtor_regs()).Select(10).(uint64))) <= 0)) && (((m_Semantics.Companion_Default___.Rel(_0_a, ((s0).Dtor_regs()).Select(10).(uint64))).Plus(_1_w)).Cmp((sp).Dtor_floor()) <= 0)
		}
	}
	{
		if _source0.Is_EHelper() {
			var _2_args _dafny.Sequence = _source0.Get_().(m_Semantics.Event_EHelper).Args
			_ = _2_args
			return (((sp).Dtor_helper()).Is_Helper()) && (!(((sp).Dtor_helper()).Dtor_checkArgs()) || (_dafny.Companion_Sequence_.Equal(_2_args, ((s0).Dtor_regs()).Subsequence(1, 6))))
		}
	}
	{
		return (sp).Dtor_hookCalls()
	}
}
func (_static *CompanionStruct_Default___) CountHelpers(evs _dafny.Sequence) _dafny.Int {
	var _0___accumulator _dafny.Int = _dafny.Zero
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((evs).Cardinality())).Sign() == 0 {
		return (_dafny.Zero).Plus(_0___accumulator)
	} else {
		_0___accumulator = ((func() _dafny.Int {
			if ((evs).Select(((_dafny.IntOfUint32((evs).Cardinality())).Minus(_dafny.One)).Uint32()).(m_Semantics.Event)).Is_EHelper() {
				return _dafny.One
			}
			return _dafny.Zero
		})()).Plus(_0___accumulator)
		var _in0 _dafny.Sequence = (evs).Take(((_dafny.IntOfUint32((evs).Cardinality())).Minus(_dafny.One)).Uint32())
		_ = _in0
		evs = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) CountHooks(evs _dafny.Sequence) _dafny.Int {
	var _0___accumulator _dafny.Int = _dafny.Zero
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((evs).Cardinality())).Sign() == 0 {
		return (_dafny.Zero).Plus(_0___accumulator)
	} else {
		_0___accumulator = ((func() _dafny.Int {
			if ((evs).Select(((_dafny.IntOfUint32((evs).Cardinality())).Minus(_dafny.One)).Uint32()).(m_Semantics.Event)).Is_EHook() {
				return _dafny.One
			}
			return _dafny.Zero
		})()).Plus(_0___accumulator)
		var _in0 _dafny.Sequence = (evs).Take(((_dafny.IntOfUint32((evs).Cardinality())).Minus(_dafny.One)).Uint32())
		_ = _in0
		evs = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) HelperRet(evs _dafny.Sequence) uint64 {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((evs).Cardinality())).Sign() == 0 {
		return uint64(0)
	} else if ((evs).Select(((_dafny.IntOfUint32((evs).Cardinality())).Minus(_dafny.One)).Uint32()).(m_Semantics.Event)).Is_EHelper() {
		return ((evs).Select(((_dafny.IntOfUint32((evs).Cardinality())).Minus(_dafny.One)).Uint32()).(m_Semantics.Event)).Dtor_ret()
	} else {
		var _in0 _dafny.Sequence = (evs).Take(((_dafny.IntOfUint32((evs).Cardinality())).Minus(_dafny.One)).Uint32())
		_ = _in0
		evs = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) UpperBase(evs _dafny.Sequence, entry _dafny.Sequence) _dafny.Sequence {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((evs).Cardinality())).Sign() == 0 {
		return entry
	} else if ((evs).Select(((_dafny.IntOfUint32((evs).Cardinality())).Minus(_dafny.One)).Uint32()).(m_Semantics.Event)).Is_EHelper() {
		return ((evs).Select(((_dafny.IntOfUint32((evs).Cardinality())).Minus(_dafny.One)).Uint32()).(m_Semantics.Event)).Dtor_stackAfter()
	} else {
		var _in0 _dafny.Sequence = (evs).Take(((_dafny.IntOfUint32((evs).Cardinality())).Minus(_dafny.One)).Uint32())
		_ = _in0
		var _in1 _dafny.Sequence = entry
		_ = _in1
		evs = _in0
		entry = _in1
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) FinalOk(sp Spec, s0 m_Semantics.CState, s m_Semantics.CState) bool {
	return (((((((((m_Semantics.Companion_Default___.CWF(s)) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32(((s).Dtor_events()).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32(((s).Dtor_events()).Cardinality())) < 0)) || (Companion_Default___.EventOk(sp, s0, ((s).Dtor_events()).Select((_0_i).Uint32()).(m_Semantics.Event)))
	}))) && ((Companion_Default___.CountHelpers((s).Dtor_events())).Cmp((func() _dafny.Int {
		if ((sp).Dtor_helper()).Is_Helper() {
			return _dafny.One
		}
		return _dafny.Zero
	})()) == 0)) && ((Companion_Default___.CountHooks((s).Dtor_events())).Cmp(_dafny.One) <= 0)) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.IntOfInt64(6), (_dafny.IntOfInt64(10)).Plus(_dafny.One)), true, func(_forall_var_1 _dafny.Int) bool {
		var _1_k _dafny.Int
		_1_k = interface{}(_forall_var_1).(_dafny.Int)
		return !(((_dafny.IntOfInt64(6)).Cmp(_1_k) <= 0) && ((_1_k).Cmp(_dafny.IntOfInt64(10)) <= 0)) || ((((s).Dtor_regs()).Select((_1_k).Uint32()).(uint64)) == (((s0).Dtor_regs()).Select((_1_k).Uint32()).(uint64)))
	}))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, (_dafny.IntOfInt64(5)).Plus(_dafny.One)), true, func(_forall_var_2 _dafny.Int) bool {
		var _2_k _dafny.Int
		_2_k = interface{}(_forall_var_2).(_dafny.Int)
		return !(((((_2_k).Sign() != -1) && ((_2_k).Cmp(_dafny.IntOfInt64(5)) <= 0)) && (!((sp).Dtor_free()).Contains(_2_k))) && (!(((_2_k).Sign() == 0) && (Companion_Default___.R0Special(sp))))) || ((((s).Dtor_regs()).Select((_2_k).Uint32()).(uint64)) == (((s0).Dtor_regs()).Select((_2_k).Uint32()).(uint64)))
	}))) && (!((((sp).Dtor_helper()).Is_Helper()) && (((sp).Dtor_helper()).Dtor_restoreR0())) || ((((s).Dtor_regs()).Select(0).(uint64)) == (Companion_Default___.HelperRet((s).Dtor_events()))))) && (!((sp).Dtor_exitMode()) || ((((s).Dtor_regs()).Select(0).(uint64)) == (uint64(0))))) && ((_dafny.IntOfUint32((Companion_Default___.UpperBase((s).Dtor_events(), (s0).Dtor_stack())).Cardinality())).Cmp(m_Semantics.Companion_Default___.STACK()) == 0)) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, m_Semantics.Companion_Default___.STACK()), true, func(_forall_var_3 _dafny.Int) bool {
		var _3_i _dafny.Int
		_3_i = interface{}(_forall_var_3).(_dafny.Int)
		return !((((_3_i).Sign() != -1) && ((_3_i).Cmp(m_Semantics.Companion_Default___.STACK()) < 0)) && (((m_Semantics.Companion_Default___.STACK()).Plus((sp).Dtor_floor())).Cmp(_3_i) <= 0)) || ((((s).Dtor_stack()).Select((_3_i).Uint32()).(uint8)) == ((Companion_Default___.UpperBase((s).Dtor_events(), (s0).Dtor_stack())).Select((_3_i).Uint32()).(uint8)))
	}))
}
func (_static *CompanionStruct_Default___) ObligationsHold(raw _dafny.Sequence, sp Spec, s0 m_Semantics.CState, out m_Semantics.Outcome) bool {
	var _source0 m_Semantics.Outcome = out
	_ = _source0
	{
		if _source0.Is_Done() {
			var _0_s m_Semantics.CState = _source0.Get_().(m_Semantics.Outcome_Done).S
			_ = _0_s
			return (!((sp).Dtor_exitMode())) && (Companion_Default___.FinalOk(sp, s0, _0_s))
		}
	}
	{
		if _source0.Is_Exited() {
			var _1_s m_Semantics.CState = _source0.Get_().(m_Semantics.Outcome_Exited).S
			_ = _1_s
			return ((sp).Dtor_exitMode()) && (Companion_Default___.FinalOk(sp, s0, _1_s))
		}
	}
	{
		if _source0.Is_Escaped() {
			return false
		}
	}
	{
		return false
	}
}

// End of class Default__

// Definition of datatype HelperMode
type HelperMode struct {
	Data_HelperMode_
}

func (_this HelperMode) Get_() Data_HelperMode_ {
	return _this.Data_HelperMode_
}

type Data_HelperMode_ interface {
	isHelperMode()
}

type CompanionStruct_HelperMode_ struct {
}

var Companion_HelperMode_ = CompanionStruct_HelperMode_{}

type HelperMode_NoHelper struct {
}

func (HelperMode_NoHelper) isHelperMode() {}

func (CompanionStruct_HelperMode_) Create_NoHelper_() HelperMode {
	return HelperMode{HelperMode_NoHelper{}}
}

func (_this HelperMode) Is_NoHelper() bool {
	_, ok := _this.Get_().(HelperMode_NoHelper)
	return ok
}

type HelperMode_Helper struct {
	CheckArgs bool
	RestoreR0 bool
}

func (HelperMode_Helper) isHelperMode() {}

func (CompanionStruct_HelperMode_) Create_Helper_(CheckArgs bool, RestoreR0 bool) HelperMode {
	return HelperMode{HelperMode_Helper{CheckArgs, RestoreR0}}
}

func (_this HelperMode) Is_Helper() bool {
	_, ok := _this.Get_().(HelperMode_Helper)
	return ok
}

func (CompanionStruct_HelperMode_) Default() HelperMode {
	return Companion_HelperMode_.Create_NoHelper_()
}

func (_this HelperMode) Dtor_checkArgs() bool {
	return _this.Get_().(HelperMode_Helper).CheckArgs
}

func (_this HelperMode) Dtor_restoreR0() bool {
	return _this.Get_().(HelperMode_Helper).RestoreR0
}

func (_this HelperMode) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case HelperMode_NoHelper:
		{
			return "Obligations.HelperMode.NoHelper"
		}
	case HelperMode_Helper:
		{
			return "Obligations.HelperMode.Helper" + "(" + _dafny.String(data.CheckArgs) + ", " + _dafny.String(data.RestoreR0) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this HelperMode) Equals(other HelperMode) bool {
	switch data1 := _this.Get_().(type) {
	case HelperMode_NoHelper:
		{
			_, ok := other.Get_().(HelperMode_NoHelper)
			return ok
		}
	case HelperMode_Helper:
		{
			data2, ok := other.Get_().(HelperMode_Helper)
			return ok && data1.CheckArgs == data2.CheckArgs && data1.RestoreR0 == data2.RestoreR0
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this HelperMode) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(HelperMode)
	return ok && _this.Equals(typed)
}

func Type_HelperMode_() _dafny.TypeDescriptor {
	return type_HelperMode_{}
}

type type_HelperMode_ struct {
}

func (_this type_HelperMode_) Default() interface{} {
	return Companion_HelperMode_.Default()
}

func (_this type_HelperMode_) String() string {
	return "Obligations.HelperMode"
}
func (_this HelperMode) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = HelperMode{}

// End of datatype HelperMode

// Definition of datatype Spec
type Spec struct {
	Data_Spec_
}

func (_this Spec) Get_() Data_Spec_ {
	return _this.Data_Spec_
}

type Data_Spec_ interface {
	isSpec()
}

type CompanionStruct_Spec_ struct {
}

var Companion_Spec_ = CompanionStruct_Spec_{}

type Spec_Spec struct {
	Floor      _dafny.Int
	Free       _dafny.Set
	Helper     HelperMode
	AllowStore bool
	HookCalls  bool
	ExitMode   bool
}

func (Spec_Spec) isSpec() {}

func (CompanionStruct_Spec_) Create_Spec_(Floor _dafny.Int, Free _dafny.Set, Helper HelperMode, AllowStore bool, HookCalls bool, ExitMode bool) Spec {
	return Spec{Spec_Spec{Floor, Free, Helper, AllowStore, HookCalls, ExitMode}}
}

func (_this Spec) Is_Spec() bool {
	_, ok := _this.Get_().(Spec_Spec)
	return ok
}

func (CompanionStruct_Spec_) Default() Spec {
	return Companion_Spec_.Create_Spec_(_dafny.Zero, _dafny.EmptySet, Companion_HelperMode_.Default(), false, false, false)
}

func (_this Spec) Dtor_floor() _dafny.Int {
	return _this.Get_().(Spec_Spec).Floor
}

func (_this Spec) Dtor_free() _dafny.Set {
	return _this.Get_().(Spec_Spec).Free
}

func (_this Spec) Dtor_helper() HelperMode {
	return _this.Get_().(Spec_Spec).Helper
}

func (_this Spec) Dtor_allowStore() bool {
	return _this.Get_().(Spec_Spec).AllowStore
}

func (_this Spec) Dtor_hookCalls() bool {
	return _this.Get_().(Spec_Spec).HookCalls
}

func (_this Spec) Dtor_exitMode() bool {
	return _this.Get_().(Spec_Spec).ExitMode
}

func (_this Spec) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Spec_Spec:
		{
			return "Obligations.Spec.Spec" + "(" + _dafny.String(data.Floor) + ", " + _dafny.String(data.Free) + ", " + _dafny.String(data.Helper) + ", " + _dafny.String(data.AllowStore) + ", " + _dafny.String(data.HookCalls) + ", " + _dafny.String(data.ExitMode) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Spec) Equals(other Spec) bool {
	switch data1 := _this.Get_().(type) {
	case Spec_Spec:
		{
			data2, ok := other.Get_().(Spec_Spec)
			return ok && data1.Floor.Cmp(data2.Floor) == 0 && data1.Free.Equals(data2.Free) && data1.Helper.Equals(data2.Helper) && data1.AllowStore == data2.AllowStore && data1.HookCalls == data2.HookCalls && data1.ExitMode == data2.ExitMode
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Spec) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Spec)
	return ok && _this.Equals(typed)
}

func Type_Spec_() _dafny.TypeDescriptor {
	return type_Spec_{}
}

type type_Spec_ struct {
}

func (_this type_Spec_) Default() interface{} {
	return Companion_Spec_.Default()
}

func (_this type_Spec_) String() string {
	return "Obligations.Spec"
}
func (_this Spec) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Spec{}

// End of datatype Spec
