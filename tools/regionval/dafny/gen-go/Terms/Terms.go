// Package Terms
// Dafny module Terms compiled into Go

package Terms

import (
	os "os"

	m__System "github.com/dafny-lang/DafnyRuntimeGo/v4/System_"
	_dafny "github.com/dafny-lang/DafnyRuntimeGo/v4/dafny"
	m_Bits "github.com/takehaya/bpf-ninja/tools/regionval/dafny/gen-go/Bits"
	m_Obligations "github.com/takehaya/bpf-ninja/tools/regionval/dafny/gen-go/Obligations"
	m_Semantics "github.com/takehaya/bpf-ninja/tools/regionval/dafny/gen-go/Semantics"
)

var _ = os.Args
var _ _dafny.Dummy__
var _ m__System.Dummy__
var _ m_Bits.Dummy__
var _ m_Semantics.Dummy__
var _ m_Obligations.Dummy__

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
	return "Terms.Default__"
}
func (_this *Default__) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Default__{}

func (_static *CompanionStruct_Default___) Eval(t Term, e Env) uint64 {
	var _source0 Term = t
	_ = _source0
	{
		if _source0.Is_Entry() {
			var _0_k _dafny.Int = _source0.Get_().(Term_Entry).K
			_ = _0_k
			if (_0_k).Cmp(_dafny.IntOfUint32(((e).Dtor_regs()).Cardinality())) < 0 {
				return ((e).Dtor_regs()).Select((_0_k).Uint32()).(uint64)
			} else {
				return uint64(0)
			}
		}
	}
	{
		if _source0.Is_Fresh() {
			var _1_n _dafny.Int = _source0.Get_().(Term_Fresh).N
			_ = _1_n
			if (_1_n).Cmp(_dafny.IntOfUint32(((e).Dtor_log()).Cardinality())) < 0 {
				return ((e).Dtor_log()).Select((_1_n).Uint32()).(uint64)
			} else {
				return uint64(0)
			}
		}
	}
	{
		if _source0.Is_Const() {
			var _2_c uint64 = _source0.Get_().(Term_Const).C
			_ = _2_c
			return _2_c
		}
	}
	{
		if _source0.Is_AddT() {
			var _3_a Term = _source0.Get_().(Term_AddT).A
			_ = _3_a
			var _4_b Term = _source0.Get_().(Term_AddT).B
			_ = _4_b
			return (Companion_Default___.Eval(_3_a, e)) + (Companion_Default___.Eval(_4_b, e))
		}
	}
	{
		if _source0.Is_AndT() {
			var _5_a Term = _source0.Get_().(Term_AndT).A
			_ = _5_a
			var _6_b Term = _source0.Get_().(Term_AndT).B
			_ = _6_b
			return (Companion_Default___.Eval(_5_a, e)) & (Companion_Default___.Eval(_6_b, e))
		}
	}
	{
		if _source0.Is_OrT() {
			var _7_a Term = _source0.Get_().(Term_OrT).A
			_ = _7_a
			var _8_b Term = _source0.Get_().(Term_OrT).B
			_ = _8_b
			return (Companion_Default___.Eval(_7_a, e)) | (Companion_Default___.Eval(_8_b, e))
		}
	}
	{
		if _source0.Is_LshT() {
			var _9_a Term = _source0.Get_().(Term_LshT).A
			_ = _9_a
			var _10_b Term = _source0.Get_().(Term_LshT).B
			_ = _10_b
			return (Companion_Default___.Eval(_9_a, e)) << (uint8((Companion_Default___.Eval(_10_b, e)) & (uint64(63))))
		}
	}
	{
		if _source0.Is_Zext32() {
			var _11_a Term = _source0.Get_().(Term_Zext32).A
			_ = _11_a
			return m_Bits.Companion_Default___.Low32(Companion_Default___.Eval(_11_a, e))
		}
	}
	{
		var _12_bs _dafny.Sequence = _source0.Get_().(Term_Bytes).Bs
		_ = _12_bs
		if (_dafny.IntOfUint32((_12_bs).Cardinality())).Cmp(_dafny.IntOfInt64(8)) <= 0 {
			return m_Bits.Companion_Default___.LE(Companion_Default___.EvalBs(_12_bs, e))
		} else {
			return uint64(0)
		}
	}
}
func (_static *CompanionStruct_Default___) EvalB(b BTerm, e Env) uint8 {
	var _source0 BTerm = b
	_ = _source0
	{
		if _source0.Is_BEntry() {
			var _0_i _dafny.Int = _source0.Get_().(BTerm_BEntry).I
			_ = _0_i
			if (_0_i).Cmp(_dafny.IntOfUint32(((e).Dtor_stack()).Cardinality())) < 0 {
				return ((e).Dtor_stack()).Select((_0_i).Uint32()).(uint8)
			} else {
				return uint8(0)
			}
		}
	}
	{
		var _1_t Term = _source0.Get_().(BTerm_BOf).T
		_ = _1_t
		var _2_j _dafny.Int = _source0.Get_().(BTerm_BOf).J
		_ = _2_j
		if (_2_j).Cmp(_dafny.IntOfInt64(8)) < 0 {
			return m_Bits.Companion_Default___.ByteOf(Companion_Default___.Eval(_1_t, e), _2_j)
		} else {
			return uint8(0)
		}
	}
}
func (_static *CompanionStruct_Default___) EvalBs(bs _dafny.Sequence, e Env) _dafny.Sequence {
	if (_dafny.IntOfUint32((bs).Cardinality())).Sign() == 0 {
		return _dafny.SeqOf()
	} else {
		return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Default___.EvalB((bs).Select(0).(BTerm), e)), Companion_Default___.EvalBs((bs).Drop(1), e))
	}
}
func (_static *CompanionStruct_Default___) MkAdd(a Term, b Term) Term {
	if (((b).Is_Const()) && ((a).Is_AddT())) && (((a).Dtor_b()).Is_Const()) {
		return Companion_Term_.Create_AddT_((a).Dtor_a(), Companion_Term_.Create_Const_((((a).Dtor_b()).Dtor_c())+((b).Dtor_c())))
	} else {
		return Companion_Term_.Create_AddT_(a, b)
	}
}
func (_static *CompanionStruct_Default___) MkZext(a Term) Term {
	if (a).Is_Zext32() {
		return a
	} else {
		return Companion_Term_.Create_Zext32_(a)
	}
}
func (_static *CompanionStruct_Default___) AllBytesOf(bs _dafny.Sequence) bool {
	return (((_dafny.IntOfUint32((bs).Cardinality())).Cmp(_dafny.IntOfInt64(8)) == 0) && (((bs).Select(0).(BTerm)).Is_BOf())) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfInt64(8)), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_j _dafny.Int
		_0_j = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_0_j).Sign() != -1) && ((_0_j).Cmp(_dafny.IntOfInt64(8)) < 0)) || (((bs).Select((_0_j).Uint32()).(BTerm)).Equals(Companion_BTerm_.Create_BOf_(((bs).Select(0).(BTerm)).Dtor_t(), _0_j)))
	}))
}
func (_static *CompanionStruct_Default___) MkBytes(bs _dafny.Sequence) Term {
	if Companion_Default___.AllBytesOf(bs) {
		return ((bs).Select(0).(BTerm)).Dtor_t()
	} else {
		return Companion_Term_.Create_Bytes_(bs)
	}
}
func (_static *CompanionStruct_Default___) FpOff(t Term) m_Bits.Option {
	if (t).Equals(Companion_Term_.Create_Entry_(_dafny.IntOfInt64(10))) {
		return m_Bits.Companion_Option_.Create_Some_(uint64(0))
	} else if (((t).Is_AddT()) && (((t).Dtor_a()).Equals(Companion_Term_.Create_Entry_(_dafny.IntOfInt64(10))))) && (((t).Dtor_b()).Is_Const()) {
		return m_Bits.Companion_Option_.Create_Some_(((t).Dtor_b()).Dtor_c())
	} else {
		return m_Bits.Companion_Option_.Create_None_()
	}
}

// End of class Default__

// Definition of datatype Term
type Term struct {
	Data_Term_
}

func (_this Term) Get_() Data_Term_ {
	return _this.Data_Term_
}

type Data_Term_ interface {
	isTerm()
}

type CompanionStruct_Term_ struct {
}

var Companion_Term_ = CompanionStruct_Term_{}

type Term_Entry struct {
	K _dafny.Int
}

func (Term_Entry) isTerm() {}

func (CompanionStruct_Term_) Create_Entry_(K _dafny.Int) Term {
	return Term{Term_Entry{K}}
}

func (_this Term) Is_Entry() bool {
	_, ok := _this.Get_().(Term_Entry)
	return ok
}

type Term_Fresh struct {
	N _dafny.Int
}

func (Term_Fresh) isTerm() {}

func (CompanionStruct_Term_) Create_Fresh_(N _dafny.Int) Term {
	return Term{Term_Fresh{N}}
}

func (_this Term) Is_Fresh() bool {
	_, ok := _this.Get_().(Term_Fresh)
	return ok
}

type Term_Const struct {
	C uint64
}

func (Term_Const) isTerm() {}

func (CompanionStruct_Term_) Create_Const_(C uint64) Term {
	return Term{Term_Const{C}}
}

func (_this Term) Is_Const() bool {
	_, ok := _this.Get_().(Term_Const)
	return ok
}

type Term_AddT struct {
	A Term
	B Term
}

func (Term_AddT) isTerm() {}

func (CompanionStruct_Term_) Create_AddT_(A Term, B Term) Term {
	return Term{Term_AddT{A, B}}
}

func (_this Term) Is_AddT() bool {
	_, ok := _this.Get_().(Term_AddT)
	return ok
}

type Term_AndT struct {
	A Term
	B Term
}

func (Term_AndT) isTerm() {}

func (CompanionStruct_Term_) Create_AndT_(A Term, B Term) Term {
	return Term{Term_AndT{A, B}}
}

func (_this Term) Is_AndT() bool {
	_, ok := _this.Get_().(Term_AndT)
	return ok
}

type Term_OrT struct {
	A Term
	B Term
}

func (Term_OrT) isTerm() {}

func (CompanionStruct_Term_) Create_OrT_(A Term, B Term) Term {
	return Term{Term_OrT{A, B}}
}

func (_this Term) Is_OrT() bool {
	_, ok := _this.Get_().(Term_OrT)
	return ok
}

type Term_LshT struct {
	A Term
	B Term
}

func (Term_LshT) isTerm() {}

func (CompanionStruct_Term_) Create_LshT_(A Term, B Term) Term {
	return Term{Term_LshT{A, B}}
}

func (_this Term) Is_LshT() bool {
	_, ok := _this.Get_().(Term_LshT)
	return ok
}

type Term_Zext32 struct {
	A Term
}

func (Term_Zext32) isTerm() {}

func (CompanionStruct_Term_) Create_Zext32_(A Term) Term {
	return Term{Term_Zext32{A}}
}

func (_this Term) Is_Zext32() bool {
	_, ok := _this.Get_().(Term_Zext32)
	return ok
}

type Term_Bytes struct {
	Bs _dafny.Sequence
}

func (Term_Bytes) isTerm() {}

func (CompanionStruct_Term_) Create_Bytes_(Bs _dafny.Sequence) Term {
	return Term{Term_Bytes{Bs}}
}

func (_this Term) Is_Bytes() bool {
	_, ok := _this.Get_().(Term_Bytes)
	return ok
}

func (CompanionStruct_Term_) Default() Term {
	return Companion_Term_.Create_Entry_(_dafny.Zero)
}

func (_this Term) Dtor_k() _dafny.Int {
	return _this.Get_().(Term_Entry).K
}

func (_this Term) Dtor_n() _dafny.Int {
	return _this.Get_().(Term_Fresh).N
}

func (_this Term) Dtor_c() uint64 {
	return _this.Get_().(Term_Const).C
}

func (_this Term) Dtor_a() Term {
	switch data := _this.Get_().(type) {
	case Term_AddT:
		return data.A
	case Term_AndT:
		return data.A
	case Term_OrT:
		return data.A
	case Term_LshT:
		return data.A
	default:
		return data.(Term_Zext32).A
	}
}

func (_this Term) Dtor_b() Term {
	switch data := _this.Get_().(type) {
	case Term_AddT:
		return data.B
	case Term_AndT:
		return data.B
	case Term_OrT:
		return data.B
	default:
		return data.(Term_LshT).B
	}
}

func (_this Term) Dtor_bs() _dafny.Sequence {
	return _this.Get_().(Term_Bytes).Bs
}

func (_this Term) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Term_Entry:
		{
			return "Terms.Term.Entry" + "(" + _dafny.String(data.K) + ")"
		}
	case Term_Fresh:
		{
			return "Terms.Term.Fresh" + "(" + _dafny.String(data.N) + ")"
		}
	case Term_Const:
		{
			return "Terms.Term.Const" + "(" + _dafny.String(data.C) + ")"
		}
	case Term_AddT:
		{
			return "Terms.Term.AddT" + "(" + _dafny.String(data.A) + ", " + _dafny.String(data.B) + ")"
		}
	case Term_AndT:
		{
			return "Terms.Term.AndT" + "(" + _dafny.String(data.A) + ", " + _dafny.String(data.B) + ")"
		}
	case Term_OrT:
		{
			return "Terms.Term.OrT" + "(" + _dafny.String(data.A) + ", " + _dafny.String(data.B) + ")"
		}
	case Term_LshT:
		{
			return "Terms.Term.LshT" + "(" + _dafny.String(data.A) + ", " + _dafny.String(data.B) + ")"
		}
	case Term_Zext32:
		{
			return "Terms.Term.Zext32" + "(" + _dafny.String(data.A) + ")"
		}
	case Term_Bytes:
		{
			return "Terms.Term.Bytes" + "(" + _dafny.String(data.Bs) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Term) Equals(other Term) bool {
	switch data1 := _this.Get_().(type) {
	case Term_Entry:
		{
			data2, ok := other.Get_().(Term_Entry)
			return ok && data1.K.Cmp(data2.K) == 0
		}
	case Term_Fresh:
		{
			data2, ok := other.Get_().(Term_Fresh)
			return ok && data1.N.Cmp(data2.N) == 0
		}
	case Term_Const:
		{
			data2, ok := other.Get_().(Term_Const)
			return ok && data1.C == data2.C
		}
	case Term_AddT:
		{
			data2, ok := other.Get_().(Term_AddT)
			return ok && data1.A.Equals(data2.A) && data1.B.Equals(data2.B)
		}
	case Term_AndT:
		{
			data2, ok := other.Get_().(Term_AndT)
			return ok && data1.A.Equals(data2.A) && data1.B.Equals(data2.B)
		}
	case Term_OrT:
		{
			data2, ok := other.Get_().(Term_OrT)
			return ok && data1.A.Equals(data2.A) && data1.B.Equals(data2.B)
		}
	case Term_LshT:
		{
			data2, ok := other.Get_().(Term_LshT)
			return ok && data1.A.Equals(data2.A) && data1.B.Equals(data2.B)
		}
	case Term_Zext32:
		{
			data2, ok := other.Get_().(Term_Zext32)
			return ok && data1.A.Equals(data2.A)
		}
	case Term_Bytes:
		{
			data2, ok := other.Get_().(Term_Bytes)
			return ok && data1.Bs.Equals(data2.Bs)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Term) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Term)
	return ok && _this.Equals(typed)
}

func Type_Term_() _dafny.TypeDescriptor {
	return type_Term_{}
}

type type_Term_ struct {
}

func (_this type_Term_) Default() interface{} {
	return Companion_Term_.Default()
}

func (_this type_Term_) String() string {
	return "Terms.Term"
}
func (_this Term) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Term{}

// End of datatype Term

// Definition of datatype BTerm
type BTerm struct {
	Data_BTerm_
}

func (_this BTerm) Get_() Data_BTerm_ {
	return _this.Data_BTerm_
}

type Data_BTerm_ interface {
	isBTerm()
}

type CompanionStruct_BTerm_ struct {
}

var Companion_BTerm_ = CompanionStruct_BTerm_{}

type BTerm_BEntry struct {
	I _dafny.Int
}

func (BTerm_BEntry) isBTerm() {}

func (CompanionStruct_BTerm_) Create_BEntry_(I _dafny.Int) BTerm {
	return BTerm{BTerm_BEntry{I}}
}

func (_this BTerm) Is_BEntry() bool {
	_, ok := _this.Get_().(BTerm_BEntry)
	return ok
}

type BTerm_BOf struct {
	T Term
	J _dafny.Int
}

func (BTerm_BOf) isBTerm() {}

func (CompanionStruct_BTerm_) Create_BOf_(T Term, J _dafny.Int) BTerm {
	return BTerm{BTerm_BOf{T, J}}
}

func (_this BTerm) Is_BOf() bool {
	_, ok := _this.Get_().(BTerm_BOf)
	return ok
}

func (CompanionStruct_BTerm_) Default() BTerm {
	return Companion_BTerm_.Create_BEntry_(_dafny.Zero)
}

func (_this BTerm) Dtor_i() _dafny.Int {
	return _this.Get_().(BTerm_BEntry).I
}

func (_this BTerm) Dtor_t() Term {
	return _this.Get_().(BTerm_BOf).T
}

func (_this BTerm) Dtor_j() _dafny.Int {
	return _this.Get_().(BTerm_BOf).J
}

func (_this BTerm) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case BTerm_BEntry:
		{
			return "Terms.BTerm.BEntry" + "(" + _dafny.String(data.I) + ")"
		}
	case BTerm_BOf:
		{
			return "Terms.BTerm.BOf" + "(" + _dafny.String(data.T) + ", " + _dafny.String(data.J) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this BTerm) Equals(other BTerm) bool {
	switch data1 := _this.Get_().(type) {
	case BTerm_BEntry:
		{
			data2, ok := other.Get_().(BTerm_BEntry)
			return ok && data1.I.Cmp(data2.I) == 0
		}
	case BTerm_BOf:
		{
			data2, ok := other.Get_().(BTerm_BOf)
			return ok && data1.T.Equals(data2.T) && data1.J.Cmp(data2.J) == 0
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this BTerm) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(BTerm)
	return ok && _this.Equals(typed)
}

func Type_BTerm_() _dafny.TypeDescriptor {
	return type_BTerm_{}
}

type type_BTerm_ struct {
}

func (_this type_BTerm_) Default() interface{} {
	return Companion_BTerm_.Default()
}

func (_this type_BTerm_) String() string {
	return "Terms.BTerm"
}
func (_this BTerm) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = BTerm{}

// End of datatype BTerm

// Definition of datatype Env
type Env struct {
	Data_Env_
}

func (_this Env) Get_() Data_Env_ {
	return _this.Data_Env_
}

type Data_Env_ interface {
	isEnv()
}

type CompanionStruct_Env_ struct {
}

var Companion_Env_ = CompanionStruct_Env_{}

type Env_Env struct {
	Regs  _dafny.Sequence
	Stack _dafny.Sequence
	Log   _dafny.Sequence
}

func (Env_Env) isEnv() {}

func (CompanionStruct_Env_) Create_Env_(Regs _dafny.Sequence, Stack _dafny.Sequence, Log _dafny.Sequence) Env {
	return Env{Env_Env{Regs, Stack, Log}}
}

func (_this Env) Is_Env() bool {
	_, ok := _this.Get_().(Env_Env)
	return ok
}

func (CompanionStruct_Env_) Default() Env {
	return Companion_Env_.Create_Env_(_dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq)
}

func (_this Env) Dtor_regs() _dafny.Sequence {
	return _this.Get_().(Env_Env).Regs
}

func (_this Env) Dtor_stack() _dafny.Sequence {
	return _this.Get_().(Env_Env).Stack
}

func (_this Env) Dtor_log() _dafny.Sequence {
	return _this.Get_().(Env_Env).Log
}

func (_this Env) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Env_Env:
		{
			return "Terms.Env.Env" + "(" + _dafny.String(data.Regs) + ", " + _dafny.String(data.Stack) + ", " + _dafny.String(data.Log) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Env) Equals(other Env) bool {
	switch data1 := _this.Get_().(type) {
	case Env_Env:
		{
			data2, ok := other.Get_().(Env_Env)
			return ok && data1.Regs.Equals(data2.Regs) && data1.Stack.Equals(data2.Stack) && data1.Log.Equals(data2.Log)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Env) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Env)
	return ok && _this.Equals(typed)
}

func Type_Env_() _dafny.TypeDescriptor {
	return type_Env_{}
}

type type_Env_ struct {
}

func (_this type_Env_) Default() interface{} {
	return Companion_Env_.Default()
}

func (_this type_Env_) String() string {
	return "Terms.Env"
}
func (_this Env) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Env{}

// End of datatype Env
