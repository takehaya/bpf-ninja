// Package Checker
// Dafny module Checker compiled into Go

package Checker

import (
	os "os"

	m__System "github.com/dafny-lang/DafnyRuntimeGo/v4/System_"
	_dafny "github.com/dafny-lang/DafnyRuntimeGo/v4/dafny"
	m_Bits "github.com/takehaya/bpf-ninja/tools/regionval/dafny/gen-go/Bits"
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
	return "Checker.Default__"
}
func (_this *Default__) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Default__{}

func (_static *CompanionStruct_Default___) SWF(ss SState) bool {
	return (((_dafny.IntOfUint32(((ss).Dtor_regs()).Cardinality())).Cmp(m_Semantics.Companion_Default___.NREGS()) == 0) && ((_dafny.IntOfUint32(((ss).Dtor_stack()).Cardinality())).Cmp(m_Semantics.Companion_Default___.STACK()) == 0)) && ((_dafny.IntOfUint32(((ss).Dtor_snap()).Cardinality())).Cmp(m_Semantics.Companion_Default___.STACK()) == 0)
}
func (_static *CompanionStruct_Default___) SInit() SState {
	var _0_st _dafny.Sequence = _dafny.SeqCreate((m_Semantics.Companion_Default___.STACK()).Uint32(), func(coer7 func(_dafny.Int) m_Terms.BTerm) func(_dafny.Int) interface{} {
		return func(arg7 _dafny.Int) interface{} {
			return coer7(arg7)
		}
	}(func(_1_i _dafny.Int) m_Terms.BTerm {
		return m_Terms.Companion_BTerm_.Create_BEntry_(_1_i)
	}))
	_ = _0_st
	return Companion_SState_.Create_SState_(_dafny.SeqCreate((m_Semantics.Companion_Default___.NREGS()).Uint32(), func(coer8 func(_dafny.Int) m_Terms.Term) func(_dafny.Int) interface{} {
		return func(arg8 _dafny.Int) interface{} {
			return coer8(arg8)
		}
	}(func(_2_k _dafny.Int) m_Terms.Term {
		return m_Terms.Companion_Term_.Create_Entry_(_2_k)
	})), _0_st, _0_st, _dafny.Zero, _dafny.Zero, _dafny.Zero, m_Terms.Companion_Term_.Create_Const_(uint64(0)), m_Terms.Companion_Term_.Create_Const_(uint64(0)), Companion_Know_.Create_Unknown_())
}
func (_static *CompanionStruct_Default___) SymOperand(is64 bool, o m_Semantics.Operand, regs _dafny.Sequence) m_Terms.Term {
	var _source0 m_Semantics.Operand = o
	_ = _source0
	{
		if _source0.Is_Reg() {
			var _0_r _dafny.Int = _source0.Get_().(m_Semantics.Operand_Reg).R
			_ = _0_r
			if (_0_r).Cmp(m_Semantics.Companion_Default___.NREGS()) < 0 {
				return (regs).Select((_0_r).Uint32()).(m_Terms.Term)
			} else {
				return m_Terms.Companion_Term_.Create_Const_(uint64(0))
			}
		}
	}
	{
		var _1_k uint32 = _source0.Get_().(m_Semantics.Operand_Imm).K
		_ = _1_k
		return m_Terms.Companion_Term_.Create_Const_((func() uint64 {
			if is64 {
				return m_Bits.Companion_Default___.Sext32(_1_k)
			}
			return uint64(_1_k)
		})())
	}
}
func (_static *CompanionStruct_Default___) AluTerm(is64 bool, op m_Semantics.AluOp, a m_Terms.Term, b m_Terms.Term) m_Terms.Term {
	if is64 {
		var _source0 m_Semantics.AluOp = op
		_ = _source0
		{
			if _source0.Is_Add() {
				return m_Terms.Companion_Default___.MkAdd(a, b)
			}
		}
		{
			if _source0.Is_And() {
				return m_Terms.Companion_Term_.Create_AndT_(a, b)
			}
		}
		{
			if _source0.Is_Or() {
				return m_Terms.Companion_Term_.Create_OrT_(a, b)
			}
		}
		{
			if _source0.Is_Lsh() {
				return m_Terms.Companion_Term_.Create_LshT_(a, b)
			}
		}
		{
			return b
		}
	} else {
		var _source1 m_Semantics.AluOp = op
		_ = _source1
		{
			if _source1.Is_Add() {
				return m_Terms.Companion_Default___.MkZext(m_Terms.Companion_Default___.MkAdd(a, b))
			}
		}
		{
			if _source1.Is_And() {
				return m_Terms.Companion_Default___.MkZext(m_Terms.Companion_Term_.Create_AndT_(a, b))
			}
		}
		{
			if _source1.Is_Or() {
				return m_Terms.Companion_Default___.MkZext(m_Terms.Companion_Term_.Create_OrT_(a, b))
			}
		}
		{
			if _source1.Is_Lsh() {
				return m_Terms.Companion_Default___.MkZext(m_Terms.Companion_Term_.Create_LshT_(a, m_Terms.Companion_Term_.Create_AndT_(b, m_Terms.Companion_Term_.Create_Const_(uint64(31)))))
			}
		}
		{
			return m_Terms.Companion_Default___.MkZext(b)
		}
	}
}
func (_static *CompanionStruct_Default___) AddrTerm(ss SState, base _dafny.Int, off uint16) m_Terms.Term {
	return m_Terms.Companion_Default___.MkAdd(((ss).Dtor_regs()).Select((base).Uint32()).(m_Terms.Term), m_Terms.Companion_Term_.Create_Const_(m_Bits.Companion_Default___.Sext16(off)))
}
func (_static *CompanionStruct_Default___) FreshRegs(regs _dafny.Sequence, next _dafny.Int) _dafny.Sequence {
	return _dafny.SeqCreate((m_Semantics.Companion_Default___.NREGS()).Uint32(), func(coer9 func(_dafny.Int) m_Terms.Term) func(_dafny.Int) interface{} {
		return func(arg9 _dafny.Int) interface{} {
			return coer9(arg9)
		}
	}((func(_0_next _dafny.Int, _1_regs _dafny.Sequence) func(_dafny.Int) m_Terms.Term {
		return func(_2_k _dafny.Int) m_Terms.Term {
			return (func() m_Terms.Term {
				if (_2_k).Cmp(_dafny.IntOfInt64(6)) < 0 {
					return m_Terms.Companion_Term_.Create_Fresh_((_0_next).Plus(_2_k))
				}
				return (_1_regs).Select((_2_k).Uint32()).(m_Terms.Term)
			})()
		}
	})(next, regs)))
}
func (_static *CompanionStruct_Default___) WriteBT(st _dafny.Sequence, idx _dafny.Int, bs _dafny.Sequence) _dafny.Sequence {
	return _dafny.SeqCreate((_dafny.IntOfUint32((st).Cardinality())).Uint32(), func(coer10 func(_dafny.Int) m_Terms.BTerm) func(_dafny.Int) interface{} {
		return func(arg10 _dafny.Int) interface{} {
			return coer10(arg10)
		}
	}((func(_0_idx _dafny.Int, _1_bs _dafny.Sequence, _2_st _dafny.Sequence) func(_dafny.Int) m_Terms.BTerm {
		return func(_3_i _dafny.Int) m_Terms.BTerm {
			return (func() m_Terms.BTerm {
				if ((_0_idx).Cmp(_3_i) <= 0) && ((_3_i).Cmp((_0_idx).Plus(_dafny.IntOfUint32((_1_bs).Cardinality()))) < 0) {
					return (_1_bs).Select(((_3_i).Minus(_0_idx)).Uint32()).(m_Terms.BTerm)
				}
				return (_2_st).Select((_3_i).Uint32()).(m_Terms.BTerm)
			})()
		}
	})(idx, bs, st)))
}
func (_static *CompanionStruct_Default___) StoreBytes(v m_Terms.Term, w _dafny.Int) _dafny.Sequence {
	return _dafny.SeqCreate((w).Uint32(), func(coer11 func(_dafny.Int) m_Terms.BTerm) func(_dafny.Int) interface{} {
		return func(arg11 _dafny.Int) interface{} {
			return coer11(arg11)
		}
	}((func(_0_v m_Terms.Term, _1_w _dafny.Int) func(_dafny.Int) m_Terms.BTerm {
		return func(_2_j _dafny.Int) m_Terms.BTerm {
			return m_Terms.Companion_BTerm_.Create_BOf_(_0_v, _2_j)
		}
	})(v, w)))
}
func (_static *CompanionStruct_Default___) SymStore(sp m_Obligations.Spec, ss SState, base _dafny.Int, off uint16, w _dafny.Int, v m_Terms.Term) SR {
	var _pat_let_tv0 = ss
	_ = _pat_let_tv0
	var _pat_let_tv1 = v
	_ = _pat_let_tv1
	var _pat_let_tv2 = w
	_ = _pat_let_tv2
	if !((sp).Dtor_allowStore()) {
		return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("store not allowed in this window"))
	} else if ((base).Cmp(m_Semantics.Companion_Default___.NREGS()) >= 0) || ((w).Cmp(_dafny.IntOfInt64(8)) > 0) {
		return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("malformed store"))
	} else {
		var _source0 m_Bits.Option = m_Terms.Companion_Default___.FpOff(Companion_Default___.AddrTerm(ss, base, off))
		_ = _source0
		{
			if _source0.Is_None() {
				return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("store address is not r10+const"))
			}
		}
		{
			var _0_c uint64 = _source0.Get_().(m_Bits.Option_Some).Value.(uint64)
			_ = _0_c
			var _1_o _dafny.Int = m_Bits.Companion_Default___.Signed64(_0_c)
			_ = _1_o
			if !((((_dafny.Zero).Minus(m_Semantics.Companion_Default___.STACK())).Cmp(_1_o) <= 0) && (((_1_o).Plus(w)).Cmp((sp).Dtor_floor()) <= 0)) {
				return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("store not below the floor"))
			} else {
				return Companion_SR_.Create_SOk_(func(_pat_let30_0 SState) SState {
					return func(_2_dt__update__tmp_h0 SState) SState {
						return func(_pat_let31_0 _dafny.Sequence) SState {
							return func(_3_dt__update_hstack_h0 _dafny.Sequence) SState {
								return Companion_SState_.Create_SState_((_2_dt__update__tmp_h0).Dtor_regs(), _3_dt__update_hstack_h0, (_2_dt__update__tmp_h0).Dtor_snap(), (_2_dt__update__tmp_h0).Dtor_next(), (_2_dt__update__tmp_h0).Dtor_helpers(), (_2_dt__update__tmp_h0).Dtor_hooks(), (_2_dt__update__tmp_h0).Dtor_ret(), (_2_dt__update__tmp_h0).Dtor_hkey(), (_2_dt__update__tmp_h0).Dtor_know())
							}(_pat_let31_0)
						}(Companion_Default___.WriteBT((_pat_let_tv0).Dtor_stack(), (_1_o).Plus(m_Semantics.Companion_Default___.STACK()), Companion_Default___.StoreBytes(_pat_let_tv1, _pat_let_tv2)))
					}(_pat_let30_0)
				}(ss))
			}
		}
	}
}
func (_static *CompanionStruct_Default___) SymStep(sp m_Obligations.Spec, ins m_Semantics.Instr, ss SState) SR {
	var _pat_let_tv0 = ss
	_ = _pat_let_tv0
	var _pat_let_tv1 = ss
	_ = _pat_let_tv1
	var _pat_let_tv2 = ss
	_ = _pat_let_tv2
	var _pat_let_tv3 = ss
	_ = _pat_let_tv3
	var _pat_let_tv4 = ss
	_ = _pat_let_tv4
	var _pat_let_tv5 = ss
	_ = _pat_let_tv5
	var _pat_let_tv6 = ss
	_ = _pat_let_tv6
	var _pat_let_tv7 = ss
	_ = _pat_let_tv7
	var _source0 m_Semantics.Instr = ins
	_ = _source0
	{
		if _source0.Is_Alu() {
			var _0_is64 bool = _source0.Get_().(m_Semantics.Instr_Alu).Is64
			_ = _0_is64
			var _1_op m_Semantics.AluOp = _source0.Get_().(m_Semantics.Instr_Alu).Op
			_ = _1_op
			var _2_dst _dafny.Int = _source0.Get_().(m_Semantics.Instr_Alu).Dst
			_ = _2_dst
			var _3_opnd m_Semantics.Operand = _source0.Get_().(m_Semantics.Instr_Alu).Opnd
			_ = _3_opnd
			if (_2_dst).Cmp(_dafny.IntOfInt64(10)) >= 0 {
				return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("write to r10"))
			} else {
				return Companion_SR_.Create_SOk_(func(_pat_let32_0 SState) SState {
					return func(_4_dt__update__tmp_h0 SState) SState {
						return func(_pat_let33_0 _dafny.Sequence) SState {
							return func(_5_dt__update_hregs_h0 _dafny.Sequence) SState {
								return Companion_SState_.Create_SState_(_5_dt__update_hregs_h0, (_4_dt__update__tmp_h0).Dtor_stack(), (_4_dt__update__tmp_h0).Dtor_snap(), (_4_dt__update__tmp_h0).Dtor_next(), (_4_dt__update__tmp_h0).Dtor_helpers(), (_4_dt__update__tmp_h0).Dtor_hooks(), (_4_dt__update__tmp_h0).Dtor_ret(), (_4_dt__update__tmp_h0).Dtor_hkey(), (_4_dt__update__tmp_h0).Dtor_know())
							}(_pat_let33_0)
						}(_dafny.Companion_Sequence_.Update((_pat_let_tv0).Dtor_regs(), (_2_dst).Uint32(), Companion_Default___.AluTerm(_0_is64, _1_op, ((_pat_let_tv1).Dtor_regs()).Select((_2_dst).Uint32()).(m_Terms.Term), Companion_Default___.SymOperand(_0_is64, _3_opnd, (_pat_let_tv2).Dtor_regs()))))
					}(_pat_let32_0)
				}(ss))
			}
		}
	}
	{
		if _source0.Is_Ldx() {
			var _6_w _dafny.Int = _source0.Get_().(m_Semantics.Instr_Ldx).Size
			_ = _6_w
			var _7_dst _dafny.Int = _source0.Get_().(m_Semantics.Instr_Ldx).Dst
			_ = _7_dst
			var _8_base _dafny.Int = _source0.Get_().(m_Semantics.Instr_Ldx).Base
			_ = _8_base
			var _9_off uint16 = _source0.Get_().(m_Semantics.Instr_Ldx).Off
			_ = _9_off
			if (((_7_dst).Cmp(_dafny.IntOfInt64(10)) >= 0) || ((_8_base).Cmp(m_Semantics.Companion_Default___.NREGS()) >= 0)) || ((_6_w).Cmp(_dafny.IntOfInt64(8)) > 0) {
				return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("malformed load"))
			} else if ((m_Terms.Companion_Default___.FpOff(Companion_Default___.AddrTerm(ss, _8_base, _9_off))).Is_Some()) && (!(m_Semantics.Companion_Default___.InFrame(m_Bits.Companion_Default___.Signed64((m_Terms.Companion_Default___.FpOff(Companion_Default___.AddrTerm(ss, _8_base, _9_off))).Dtor_value().(uint64)), _6_w))) {
				return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("stack load outside the frame"))
			} else {
				var _10_v m_Terms.Term = func() m_Terms.Term {
					var _source1 m_Bits.Option = m_Terms.Companion_Default___.FpOff(Companion_Default___.AddrTerm(ss, _8_base, _9_off))
					_ = _source1
					{
						if _source1.Is_Some() {
							var _11_c uint64 = _source1.Get_().(m_Bits.Option_Some).Value.(uint64)
							_ = _11_c
							if m_Semantics.Companion_Default___.InFrame(m_Bits.Companion_Default___.Signed64(_11_c), _6_w) {
								return m_Terms.Companion_Default___.MkBytes(((ss).Dtor_stack()).Subsequence(((m_Bits.Companion_Default___.Signed64(_11_c)).Plus(_dafny.IntOfInt64(512))).Uint32(), (((m_Bits.Companion_Default___.Signed64(_11_c)).Plus(_dafny.IntOfInt64(512))).Plus(_6_w)).Uint32()))
							} else {
								return m_Terms.Companion_Term_.Create_Fresh_((ss).Dtor_next())
							}
						}
					}
					{
						return m_Terms.Companion_Term_.Create_Fresh_((ss).Dtor_next())
					}
				}()
				_ = _10_v
				return Companion_SR_.Create_SOk_(func(_pat_let34_0 SState) SState {
					return func(_12_dt__update__tmp_h1 SState) SState {
						return func(_pat_let35_0 _dafny.Int) SState {
							return func(_13_dt__update_hnext_h0 _dafny.Int) SState {
								return func(_pat_let36_0 _dafny.Sequence) SState {
									return func(_14_dt__update_hregs_h1 _dafny.Sequence) SState {
										return Companion_SState_.Create_SState_(_14_dt__update_hregs_h1, (_12_dt__update__tmp_h1).Dtor_stack(), (_12_dt__update__tmp_h1).Dtor_snap(), _13_dt__update_hnext_h0, (_12_dt__update__tmp_h1).Dtor_helpers(), (_12_dt__update__tmp_h1).Dtor_hooks(), (_12_dt__update__tmp_h1).Dtor_ret(), (_12_dt__update__tmp_h1).Dtor_hkey(), (_12_dt__update__tmp_h1).Dtor_know())
									}(_pat_let36_0)
								}(_dafny.Companion_Sequence_.Update((_pat_let_tv4).Dtor_regs(), (_7_dst).Uint32(), _10_v))
							}(_pat_let35_0)
						}(((_pat_let_tv3).Dtor_next()).Plus(_dafny.One))
					}(_pat_let34_0)
				}(ss))
			}
		}
	}
	{
		if _source0.Is_Stx() {
			var _15_w _dafny.Int = _source0.Get_().(m_Semantics.Instr_Stx).Size
			_ = _15_w
			var _16_base _dafny.Int = _source0.Get_().(m_Semantics.Instr_Stx).Base
			_ = _16_base
			var _17_src _dafny.Int = _source0.Get_().(m_Semantics.Instr_Stx).Src
			_ = _17_src
			var _18_off uint16 = _source0.Get_().(m_Semantics.Instr_Stx).Off
			_ = _18_off
			if (_17_src).Cmp(m_Semantics.Companion_Default___.NREGS()) >= 0 {
				return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("malformed store"))
			} else {
				return Companion_Default___.SymStore(sp, ss, _16_base, _18_off, _15_w, ((ss).Dtor_regs()).Select((_17_src).Uint32()).(m_Terms.Term))
			}
		}
	}
	{
		if _source0.Is_St() {
			var _19_w _dafny.Int = _source0.Get_().(m_Semantics.Instr_St).Size
			_ = _19_w
			var _20_base _dafny.Int = _source0.Get_().(m_Semantics.Instr_St).Base
			_ = _20_base
			var _21_off uint16 = _source0.Get_().(m_Semantics.Instr_St).Off
			_ = _21_off
			var _22_imm uint32 = _source0.Get_().(m_Semantics.Instr_St).Imm
			_ = _22_imm
			return Companion_Default___.SymStore(sp, ss, _20_base, _21_off, _19_w, m_Terms.Companion_Term_.Create_Const_(m_Bits.Companion_Default___.Sext32(_22_imm)))
		}
	}
	{
		if _source0.Is_CallHelper() {
			var _23_id uint32 = _source0.Get_().(m_Semantics.Instr_CallHelper).Id
			_ = _23_id
			if !(((sp).Dtor_helper()).Is_Helper()) {
				return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("helper call outside a site window"))
			} else if ((ss).Dtor_helpers()).Sign() != 0 {
				return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("second helper call on a path"))
			} else if (((sp).Dtor_helper()).Dtor_checkArgs()) && (!_dafny.Companion_Sequence_.Equal(((ss).Dtor_regs()).Subsequence(1, 6), _dafny.SeqOf(m_Terms.Companion_Term_.Create_Entry_(_dafny.One), m_Terms.Companion_Term_.Create_Entry_(_dafny.IntOfInt64(2)), m_Terms.Companion_Term_.Create_Entry_(_dafny.IntOfInt64(3)), m_Terms.Companion_Term_.Create_Entry_(_dafny.IntOfInt64(4)), m_Terms.Companion_Term_.Create_Entry_(_dafny.IntOfInt64(5))))) {
				return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("r1-r5 changed before the helper call"))
			} else if (((sp).Dtor_wrap()).Is_Wrap()) && (!(((m_Bits.Companion_Option_.Create_Some_(_23_id)).Equals(m_Obligations.Companion_Default___.HelperIdOf(((sp).Dtor_wrap()).Dtor_helper()))) && (Companion_Default___.WrapArgsSym(_23_id, (ss).Dtor_regs())))) {
				return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("W's helper call is not O[i] with the site's r1-r5"))
			} else {
				var _24_lo _dafny.Int = (m_Semantics.Companion_Default___.STACK()).Plus((sp).Dtor_floor())
				_ = _24_lo
				var _25_st _dafny.Sequence = _dafny.SeqCreate((m_Semantics.Companion_Default___.STACK()).Uint32(), func(coer12 func(_dafny.Int) m_Terms.BTerm) func(_dafny.Int) interface{} {
					return func(arg12 _dafny.Int) interface{} {
						return coer12(arg12)
					}
				}((func(_26_lo _dafny.Int, _27_ss SState) func(_dafny.Int) m_Terms.BTerm {
					return func(_28_i _dafny.Int) m_Terms.BTerm {
						return (func() m_Terms.BTerm {
							if (_28_i).Cmp(_26_lo) >= 0 {
								return m_Terms.Companion_BTerm_.Create_BOf_(m_Terms.Companion_Term_.Create_Fresh_((((_27_ss).Dtor_next()).Plus(_dafny.IntOfInt64(6))).Plus((_28_i).Minus(_26_lo))), _dafny.Zero)
							}
							return ((_27_ss).Dtor_stack()).Select((_28_i).Uint32()).(m_Terms.BTerm)
						})()
					}
				})(_24_lo, ss)))
				_ = _25_st
				return Companion_SR_.Create_SOk_(Companion_SState_.Create_SState_(Companion_Default___.FreshRegs((ss).Dtor_regs(), (ss).Dtor_next()), _25_st, _25_st, (((ss).Dtor_next()).Plus(_dafny.IntOfInt64(6))).Plus((_dafny.Zero).Minus((sp).Dtor_floor())), _dafny.One, (ss).Dtor_hooks(), m_Terms.Companion_Term_.Create_Fresh_((ss).Dtor_next()), ((ss).Dtor_regs()).Select(2).(m_Terms.Term), Companion_Know_.Create_Unknown_()))
			}
		}
	}
	{
		if _source0.Is_CallLocal() {
			if !((sp).Dtor_hookCalls()) {
				return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("call not allowed in this window"))
			} else if ((ss).Dtor_hooks()).Sign() != 0 {
				return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("second hook call on a path"))
			} else {
				return Companion_SR_.Create_SOk_(func(_pat_let37_0 SState) SState {
					return func(_29_dt__update__tmp_h2 SState) SState {
						return func(_pat_let38_0 _dafny.Int) SState {
							return func(_30_dt__update_hhooks_h0 _dafny.Int) SState {
								return func(_pat_let39_0 _dafny.Int) SState {
									return func(_31_dt__update_hnext_h1 _dafny.Int) SState {
										return func(_pat_let40_0 _dafny.Sequence) SState {
											return func(_32_dt__update_hregs_h2 _dafny.Sequence) SState {
												return Companion_SState_.Create_SState_(_32_dt__update_hregs_h2, (_29_dt__update__tmp_h2).Dtor_stack(), (_29_dt__update__tmp_h2).Dtor_snap(), _31_dt__update_hnext_h1, (_29_dt__update__tmp_h2).Dtor_helpers(), _30_dt__update_hhooks_h0, (_29_dt__update__tmp_h2).Dtor_ret(), (_29_dt__update__tmp_h2).Dtor_hkey(), (_29_dt__update__tmp_h2).Dtor_know())
											}(_pat_let40_0)
										}(Companion_Default___.FreshRegs((_pat_let_tv6).Dtor_regs(), (_pat_let_tv7).Dtor_next()))
									}(_pat_let39_0)
								}(((_pat_let_tv5).Dtor_next()).Plus(_dafny.IntOfInt64(6)))
							}(_pat_let38_0)
						}(_dafny.One)
					}(_pat_let37_0)
				}(ss))
			}
		}
	}
	{
		return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("control instruction"))
	}
}
func (_static *CompanionStruct_Default___) WrapArgsSym(id uint32, regs _dafny.Sequence) bool {
	return ((((((regs).Select(1).(m_Terms.Term)).Equals(m_Terms.Companion_Term_.Create_Entry_(_dafny.One))) && (((regs).Select(2).(m_Terms.Term)).Equals(m_Terms.Companion_Term_.Create_Entry_(_dafny.IntOfInt64(2))))) && (((regs).Select(3).(m_Terms.Term)).Equals(m_Terms.Companion_Term_.Create_Entry_(_dafny.IntOfInt64(3))))) && (((regs).Select(5).(m_Terms.Term)).Equals(m_Terms.Companion_Term_.Create_Entry_(_dafny.IntOfInt64(5))))) && (!(!(m_Obligations.Companion_Default___.IsLookup(id))) || (((regs).Select(4).(m_Terms.Term)).Equals(m_Terms.Companion_Term_.Create_Entry_(_dafny.IntOfInt64(4)))))
}
func (_static *CompanionStruct_Default___) EnterWS(ss SState) SState {
	var _0_dt__update__tmp_h0 SState = ss
	_ = _0_dt__update__tmp_h0
	var _1_dt__update_hnext_h0 _dafny.Int = ((ss).Dtor_next()).Plus(_dafny.IntOfInt64(5))
	_ = _1_dt__update_hnext_h0
	var _2_dt__update_hregs_h0 _dafny.Sequence = _dafny.SeqCreate((m_Semantics.Companion_Default___.NREGS()).Uint32(), func(coer13 func(_dafny.Int) m_Terms.Term) func(_dafny.Int) interface{} {
		return func(arg13 _dafny.Int) interface{} {
			return coer13(arg13)
		}
	}((func(_3_ss SState) func(_dafny.Int) m_Terms.Term {
		return func(_4_k _dafny.Int) m_Terms.Term {
			return (func() m_Terms.Term {
				if (((_dafny.One).Cmp(_4_k) <= 0) && ((_4_k).Cmp(_dafny.IntOfInt64(5)) <= 0)) || ((_4_k).Cmp(_dafny.IntOfInt64(10)) == 0) {
					return ((_3_ss).Dtor_regs()).Select((_4_k).Uint32()).(m_Terms.Term)
				}
				return m_Terms.Companion_Term_.Create_Fresh_(((_3_ss).Dtor_next()).Plus((func() _dafny.Int {
					if (_4_k).Sign() == 0 {
						return _dafny.Zero
					}
					return (_4_k).Minus(_dafny.IntOfInt64(5))
				})()))
			})()
		}
	})(ss)))
	_ = _2_dt__update_hregs_h0
	return Companion_SState_.Create_SState_(_2_dt__update_hregs_h0, (_0_dt__update__tmp_h0).Dtor_stack(), (_0_dt__update__tmp_h0).Dtor_snap(), _1_dt__update_hnext_h0, (_0_dt__update__tmp_h0).Dtor_helpers(), (_0_dt__update__tmp_h0).Dtor_hooks(), (_0_dt__update__tmp_h0).Dtor_ret(), (_0_dt__update__tmp_h0).Dtor_hkey(), (_0_dt__update__tmp_h0).Dtor_know())
}
func (_static *CompanionStruct_Default___) ReturnS(ss SState, caller _dafny.Sequence) SState {
	var _0_dt__update__tmp_h0 SState = ss
	_ = _0_dt__update__tmp_h0
	var _1_dt__update_hnext_h0 _dafny.Int = ((ss).Dtor_next()).Plus(_dafny.IntOfInt64(5))
	_ = _1_dt__update_hnext_h0
	var _2_dt__update_hregs_h0 _dafny.Sequence = _dafny.SeqCreate((m_Semantics.Companion_Default___.NREGS()).Uint32(), func(coer14 func(_dafny.Int) m_Terms.Term) func(_dafny.Int) interface{} {
		return func(arg14 _dafny.Int) interface{} {
			return coer14(arg14)
		}
	}((func(_3_ss SState, _4_caller _dafny.Sequence) func(_dafny.Int) m_Terms.Term {
		return func(_5_k _dafny.Int) m_Terms.Term {
			return (func() m_Terms.Term {
				if (_5_k).Sign() == 0 {
					return ((_3_ss).Dtor_regs()).Select(0).(m_Terms.Term)
				}
				return (func() m_Terms.Term {
					if (_5_k).Cmp(_dafny.IntOfInt64(5)) <= 0 {
						return m_Terms.Companion_Term_.Create_Fresh_(((_3_ss).Dtor_next()).Plus((_5_k).Minus(_dafny.One)))
					}
					return (_4_caller).Select((_5_k).Uint32()).(m_Terms.Term)
				})()
			})()
		}
	})(ss, caller)))
	_ = _2_dt__update_hregs_h0
	return Companion_SState_.Create_SState_(_2_dt__update_hregs_h0, (_0_dt__update__tmp_h0).Dtor_stack(), (_0_dt__update__tmp_h0).Dtor_snap(), _1_dt__update_hnext_h0, (_0_dt__update__tmp_h0).Dtor_helpers(), (_0_dt__update__tmp_h0).Dtor_hooks(), (_0_dt__update__tmp_h0).Dtor_ret(), (_0_dt__update__tmp_h0).Dtor_hkey(), (_0_dt__update__tmp_h0).Dtor_know())
}
func (_static *CompanionStruct_Default___) BindFail(sp m_Obligations.Spec, pc _dafny.Int, ss SState) _dafny.Sequence {
	return Companion_Default___.BindFailFrom((sp).Dtor_binds(), pc, ss, _dafny.Zero)
}
func (_static *CompanionStruct_Default___) CopyHolds(t m_Terms.Term, off _dafny.Int, ss SState) bool {
	return (((m_Terms.Companion_Default___.FpOff(t)).Is_Some()) && ((m_Bits.Companion_Default___.Signed64((m_Terms.Companion_Default___.FpOff(t)).Dtor_value().(uint64))).Cmp(off) == 0)) && ((((ss).Dtor_regs()).Select(0).(m_Terms.Term)).Equals((ss).Dtor_ret()))
}
func (_static *CompanionStruct_Default___) BindFailFrom(bs _dafny.Sequence, pc _dafny.Int, ss SState, j _dafny.Int) _dafny.Sequence {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (j).Cmp(_dafny.IntOfUint32((bs).Cardinality())) >= 0 {
		return _dafny.UnicodeSeqOfUtf8Bytes("")
	} else if (((bs).Select((j).Uint32()).(m_Obligations.Bind)).Dtor_pc()).Cmp(pc) != 0 {
		var _in0 _dafny.Sequence = bs
		_ = _in0
		var _in1 _dafny.Int = pc
		_ = _in1
		var _in2 SState = ss
		_ = _in2
		var _in3 _dafny.Int = (j).Plus(_dafny.One)
		_ = _in3
		bs = _in0
		pc = _in1
		ss = _in2
		j = _in3
		goto TAIL_CALL_START
	} else if ((ss).Dtor_helpers()).Cmp(_dafny.One) != 0 {
		return _dafny.UnicodeSeqOfUtf8Bytes("record binding: hook call before the helper call")
	} else if !(((_dafny.One).Cmp(((bs).Select((j).Uint32()).(m_Obligations.Bind)).Dtor_reg()) <= 0) && ((((bs).Select((j).Uint32()).(m_Obligations.Bind)).Dtor_reg()).Cmp(_dafny.IntOfInt64(5)) <= 0)) {
		return _dafny.UnicodeSeqOfUtf8Bytes("record binding: bad register")
	} else if ((((bs).Select((j).Uint32()).(m_Obligations.Bind)).Dtor_role()).Is_KeyArg()) && (!(((ss).Dtor_regs()).Select((((bs).Select((j).Uint32()).(m_Obligations.Bind)).Dtor_reg()).Uint32()).(m_Terms.Term)).Equals((ss).Dtor_hkey())) {
		return _dafny.UnicodeSeqOfUtf8Bytes("record binding: key argument is not the helper's key pointer")
	} else if ((((bs).Select((j).Uint32()).(m_Obligations.Bind)).Dtor_role()).Is_ValueArg()) && (!(((ss).Dtor_regs()).Select((((bs).Select((j).Uint32()).(m_Obligations.Bind)).Dtor_reg()).Uint32()).(m_Terms.Term)).Equals((ss).Dtor_ret())) {
		return _dafny.UnicodeSeqOfUtf8Bytes("record binding: value argument is not the helper's result")
	} else if ((((bs).Select((j).Uint32()).(m_Obligations.Bind)).Dtor_role()).Is_HitCall()) && (!(((ss).Dtor_know()).Is_NonZero())) {
		return _dafny.UnicodeSeqOfUtf8Bytes("hook selection: hit hook on a path where the result may be NULL")
	} else if ((((bs).Select((j).Uint32()).(m_Obligations.Bind)).Dtor_role()).Is_MissCall()) && (!(((ss).Dtor_know()).Is_IsZero())) {
		return _dafny.UnicodeSeqOfUtf8Bytes("hook selection: miss hook on a path where the result may be non-NULL")
	} else if ((((bs).Select((j).Uint32()).(m_Obligations.Bind)).Dtor_role()).Is_CopyArg()) && (!(Companion_Default___.CopyHolds(((ss).Dtor_regs()).Select((((bs).Select((j).Uint32()).(m_Obligations.Bind)).Dtor_reg()).Uint32()).(m_Terms.Term), (((bs).Select((j).Uint32()).(m_Obligations.Bind)).Dtor_role()).Dtor_off(), ss))) {
		return _dafny.UnicodeSeqOfUtf8Bytes("record binding: value argument is not r10 plus the copy's offset, or r0 is not the helper's result")
	} else {
		var _in4 _dafny.Sequence = bs
		_ = _in4
		var _in5 _dafny.Int = pc
		_ = _in5
		var _in6 SState = ss
		_ = _in6
		var _in7 _dafny.Int = (j).Plus(_dafny.One)
		_ = _in7
		bs = _in4
		pc = _in5
		ss = _in6
		j = _in7
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) Final(sp m_Obligations.Spec, ss SState, pc _dafny.Int) Verdict {
	if ((ss).Dtor_helpers()).Cmp((func() _dafny.Int {
		if ((sp).Dtor_helper()).Is_Helper() {
			return _dafny.One
		}
		return _dafny.Zero
	})()) != 0 {
		return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("helper call count"))
	} else if !(_dafny.Quantifier(_dafny.IntegerRange(_dafny.IntOfInt64(6), (_dafny.IntOfInt64(10)).Plus(_dafny.One)), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_k _dafny.Int
		_0_k = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_dafny.IntOfInt64(6)).Cmp(_0_k) <= 0) && ((_0_k).Cmp(_dafny.IntOfInt64(10)) <= 0)) || ((((ss).Dtor_regs()).Select((_0_k).Uint32()).(m_Terms.Term)).Equals(m_Terms.Companion_Term_.Create_Entry_(_0_k)))
	})) {
		return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("r6-r10 not preserved"))
	} else if !(_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, (_dafny.IntOfInt64(5)).Plus(_dafny.One)), true, func(_forall_var_1 _dafny.Int) bool {
		var _1_k _dafny.Int
		_1_k = interface{}(_forall_var_1).(_dafny.Int)
		return !(((((_1_k).Sign() != -1) && ((_1_k).Cmp(_dafny.IntOfInt64(5)) <= 0)) && (!((sp).Dtor_free()).Contains(_1_k))) && (!(((_1_k).Sign() == 0) && (m_Obligations.Companion_Default___.R0Special(sp))))) || ((((ss).Dtor_regs()).Select((_1_k).Uint32()).(m_Terms.Term)).Equals(m_Terms.Companion_Term_.Create_Entry_(_1_k)))
	})) {
		return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("register not preserved"))
	} else if ((((sp).Dtor_helper()).Is_Helper()) && (((sp).Dtor_helper()).Dtor_restoreR0())) && (!(((ss).Dtor_regs()).Select(0).(m_Terms.Term)).Equals((ss).Dtor_ret())) {
		return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("r0 not restored to the helper result"))
	} else if ((sp).Dtor_exitMode()) && (!(((ss).Dtor_regs()).Select(0).(m_Terms.Term)).Equals(m_Terms.Companion_Term_.Create_Const_(uint64(0)))) {
		return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("r0 != 0 at exit"))
	} else if !(_dafny.Quantifier(_dafny.IntegerRange((m_Semantics.Companion_Default___.STACK()).Plus((sp).Dtor_floor()), m_Semantics.Companion_Default___.STACK()), true, func(_forall_var_2 _dafny.Int) bool {
		var _2_i _dafny.Int
		_2_i = interface{}(_forall_var_2).(_dafny.Int)
		return !((((m_Semantics.Companion_Default___.STACK()).Plus((sp).Dtor_floor())).Cmp(_2_i) <= 0) && ((_2_i).Cmp(m_Semantics.Companion_Default___.STACK()) < 0)) || ((((ss).Dtor_stack()).Select((_2_i).Uint32()).(m_Terms.BTerm)).Equals(((ss).Dtor_snap()).Select((_2_i).Uint32()).(m_Terms.BTerm)))
	})) {
		return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("stack at or above the floor changed"))
	} else {
		return Companion_Verdict_.Create_Validated_()
	}
}
func (_static *CompanionStruct_Default___) Refine(ss SState, c m_Semantics.Cond, dst _dafny.Int, imm uint32, taken bool) SState {
	if (((((c).Is_JEq()) || ((c).Is_JNe())) && ((imm) == (uint32(0)))) && ((dst).Cmp(m_Semantics.Companion_Default___.NREGS()) < 0)) && ((((ss).Dtor_regs()).Select((dst).Uint32()).(m_Terms.Term)).Equals((ss).Dtor_ret())) {
		var _0_dt__update__tmp_h0 SState = ss
		_ = _0_dt__update__tmp_h0
		var _1_dt__update_hknow_h0 Know = (func() Know {
			if ((c).Is_JEq()) == (taken) {
				return Companion_Know_.Create_IsZero_()
			}
			return Companion_Know_.Create_NonZero_()
		})()
		_ = _1_dt__update_hknow_h0
		return Companion_SState_.Create_SState_((_0_dt__update__tmp_h0).Dtor_regs(), (_0_dt__update__tmp_h0).Dtor_stack(), (_0_dt__update__tmp_h0).Dtor_snap(), (_0_dt__update__tmp_h0).Dtor_next(), (_0_dt__update__tmp_h0).Dtor_helpers(), (_0_dt__update__tmp_h0).Dtor_hooks(), (_0_dt__update__tmp_h0).Dtor_ret(), (_0_dt__update__tmp_h0).Dtor_hkey(), _1_dt__update_hknow_h0)
	} else {
		return ss
	}
}
func (_static *CompanionStruct_Default___) Target(pc _dafny.Int, off uint16) _dafny.Int {
	return ((pc).Plus(_dafny.One)).Plus(m_Bits.Companion_Default___.Signed16(off))
}
func (_static *CompanionStruct_Default___) SymExec(prog _dafny.Sequence, sp m_Obligations.Spec, pc _dafny.Int, ss SState, m Mode) Verdict {
	if (pc).Cmp(_dafny.IntOfUint32((prog).Cardinality())) == 0 {
		var _source0 Mode = m
		_ = _source0
		{
			if _source0.Is_Top() {
				if (sp).Dtor_exitMode() {
					return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("hook body falls through"))
				} else {
					return Companion_Default___.Final(sp, ss, pc)
				}
			}
		}
		{
			if _source0.Is_WP() {
				var _0_wprog _dafny.Sequence = _source0.Get_().(Mode_WP).Wprog
				_ = _0_wprog
				if !(_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, (_dafny.IntOfInt64(9)).Plus(_dafny.One)), true, func(_forall_var_0 _dafny.Int) bool {
					var _1_k _dafny.Int
					_1_k = interface{}(_forall_var_0).(_dafny.Int)
					return !((((_1_k).Sign() != -1) && ((_1_k).Cmp(_dafny.IntOfInt64(9)) <= 0)) && ((_1_k).Cmp(_dafny.IntOfInt64(4)) != 0)) || ((((ss).Dtor_regs()).Select((_1_k).Uint32()).(m_Terms.Term)).Equals(m_Terms.Companion_Term_.Create_Entry_(_1_k)))
				})) {
					return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("a register other than r4 changed before call W"))
				} else {
					return Companion_Default___.SymExec(_0_wprog, sp, _dafny.Zero, Companion_Default___.EnterWS(ss), Companion_Mode_.Create_WBody_((ss).Dtor_regs()))
				}
			}
		}
		{
			return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("falls off the end of W"))
		}
	} else {
		var _source1 m_Semantics.Instr = (prog).Select((pc).Uint32()).(m_Semantics.Instr)
		_ = _source1
		{
			if _source1.Is_Exit() {
				var _source2 Mode = m
				_ = _source2
				{
					if _source2.Is_Top() {
						if !((sp).Dtor_exitMode()) {
							return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("exit outside a hook body"))
						} else {
							return Companion_Default___.Final(sp, ss, pc)
						}
					}
				}
				{
					if _source2.Is_WP() {
						return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("exit in WP"))
					}
				}
				{
					var _2_caller _dafny.Sequence = _source2.Get_().(Mode_WBody).Caller
					_ = _2_caller
					if !(((ss).Dtor_regs()).Select(0).(m_Terms.Term)).Equals((ss).Dtor_ret()) {
						return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("W does not return the helper result"))
					} else if (_dafny.IntOfUint32((_2_caller).Cardinality())).Cmp(m_Semantics.Companion_Default___.NREGS()) != 0 {
						return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("internal"))
					} else {
						return Companion_Default___.Final(sp, Companion_Default___.ReturnS(ss, _2_caller), pc)
					}
				}
			}
		}
		{
			if _source1.Is_Ja() {
				var _3_off uint16 = _source1.Get_().(m_Semantics.Instr_Ja).Off
				_ = _3_off
				if ((m_Bits.Companion_Default___.Signed16(_3_off)).Sign() == -1) || ((Companion_Default___.Target(pc, _3_off)).Cmp(_dafny.IntOfUint32((prog).Cardinality())) > 0) {
					return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("jump not forward within the window"))
				} else {
					return Companion_Default___.SymExec(prog, sp, Companion_Default___.Target(pc, _3_off), ss, m)
				}
			}
		}
		{
			if _source1.Is_Jcond() {
				var _4_c m_Semantics.Cond = _source1.Get_().(m_Semantics.Instr_Jcond).Cond
				_ = _4_c
				var _5_dst _dafny.Int = _source1.Get_().(m_Semantics.Instr_Jcond).Dst
				_ = _5_dst
				var _6_imm uint32 = _source1.Get_().(m_Semantics.Instr_Jcond).Imm
				_ = _6_imm
				var _7_off uint16 = _source1.Get_().(m_Semantics.Instr_Jcond).Off
				_ = _7_off
				if (((_5_dst).Cmp(m_Semantics.Companion_Default___.NREGS()) >= 0) || ((m_Bits.Companion_Default___.Signed16(_7_off)).Sign() == -1)) || ((Companion_Default___.Target(pc, _7_off)).Cmp(_dafny.IntOfUint32((prog).Cardinality())) > 0) {
					return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("branch not forward within the window"))
				} else {
					var _8_r Verdict = Companion_Default___.SymExec(prog, sp, (pc).Plus(_dafny.One), Companion_Default___.Refine(ss, _4_c, _5_dst, _6_imm, false), m)
					_ = _8_r
					if (_8_r).Is_NotValidated() {
						return _8_r
					} else {
						return Companion_Default___.SymExec(prog, sp, Companion_Default___.Target(pc, _7_off), Companion_Default___.Refine(ss, _4_c, _5_dst, _6_imm, true), m)
					}
				}
			}
		}
		{
			var _source3 SR = Companion_Default___.SymStep(sp, (prog).Select((pc).Uint32()).(m_Semantics.Instr), ss)
			_ = _source3
			{
				if _source3.Is_SFail() {
					var _9_msg _dafny.Sequence = _source3.Get_().(SR_SFail).Reason
					_ = _9_msg
					return Companion_Verdict_.Create_NotValidated_(pc, _9_msg)
				}
			}
			{
				var _10_ss_k SState = _source3.Get_().(SR_SOk).Ss
				_ = _10_ss_k
				if !(Companion_Default___.SWF(_10_ss_k)) {
					return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("internal"))
				} else if (((prog).Select((pc).Uint32()).(m_Semantics.Instr)).Is_CallLocal()) && (!_dafny.Companion_Sequence_.Equal(Companion_Default___.BindFail(sp, pc, ss), _dafny.UnicodeSeqOfUtf8Bytes(""))) {
					return Companion_Verdict_.Create_NotValidated_(pc, Companion_Default___.BindFail(sp, pc, ss))
				} else {
					return Companion_Default___.SymExec(prog, sp, (pc).Plus(_dafny.One), _10_ss_k, m)
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecodeFrom(raw _dafny.Sequence, i _dafny.Int) DR {
	if (i).Cmp(m_Semantics.Companion_Default___.NumInsns(raw)) == 0 {
		return Companion_DR_.Create_DOk_(_dafny.SeqOf())
	} else {
		var _source0 m_Bits.Option = m_Semantics.Companion_Default___.Decode(m_Semantics.Companion_Default___.InsnAt(raw, i))
		_ = _source0
		{
			if _source0.Is_None() {
				return Companion_DR_.Create_DBad_(i)
			}
		}
		{
			var _0_ins m_Semantics.Instr = _source0.Get_().(m_Bits.Option_Some).Value.(m_Semantics.Instr)
			_ = _0_ins
			var _source1 DR = Companion_Default___.DecodeFrom(raw, (i).Plus(_dafny.One))
			_ = _source1
			{
				if _source1.Is_DBad() {
					var _1_p _dafny.Int = _source1.Get_().(DR_DBad).Pc
					_ = _1_p
					return Companion_DR_.Create_DBad_(_1_p)
				}
			}
			{
				var _2_rest _dafny.Sequence = _source1.Get_().(DR_DOk).Prog
				_ = _2_rest
				return Companion_DR_.Create_DOk_(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(_0_ins), _2_rest))
			}
		}
	}
}
func (_static *CompanionStruct_Default___) CountBranches(prog _dafny.Sequence) _dafny.Int {
	var _0___accumulator _dafny.Int = _dafny.Zero
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((prog).Cardinality())).Sign() == 0 {
		return (_dafny.Zero).Plus(_0___accumulator)
	} else {
		_0___accumulator = (_0___accumulator).Plus((func() _dafny.Int {
			if ((prog).Select(0).(m_Semantics.Instr)).Is_Jcond() {
				return _dafny.One
			}
			return _dafny.Zero
		})())
		var _in0 _dafny.Sequence = (prog).Drop(1)
		_ = _in0
		prog = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) CountHelperCalls(prog _dafny.Sequence) _dafny.Int {
	var _0___accumulator _dafny.Int = _dafny.Zero
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((prog).Cardinality())).Sign() == 0 {
		return (_dafny.Zero).Plus(_0___accumulator)
	} else {
		_0___accumulator = (_0___accumulator).Plus((func() _dafny.Int {
			if ((prog).Select(0).(m_Semantics.Instr)).Is_CallHelper() {
				return _dafny.One
			}
			return _dafny.Zero
		})())
		var _in0 _dafny.Sequence = (prog).Drop(1)
		_ = _in0
		prog = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) Validate(raw _dafny.Sequence, sp m_Obligations.Spec) Verdict {
	if !(m_Obligations.Companion_Default___.SpecWF(sp)) {
		return Companion_Verdict_.Create_NotValidated_(_dafny.IntOfInt64(-1), _dafny.UnicodeSeqOfUtf8Bytes("bad window parameters"))
	} else if ((_dafny.IntOfUint32((raw).Cardinality())).Modulo(_dafny.IntOfInt64(8))).Sign() != 0 {
		return Companion_Verdict_.Create_NotValidated_(_dafny.IntOfInt64(-1), _dafny.UnicodeSeqOfUtf8Bytes("length not a multiple of 8"))
	} else if (m_Semantics.Companion_Default___.NumInsns(raw)).Cmp(Companion_Default___.MAX__INSNS()) > 0 {
		return Companion_Verdict_.Create_NotValidated_(_dafny.IntOfInt64(-1), _dafny.UnicodeSeqOfUtf8Bytes("window too long"))
	} else {
		var _source0 DR = Companion_Default___.DecodeFrom(raw, _dafny.Zero)
		_ = _source0
		{
			if _source0.Is_DBad() {
				var _0_p _dafny.Int = _source0.Get_().(DR_DBad).Pc
				_ = _0_p
				return Companion_Verdict_.Create_NotValidated_(_0_p, _dafny.UnicodeSeqOfUtf8Bytes("instruction outside the allowlist"))
			}
		}
		{
			var _1_prog _dafny.Sequence = _source0.Get_().(DR_DOk).Prog
			_ = _1_prog
			if ((sp).Dtor_wrap()).Is_Wrap() {
				return Companion_Default___.ValidateWrap(_1_prog, sp)
			} else if (Companion_Default___.CountBranches(_1_prog)).Cmp(Companion_Default___.MAX__BRANCHES()) > 0 {
				return Companion_Verdict_.Create_NotValidated_(_dafny.IntOfInt64(-1), _dafny.UnicodeSeqOfUtf8Bytes("too many branches"))
			} else {
				return Companion_Default___.SymExec(_1_prog, sp, _dafny.Zero, Companion_Default___.SInit(), Companion_Mode_.Create_Top_())
			}
		}
	}
}
func (_static *CompanionStruct_Default___) ValidateWrap(prog _dafny.Sequence, sp m_Obligations.Spec) Verdict {
	var _0_n _dafny.Int = _dafny.IntOfUint32((prog).Cardinality())
	_ = _0_n
	var _1_body _dafny.Sequence = ((sp).Dtor_wrap()).Dtor_body()
	_ = _1_body
	if ((_0_n).Sign() == 0) || (!(((prog).Select(((_0_n).Minus(_dafny.One)).Uint32()).(m_Semantics.Instr)).Is_CallLocal())) {
		return Companion_Verdict_.Create_NotValidated_(_dafny.IntOfInt64(-1), _dafny.UnicodeSeqOfUtf8Bytes("P8 window does not end in call W"))
	} else if !(_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, (_0_n).Minus(_dafny.One)), true, func(_forall_var_0 _dafny.Int) bool {
		var _2_j _dafny.Int
		_2_j = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_2_j).Sign() != -1) && ((_2_j).Cmp((_0_n).Minus(_dafny.One)) < 0)) || ((m_Semantics.Companion_Default___.Writes((prog).Select((_2_j).Uint32()).(m_Semantics.Instr))).IsSubsetOf(_dafny.SetOf(_dafny.IntOfInt64(4))))
	})) {
		return Companion_Verdict_.Create_NotValidated_(_dafny.IntOfInt64(-1), _dafny.UnicodeSeqOfUtf8Bytes("WP writes a register other than r4"))
	} else if (((_dafny.IntOfUint32((_1_body).Cardinality())).Modulo(_dafny.IntOfInt64(8))).Sign() != 0) || ((m_Semantics.Companion_Default___.NumInsns(_1_body)).Cmp(Companion_Default___.MAX__INSNS()) > 0) {
		return Companion_Verdict_.Create_NotValidated_(_dafny.IntOfInt64(-1), _dafny.UnicodeSeqOfUtf8Bytes("bad W body"))
	} else {
		var _source0 DR = Companion_Default___.DecodeFrom(_1_body, _dafny.Zero)
		_ = _source0
		{
			if _source0.Is_DBad() {
				var _3_p _dafny.Int = _source0.Get_().(DR_DBad).Pc
				_ = _3_p
				return Companion_Verdict_.Create_NotValidated_(_3_p, _dafny.UnicodeSeqOfUtf8Bytes("W instruction outside the allowlist"))
			}
		}
		{
			var _4_wprog _dafny.Sequence = _source0.Get_().(DR_DOk).Prog
			_ = _4_wprog
			if !(_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((_4_wprog).Cardinality())), true, func(_forall_var_1 _dafny.Int) bool {
				var _5_j _dafny.Int
				_5_j = interface{}(_forall_var_1).(_dafny.Int)
				return !(((_5_j).Sign() != -1) && ((_5_j).Cmp(_dafny.IntOfUint32((_4_wprog).Cardinality())) < 0)) || (m_Obligations.Companion_Default___.WInsnOk((_4_wprog).Select((_5_j).Uint32()).(m_Semantics.Instr), sp))
			})) {
				return Companion_Verdict_.Create_NotValidated_(_dafny.IntOfInt64(-1), _dafny.UnicodeSeqOfUtf8Bytes("W names r10 or calls a helper other than O[i]"))
			} else if (Companion_Default___.CountHelperCalls(_4_wprog)).Cmp(_dafny.One) != 0 {
				return Companion_Verdict_.Create_NotValidated_(_dafny.IntOfInt64(-1), _dafny.UnicodeSeqOfUtf8Bytes("W does not contain exactly one helper call (rule P8)"))
			} else if ((Companion_Default___.CountBranches(prog)).Plus(Companion_Default___.CountBranches(_4_wprog))).Cmp(Companion_Default___.MAX__BRANCHES()) > 0 {
				return Companion_Verdict_.Create_NotValidated_(_dafny.IntOfInt64(-1), _dafny.UnicodeSeqOfUtf8Bytes("too many branches"))
			} else {
				return Companion_Default___.SymExec((prog).Take(((_0_n).Minus(_dafny.One)).Uint32()), sp, _dafny.Zero, Companion_Default___.SInit(), Companion_Mode_.Create_WP_(_4_wprog))
			}
		}
	}
}
func (_static *CompanionStruct_Default___) MAX__INSNS() _dafny.Int {
	return _dafny.IntOfInt64(4096)
}
func (_static *CompanionStruct_Default___) MAX__BRANCHES() _dafny.Int {
	return _dafny.IntOfInt64(10)
}

// End of class Default__

// Definition of datatype Know
type Know struct {
	Data_Know_
}

func (_this Know) Get_() Data_Know_ {
	return _this.Data_Know_
}

type Data_Know_ interface {
	isKnow()
}

type CompanionStruct_Know_ struct {
}

var Companion_Know_ = CompanionStruct_Know_{}

type Know_Unknown struct {
}

func (Know_Unknown) isKnow() {}

func (CompanionStruct_Know_) Create_Unknown_() Know {
	return Know{Know_Unknown{}}
}

func (_this Know) Is_Unknown() bool {
	_, ok := _this.Get_().(Know_Unknown)
	return ok
}

type Know_IsZero struct {
}

func (Know_IsZero) isKnow() {}

func (CompanionStruct_Know_) Create_IsZero_() Know {
	return Know{Know_IsZero{}}
}

func (_this Know) Is_IsZero() bool {
	_, ok := _this.Get_().(Know_IsZero)
	return ok
}

type Know_NonZero struct {
}

func (Know_NonZero) isKnow() {}

func (CompanionStruct_Know_) Create_NonZero_() Know {
	return Know{Know_NonZero{}}
}

func (_this Know) Is_NonZero() bool {
	_, ok := _this.Get_().(Know_NonZero)
	return ok
}

func (CompanionStruct_Know_) Default() Know {
	return Companion_Know_.Create_Unknown_()
}

func (_ CompanionStruct_Know_) AllSingletonConstructors() _dafny.Iterator {
	i := -1
	return func() (interface{}, bool) {
		i++
		switch i {
		case 0:
			return Companion_Know_.Create_Unknown_(), true
		case 1:
			return Companion_Know_.Create_IsZero_(), true
		case 2:
			return Companion_Know_.Create_NonZero_(), true
		default:
			return Know{}, false
		}
	}
}

func (_this Know) String() string {
	switch _this.Get_().(type) {
	case nil:
		return "null"
	case Know_Unknown:
		{
			return "Checker.Know.Unknown"
		}
	case Know_IsZero:
		{
			return "Checker.Know.IsZero"
		}
	case Know_NonZero:
		{
			return "Checker.Know.NonZero"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Know) Equals(other Know) bool {
	switch _this.Get_().(type) {
	case Know_Unknown:
		{
			_, ok := other.Get_().(Know_Unknown)
			return ok
		}
	case Know_IsZero:
		{
			_, ok := other.Get_().(Know_IsZero)
			return ok
		}
	case Know_NonZero:
		{
			_, ok := other.Get_().(Know_NonZero)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Know) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Know)
	return ok && _this.Equals(typed)
}

func Type_Know_() _dafny.TypeDescriptor {
	return type_Know_{}
}

type type_Know_ struct {
}

func (_this type_Know_) Default() interface{} {
	return Companion_Know_.Default()
}

func (_this type_Know_) String() string {
	return "Checker.Know"
}
func (_this Know) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Know{}

// End of datatype Know

// Definition of datatype SState
type SState struct {
	Data_SState_
}

func (_this SState) Get_() Data_SState_ {
	return _this.Data_SState_
}

type Data_SState_ interface {
	isSState()
}

type CompanionStruct_SState_ struct {
}

var Companion_SState_ = CompanionStruct_SState_{}

type SState_SState struct {
	Regs    _dafny.Sequence
	Stack   _dafny.Sequence
	Snap    _dafny.Sequence
	Next    _dafny.Int
	Helpers _dafny.Int
	Hooks   _dafny.Int
	Ret     m_Terms.Term
	Hkey    m_Terms.Term
	Know    Know
}

func (SState_SState) isSState() {}

func (CompanionStruct_SState_) Create_SState_(Regs _dafny.Sequence, Stack _dafny.Sequence, Snap _dafny.Sequence, Next _dafny.Int, Helpers _dafny.Int, Hooks _dafny.Int, Ret m_Terms.Term, Hkey m_Terms.Term, Know Know) SState {
	return SState{SState_SState{Regs, Stack, Snap, Next, Helpers, Hooks, Ret, Hkey, Know}}
}

func (_this SState) Is_SState() bool {
	_, ok := _this.Get_().(SState_SState)
	return ok
}

func (CompanionStruct_SState_) Default() SState {
	return Companion_SState_.Create_SState_(_dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, _dafny.Zero, _dafny.Zero, _dafny.Zero, m_Terms.Companion_Term_.Default(), m_Terms.Companion_Term_.Default(), Companion_Know_.Default())
}

func (_this SState) Dtor_regs() _dafny.Sequence {
	return _this.Get_().(SState_SState).Regs
}

func (_this SState) Dtor_stack() _dafny.Sequence {
	return _this.Get_().(SState_SState).Stack
}

func (_this SState) Dtor_snap() _dafny.Sequence {
	return _this.Get_().(SState_SState).Snap
}

func (_this SState) Dtor_next() _dafny.Int {
	return _this.Get_().(SState_SState).Next
}

func (_this SState) Dtor_helpers() _dafny.Int {
	return _this.Get_().(SState_SState).Helpers
}

func (_this SState) Dtor_hooks() _dafny.Int {
	return _this.Get_().(SState_SState).Hooks
}

func (_this SState) Dtor_ret() m_Terms.Term {
	return _this.Get_().(SState_SState).Ret
}

func (_this SState) Dtor_hkey() m_Terms.Term {
	return _this.Get_().(SState_SState).Hkey
}

func (_this SState) Dtor_know() Know {
	return _this.Get_().(SState_SState).Know
}

func (_this SState) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case SState_SState:
		{
			return "Checker.SState.SState" + "(" + _dafny.String(data.Regs) + ", " + _dafny.String(data.Stack) + ", " + _dafny.String(data.Snap) + ", " + _dafny.String(data.Next) + ", " + _dafny.String(data.Helpers) + ", " + _dafny.String(data.Hooks) + ", " + _dafny.String(data.Ret) + ", " + _dafny.String(data.Hkey) + ", " + _dafny.String(data.Know) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this SState) Equals(other SState) bool {
	switch data1 := _this.Get_().(type) {
	case SState_SState:
		{
			data2, ok := other.Get_().(SState_SState)
			return ok && data1.Regs.Equals(data2.Regs) && data1.Stack.Equals(data2.Stack) && data1.Snap.Equals(data2.Snap) && data1.Next.Cmp(data2.Next) == 0 && data1.Helpers.Cmp(data2.Helpers) == 0 && data1.Hooks.Cmp(data2.Hooks) == 0 && data1.Ret.Equals(data2.Ret) && data1.Hkey.Equals(data2.Hkey) && data1.Know.Equals(data2.Know)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this SState) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(SState)
	return ok && _this.Equals(typed)
}

func Type_SState_() _dafny.TypeDescriptor {
	return type_SState_{}
}

type type_SState_ struct {
}

func (_this type_SState_) Default() interface{} {
	return Companion_SState_.Default()
}

func (_this type_SState_) String() string {
	return "Checker.SState"
}
func (_this SState) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = SState{}

// End of datatype SState

// Definition of datatype Verdict
type Verdict struct {
	Data_Verdict_
}

func (_this Verdict) Get_() Data_Verdict_ {
	return _this.Data_Verdict_
}

type Data_Verdict_ interface {
	isVerdict()
}

type CompanionStruct_Verdict_ struct {
}

var Companion_Verdict_ = CompanionStruct_Verdict_{}

type Verdict_Validated struct {
}

func (Verdict_Validated) isVerdict() {}

func (CompanionStruct_Verdict_) Create_Validated_() Verdict {
	return Verdict{Verdict_Validated{}}
}

func (_this Verdict) Is_Validated() bool {
	_, ok := _this.Get_().(Verdict_Validated)
	return ok
}

type Verdict_NotValidated struct {
	Pc     _dafny.Int
	Reason _dafny.Sequence
}

func (Verdict_NotValidated) isVerdict() {}

func (CompanionStruct_Verdict_) Create_NotValidated_(Pc _dafny.Int, Reason _dafny.Sequence) Verdict {
	return Verdict{Verdict_NotValidated{Pc, Reason}}
}

func (_this Verdict) Is_NotValidated() bool {
	_, ok := _this.Get_().(Verdict_NotValidated)
	return ok
}

func (CompanionStruct_Verdict_) Default() Verdict {
	return Companion_Verdict_.Create_Validated_()
}

func (_this Verdict) Dtor_pc() _dafny.Int {
	return _this.Get_().(Verdict_NotValidated).Pc
}

func (_this Verdict) Dtor_reason() _dafny.Sequence {
	return _this.Get_().(Verdict_NotValidated).Reason
}

func (_this Verdict) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Verdict_Validated:
		{
			return "Checker.Verdict.Validated"
		}
	case Verdict_NotValidated:
		{
			return "Checker.Verdict.NotValidated" + "(" + _dafny.String(data.Pc) + ", " + data.Reason.VerbatimString(true) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Verdict) Equals(other Verdict) bool {
	switch data1 := _this.Get_().(type) {
	case Verdict_Validated:
		{
			_, ok := other.Get_().(Verdict_Validated)
			return ok
		}
	case Verdict_NotValidated:
		{
			data2, ok := other.Get_().(Verdict_NotValidated)
			return ok && data1.Pc.Cmp(data2.Pc) == 0 && data1.Reason.Equals(data2.Reason)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Verdict) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Verdict)
	return ok && _this.Equals(typed)
}

func Type_Verdict_() _dafny.TypeDescriptor {
	return type_Verdict_{}
}

type type_Verdict_ struct {
}

func (_this type_Verdict_) Default() interface{} {
	return Companion_Verdict_.Default()
}

func (_this type_Verdict_) String() string {
	return "Checker.Verdict"
}
func (_this Verdict) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Verdict{}

// End of datatype Verdict

// Definition of datatype SR
type SR struct {
	Data_SR_
}

func (_this SR) Get_() Data_SR_ {
	return _this.Data_SR_
}

type Data_SR_ interface {
	isSR()
}

type CompanionStruct_SR_ struct {
}

var Companion_SR_ = CompanionStruct_SR_{}

type SR_SOk struct {
	Ss SState
}

func (SR_SOk) isSR() {}

func (CompanionStruct_SR_) Create_SOk_(Ss SState) SR {
	return SR{SR_SOk{Ss}}
}

func (_this SR) Is_SOk() bool {
	_, ok := _this.Get_().(SR_SOk)
	return ok
}

type SR_SFail struct {
	Reason _dafny.Sequence
}

func (SR_SFail) isSR() {}

func (CompanionStruct_SR_) Create_SFail_(Reason _dafny.Sequence) SR {
	return SR{SR_SFail{Reason}}
}

func (_this SR) Is_SFail() bool {
	_, ok := _this.Get_().(SR_SFail)
	return ok
}

func (CompanionStruct_SR_) Default() SR {
	return Companion_SR_.Create_SOk_(Companion_SState_.Default())
}

func (_this SR) Dtor_ss() SState {
	return _this.Get_().(SR_SOk).Ss
}

func (_this SR) Dtor_reason() _dafny.Sequence {
	return _this.Get_().(SR_SFail).Reason
}

func (_this SR) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case SR_SOk:
		{
			return "Checker.SR.SOk" + "(" + _dafny.String(data.Ss) + ")"
		}
	case SR_SFail:
		{
			return "Checker.SR.SFail" + "(" + data.Reason.VerbatimString(true) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this SR) Equals(other SR) bool {
	switch data1 := _this.Get_().(type) {
	case SR_SOk:
		{
			data2, ok := other.Get_().(SR_SOk)
			return ok && data1.Ss.Equals(data2.Ss)
		}
	case SR_SFail:
		{
			data2, ok := other.Get_().(SR_SFail)
			return ok && data1.Reason.Equals(data2.Reason)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this SR) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(SR)
	return ok && _this.Equals(typed)
}

func Type_SR_() _dafny.TypeDescriptor {
	return type_SR_{}
}

type type_SR_ struct {
}

func (_this type_SR_) Default() interface{} {
	return Companion_SR_.Default()
}

func (_this type_SR_) String() string {
	return "Checker.SR"
}
func (_this SR) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = SR{}

// End of datatype SR

// Definition of datatype Mode
type Mode struct {
	Data_Mode_
}

func (_this Mode) Get_() Data_Mode_ {
	return _this.Data_Mode_
}

type Data_Mode_ interface {
	isMode()
}

type CompanionStruct_Mode_ struct {
}

var Companion_Mode_ = CompanionStruct_Mode_{}

type Mode_Top struct {
}

func (Mode_Top) isMode() {}

func (CompanionStruct_Mode_) Create_Top_() Mode {
	return Mode{Mode_Top{}}
}

func (_this Mode) Is_Top() bool {
	_, ok := _this.Get_().(Mode_Top)
	return ok
}

type Mode_WP struct {
	Wprog _dafny.Sequence
}

func (Mode_WP) isMode() {}

func (CompanionStruct_Mode_) Create_WP_(Wprog _dafny.Sequence) Mode {
	return Mode{Mode_WP{Wprog}}
}

func (_this Mode) Is_WP() bool {
	_, ok := _this.Get_().(Mode_WP)
	return ok
}

type Mode_WBody struct {
	Caller _dafny.Sequence
}

func (Mode_WBody) isMode() {}

func (CompanionStruct_Mode_) Create_WBody_(Caller _dafny.Sequence) Mode {
	return Mode{Mode_WBody{Caller}}
}

func (_this Mode) Is_WBody() bool {
	_, ok := _this.Get_().(Mode_WBody)
	return ok
}

func (CompanionStruct_Mode_) Default() Mode {
	return Companion_Mode_.Create_Top_()
}

func (_this Mode) Dtor_wprog() _dafny.Sequence {
	return _this.Get_().(Mode_WP).Wprog
}

func (_this Mode) Dtor_caller() _dafny.Sequence {
	return _this.Get_().(Mode_WBody).Caller
}

func (_this Mode) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Mode_Top:
		{
			return "Checker.Mode.Top"
		}
	case Mode_WP:
		{
			return "Checker.Mode.WP" + "(" + _dafny.String(data.Wprog) + ")"
		}
	case Mode_WBody:
		{
			return "Checker.Mode.WBody" + "(" + _dafny.String(data.Caller) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Mode) Equals(other Mode) bool {
	switch data1 := _this.Get_().(type) {
	case Mode_Top:
		{
			_, ok := other.Get_().(Mode_Top)
			return ok
		}
	case Mode_WP:
		{
			data2, ok := other.Get_().(Mode_WP)
			return ok && data1.Wprog.Equals(data2.Wprog)
		}
	case Mode_WBody:
		{
			data2, ok := other.Get_().(Mode_WBody)
			return ok && data1.Caller.Equals(data2.Caller)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Mode) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Mode)
	return ok && _this.Equals(typed)
}

func Type_Mode_() _dafny.TypeDescriptor {
	return type_Mode_{}
}

type type_Mode_ struct {
}

func (_this type_Mode_) Default() interface{} {
	return Companion_Mode_.Default()
}

func (_this type_Mode_) String() string {
	return "Checker.Mode"
}
func (_this Mode) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Mode{}

// End of datatype Mode

// Definition of datatype DR
type DR struct {
	Data_DR_
}

func (_this DR) Get_() Data_DR_ {
	return _this.Data_DR_
}

type Data_DR_ interface {
	isDR()
}

type CompanionStruct_DR_ struct {
}

var Companion_DR_ = CompanionStruct_DR_{}

type DR_DOk struct {
	Prog _dafny.Sequence
}

func (DR_DOk) isDR() {}

func (CompanionStruct_DR_) Create_DOk_(Prog _dafny.Sequence) DR {
	return DR{DR_DOk{Prog}}
}

func (_this DR) Is_DOk() bool {
	_, ok := _this.Get_().(DR_DOk)
	return ok
}

type DR_DBad struct {
	Pc _dafny.Int
}

func (DR_DBad) isDR() {}

func (CompanionStruct_DR_) Create_DBad_(Pc _dafny.Int) DR {
	return DR{DR_DBad{Pc}}
}

func (_this DR) Is_DBad() bool {
	_, ok := _this.Get_().(DR_DBad)
	return ok
}

func (CompanionStruct_DR_) Default() DR {
	return Companion_DR_.Create_DOk_(_dafny.EmptySeq)
}

func (_this DR) Dtor_prog() _dafny.Sequence {
	return _this.Get_().(DR_DOk).Prog
}

func (_this DR) Dtor_pc() _dafny.Int {
	return _this.Get_().(DR_DBad).Pc
}

func (_this DR) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case DR_DOk:
		{
			return "Checker.DR.DOk" + "(" + _dafny.String(data.Prog) + ")"
		}
	case DR_DBad:
		{
			return "Checker.DR.DBad" + "(" + _dafny.String(data.Pc) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this DR) Equals(other DR) bool {
	switch data1 := _this.Get_().(type) {
	case DR_DOk:
		{
			data2, ok := other.Get_().(DR_DOk)
			return ok && data1.Prog.Equals(data2.Prog)
		}
	case DR_DBad:
		{
			data2, ok := other.Get_().(DR_DBad)
			return ok && data1.Pc.Cmp(data2.Pc) == 0
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this DR) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(DR)
	return ok && _this.Equals(typed)
}

func Type_DR_() _dafny.TypeDescriptor {
	return type_DR_{}
}

type type_DR_ struct {
}

func (_this type_DR_) Default() interface{} {
	return Companion_DR_.Default()
}

func (_this type_DR_) String() string {
	return "Checker.DR"
}
func (_this DR) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = DR{}

// End of datatype DR
