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
	var _0_st _dafny.Sequence = _dafny.SeqCreate((m_Semantics.Companion_Default___.STACK()).Uint32(), func(coer5 func(_dafny.Int) m_Terms.BTerm) func(_dafny.Int) interface{} {
		return func(arg5 _dafny.Int) interface{} {
			return coer5(arg5)
		}
	}(func(_1_i _dafny.Int) m_Terms.BTerm {
		return m_Terms.Companion_BTerm_.Create_BEntry_(_1_i)
	}))
	_ = _0_st
	return Companion_SState_.Create_SState_(_dafny.SeqCreate((m_Semantics.Companion_Default___.NREGS()).Uint32(), func(coer6 func(_dafny.Int) m_Terms.Term) func(_dafny.Int) interface{} {
		return func(arg6 _dafny.Int) interface{} {
			return coer6(arg6)
		}
	}(func(_2_k _dafny.Int) m_Terms.Term {
		return m_Terms.Companion_Term_.Create_Entry_(_2_k)
	})), _0_st, _0_st, _dafny.Zero, _dafny.Zero, _dafny.Zero, m_Terms.Companion_Term_.Create_Const_(uint64(0)))
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
	return _dafny.SeqCreate((m_Semantics.Companion_Default___.NREGS()).Uint32(), func(coer7 func(_dafny.Int) m_Terms.Term) func(_dafny.Int) interface{} {
		return func(arg7 _dafny.Int) interface{} {
			return coer7(arg7)
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
	return _dafny.SeqCreate((_dafny.IntOfUint32((st).Cardinality())).Uint32(), func(coer8 func(_dafny.Int) m_Terms.BTerm) func(_dafny.Int) interface{} {
		return func(arg8 _dafny.Int) interface{} {
			return coer8(arg8)
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
	return _dafny.SeqCreate((w).Uint32(), func(coer9 func(_dafny.Int) m_Terms.BTerm) func(_dafny.Int) interface{} {
		return func(arg9 _dafny.Int) interface{} {
			return coer9(arg9)
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
				return Companion_SR_.Create_SOk_(func(_pat_let29_0 SState) SState {
					return func(_2_dt__update__tmp_h0 SState) SState {
						return func(_pat_let30_0 _dafny.Sequence) SState {
							return func(_3_dt__update_hstack_h0 _dafny.Sequence) SState {
								return Companion_SState_.Create_SState_((_2_dt__update__tmp_h0).Dtor_regs(), _3_dt__update_hstack_h0, (_2_dt__update__tmp_h0).Dtor_snap(), (_2_dt__update__tmp_h0).Dtor_next(), (_2_dt__update__tmp_h0).Dtor_helpers(), (_2_dt__update__tmp_h0).Dtor_hooks(), (_2_dt__update__tmp_h0).Dtor_ret())
							}(_pat_let30_0)
						}(Companion_Default___.WriteBT((_pat_let_tv0).Dtor_stack(), (_1_o).Plus(m_Semantics.Companion_Default___.STACK()), Companion_Default___.StoreBytes(_pat_let_tv1, _pat_let_tv2)))
					}(_pat_let29_0)
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
				return Companion_SR_.Create_SOk_(func(_pat_let31_0 SState) SState {
					return func(_4_dt__update__tmp_h0 SState) SState {
						return func(_pat_let32_0 _dafny.Sequence) SState {
							return func(_5_dt__update_hregs_h0 _dafny.Sequence) SState {
								return Companion_SState_.Create_SState_(_5_dt__update_hregs_h0, (_4_dt__update__tmp_h0).Dtor_stack(), (_4_dt__update__tmp_h0).Dtor_snap(), (_4_dt__update__tmp_h0).Dtor_next(), (_4_dt__update__tmp_h0).Dtor_helpers(), (_4_dt__update__tmp_h0).Dtor_hooks(), (_4_dt__update__tmp_h0).Dtor_ret())
							}(_pat_let32_0)
						}(_dafny.Companion_Sequence_.Update((_pat_let_tv0).Dtor_regs(), (_2_dst).Uint32(), Companion_Default___.AluTerm(_0_is64, _1_op, ((_pat_let_tv1).Dtor_regs()).Select((_2_dst).Uint32()).(m_Terms.Term), Companion_Default___.SymOperand(_0_is64, _3_opnd, (_pat_let_tv2).Dtor_regs()))))
					}(_pat_let31_0)
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
				return Companion_SR_.Create_SOk_(func(_pat_let33_0 SState) SState {
					return func(_12_dt__update__tmp_h1 SState) SState {
						return func(_pat_let34_0 _dafny.Int) SState {
							return func(_13_dt__update_hnext_h0 _dafny.Int) SState {
								return func(_pat_let35_0 _dafny.Sequence) SState {
									return func(_14_dt__update_hregs_h1 _dafny.Sequence) SState {
										return Companion_SState_.Create_SState_(_14_dt__update_hregs_h1, (_12_dt__update__tmp_h1).Dtor_stack(), (_12_dt__update__tmp_h1).Dtor_snap(), _13_dt__update_hnext_h0, (_12_dt__update__tmp_h1).Dtor_helpers(), (_12_dt__update__tmp_h1).Dtor_hooks(), (_12_dt__update__tmp_h1).Dtor_ret())
									}(_pat_let35_0)
								}(_dafny.Companion_Sequence_.Update((_pat_let_tv4).Dtor_regs(), (_7_dst).Uint32(), _10_v))
							}(_pat_let34_0)
						}(((_pat_let_tv3).Dtor_next()).Plus(_dafny.One))
					}(_pat_let33_0)
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
			if !(((sp).Dtor_helper()).Is_Helper()) {
				return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("helper call outside a site window"))
			} else if ((ss).Dtor_helpers()).Sign() != 0 {
				return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("second helper call on a path"))
			} else if (((sp).Dtor_helper()).Dtor_checkArgs()) && (!_dafny.Companion_Sequence_.Equal(((ss).Dtor_regs()).Subsequence(1, 6), _dafny.SeqOf(m_Terms.Companion_Term_.Create_Entry_(_dafny.One), m_Terms.Companion_Term_.Create_Entry_(_dafny.IntOfInt64(2)), m_Terms.Companion_Term_.Create_Entry_(_dafny.IntOfInt64(3)), m_Terms.Companion_Term_.Create_Entry_(_dafny.IntOfInt64(4)), m_Terms.Companion_Term_.Create_Entry_(_dafny.IntOfInt64(5))))) {
				return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("r1-r5 changed before the helper call"))
			} else {
				var _23_lo _dafny.Int = (m_Semantics.Companion_Default___.STACK()).Plus((sp).Dtor_floor())
				_ = _23_lo
				var _24_st _dafny.Sequence = _dafny.SeqCreate((m_Semantics.Companion_Default___.STACK()).Uint32(), func(coer10 func(_dafny.Int) m_Terms.BTerm) func(_dafny.Int) interface{} {
					return func(arg10 _dafny.Int) interface{} {
						return coer10(arg10)
					}
				}((func(_25_lo _dafny.Int, _26_ss SState) func(_dafny.Int) m_Terms.BTerm {
					return func(_27_i _dafny.Int) m_Terms.BTerm {
						return (func() m_Terms.BTerm {
							if (_27_i).Cmp(_25_lo) >= 0 {
								return m_Terms.Companion_BTerm_.Create_BOf_(m_Terms.Companion_Term_.Create_Fresh_((((_26_ss).Dtor_next()).Plus(_dafny.IntOfInt64(6))).Plus((_27_i).Minus(_25_lo))), _dafny.Zero)
							}
							return ((_26_ss).Dtor_stack()).Select((_27_i).Uint32()).(m_Terms.BTerm)
						})()
					}
				})(_23_lo, ss)))
				_ = _24_st
				return Companion_SR_.Create_SOk_(Companion_SState_.Create_SState_(Companion_Default___.FreshRegs((ss).Dtor_regs(), (ss).Dtor_next()), _24_st, _24_st, (((ss).Dtor_next()).Plus(_dafny.IntOfInt64(6))).Plus((_dafny.Zero).Minus((sp).Dtor_floor())), _dafny.One, (ss).Dtor_hooks(), m_Terms.Companion_Term_.Create_Fresh_((ss).Dtor_next())))
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
				return Companion_SR_.Create_SOk_(func(_pat_let36_0 SState) SState {
					return func(_28_dt__update__tmp_h2 SState) SState {
						return func(_pat_let37_0 _dafny.Int) SState {
							return func(_29_dt__update_hhooks_h0 _dafny.Int) SState {
								return func(_pat_let38_0 _dafny.Int) SState {
									return func(_30_dt__update_hnext_h1 _dafny.Int) SState {
										return func(_pat_let39_0 _dafny.Sequence) SState {
											return func(_31_dt__update_hregs_h2 _dafny.Sequence) SState {
												return Companion_SState_.Create_SState_(_31_dt__update_hregs_h2, (_28_dt__update__tmp_h2).Dtor_stack(), (_28_dt__update__tmp_h2).Dtor_snap(), _30_dt__update_hnext_h1, (_28_dt__update__tmp_h2).Dtor_helpers(), _29_dt__update_hhooks_h0, (_28_dt__update__tmp_h2).Dtor_ret())
											}(_pat_let39_0)
										}(Companion_Default___.FreshRegs((_pat_let_tv6).Dtor_regs(), (_pat_let_tv7).Dtor_next()))
									}(_pat_let38_0)
								}(((_pat_let_tv5).Dtor_next()).Plus(_dafny.IntOfInt64(6)))
							}(_pat_let37_0)
						}(_dafny.One)
					}(_pat_let36_0)
				}(ss))
			}
		}
	}
	{
		return Companion_SR_.Create_SFail_(_dafny.UnicodeSeqOfUtf8Bytes("control instruction"))
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
func (_static *CompanionStruct_Default___) Target(pc _dafny.Int, off uint16) _dafny.Int {
	return ((pc).Plus(_dafny.One)).Plus(m_Bits.Companion_Default___.Signed16(off))
}
func (_static *CompanionStruct_Default___) SymExec(prog _dafny.Sequence, sp m_Obligations.Spec, pc _dafny.Int, ss SState) Verdict {
	if (pc).Cmp(_dafny.IntOfUint32((prog).Cardinality())) == 0 {
		if (sp).Dtor_exitMode() {
			return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("hook body falls through"))
		} else {
			return Companion_Default___.Final(sp, ss, pc)
		}
	} else {
		var _source0 m_Semantics.Instr = (prog).Select((pc).Uint32()).(m_Semantics.Instr)
		_ = _source0
		{
			if _source0.Is_Exit() {
				if !((sp).Dtor_exitMode()) {
					return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("exit outside a hook body"))
				} else {
					return Companion_Default___.Final(sp, ss, pc)
				}
			}
		}
		{
			if _source0.Is_Ja() {
				var _0_off uint16 = _source0.Get_().(m_Semantics.Instr_Ja).Off
				_ = _0_off
				if ((m_Bits.Companion_Default___.Signed16(_0_off)).Sign() == -1) || ((Companion_Default___.Target(pc, _0_off)).Cmp(_dafny.IntOfUint32((prog).Cardinality())) > 0) {
					return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("jump not forward within the window"))
				} else {
					return Companion_Default___.SymExec(prog, sp, Companion_Default___.Target(pc, _0_off), ss)
				}
			}
		}
		{
			if _source0.Is_Jcond() {
				var _1_dst _dafny.Int = _source0.Get_().(m_Semantics.Instr_Jcond).Dst
				_ = _1_dst
				var _2_off uint16 = _source0.Get_().(m_Semantics.Instr_Jcond).Off
				_ = _2_off
				if (((_1_dst).Cmp(m_Semantics.Companion_Default___.NREGS()) >= 0) || ((m_Bits.Companion_Default___.Signed16(_2_off)).Sign() == -1)) || ((Companion_Default___.Target(pc, _2_off)).Cmp(_dafny.IntOfUint32((prog).Cardinality())) > 0) {
					return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("branch not forward within the window"))
				} else {
					var _3_r Verdict = Companion_Default___.SymExec(prog, sp, (pc).Plus(_dafny.One), ss)
					_ = _3_r
					if (_3_r).Is_NotValidated() {
						return _3_r
					} else {
						return Companion_Default___.SymExec(prog, sp, Companion_Default___.Target(pc, _2_off), ss)
					}
				}
			}
		}
		{
			var _source1 SR = Companion_Default___.SymStep(sp, (prog).Select((pc).Uint32()).(m_Semantics.Instr), ss)
			_ = _source1
			{
				if _source1.Is_SFail() {
					var _4_m _dafny.Sequence = _source1.Get_().(SR_SFail).Reason
					_ = _4_m
					return Companion_Verdict_.Create_NotValidated_(pc, _4_m)
				}
			}
			{
				var _5_ss_k SState = _source1.Get_().(SR_SOk).Ss
				_ = _5_ss_k
				if Companion_Default___.SWF(_5_ss_k) {
					return Companion_Default___.SymExec(prog, sp, (pc).Plus(_dafny.One), _5_ss_k)
				} else {
					return Companion_Verdict_.Create_NotValidated_(pc, _dafny.UnicodeSeqOfUtf8Bytes("internal"))
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
			if (Companion_Default___.CountBranches(_1_prog)).Cmp(Companion_Default___.MAX__BRANCHES()) > 0 {
				return Companion_Verdict_.Create_NotValidated_(_dafny.IntOfInt64(-1), _dafny.UnicodeSeqOfUtf8Bytes("too many branches"))
			} else {
				return Companion_Default___.SymExec(_1_prog, sp, _dafny.Zero, Companion_Default___.SInit())
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
}

func (SState_SState) isSState() {}

func (CompanionStruct_SState_) Create_SState_(Regs _dafny.Sequence, Stack _dafny.Sequence, Snap _dafny.Sequence, Next _dafny.Int, Helpers _dafny.Int, Hooks _dafny.Int, Ret m_Terms.Term) SState {
	return SState{SState_SState{Regs, Stack, Snap, Next, Helpers, Hooks, Ret}}
}

func (_this SState) Is_SState() bool {
	_, ok := _this.Get_().(SState_SState)
	return ok
}

func (CompanionStruct_SState_) Default() SState {
	return Companion_SState_.Create_SState_(_dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, _dafny.Zero, _dafny.Zero, _dafny.Zero, m_Terms.Companion_Term_.Default())
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

func (_this SState) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case SState_SState:
		{
			return "Checker.SState.SState" + "(" + _dafny.String(data.Regs) + ", " + _dafny.String(data.Stack) + ", " + _dafny.String(data.Snap) + ", " + _dafny.String(data.Next) + ", " + _dafny.String(data.Helpers) + ", " + _dafny.String(data.Hooks) + ", " + _dafny.String(data.Ret) + ")"
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
			return ok && data1.Regs.Equals(data2.Regs) && data1.Stack.Equals(data2.Stack) && data1.Snap.Equals(data2.Snap) && data1.Next.Cmp(data2.Next) == 0 && data1.Helpers.Cmp(data2.Helpers) == 0 && data1.Hooks.Cmp(data2.Hooks) == 0 && data1.Ret.Equals(data2.Ret)
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
