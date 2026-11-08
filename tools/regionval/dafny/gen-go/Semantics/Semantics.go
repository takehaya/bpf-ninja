// Package Semantics
// Dafny module Semantics compiled into Go

package Semantics

import (
	os "os"

	m__System "github.com/dafny-lang/DafnyRuntimeGo/v4/System_"
	_dafny "github.com/dafny-lang/DafnyRuntimeGo/v4/dafny"
	m_Bits "github.com/takehaya/bpf-ninja/tools/regionval/dafny/gen-go/Bits"
)

var _ = os.Args
var _ _dafny.Dummy__
var _ m__System.Dummy__
var _ m_Bits.Dummy__

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
	return "Semantics.Default__"
}
func (_this *Default__) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Default__{}

func (_static *CompanionStruct_Default___) Writes(ins Instr) _dafny.Set {
	var _source0 Instr = ins
	_ = _source0
	{
		if _source0.Is_Alu() {
			var _0_dst _dafny.Int = _source0.Get_().(Instr_Alu).Dst
			_ = _0_dst
			return _dafny.SetOf(_0_dst)
		}
	}
	{
		if _source0.Is_Ldx() {
			var _1_dst _dafny.Int = _source0.Get_().(Instr_Ldx).Dst
			_ = _1_dst
			return _dafny.SetOf(_1_dst)
		}
	}
	{
		if _source0.Is_CallHelper() {
			return _dafny.SetOf(_dafny.Zero, _dafny.One, _dafny.IntOfInt64(2), _dafny.IntOfInt64(3), _dafny.IntOfInt64(4), _dafny.IntOfInt64(5))
		}
	}
	{
		if _source0.Is_CallLocal() {
			return _dafny.SetOf(_dafny.Zero, _dafny.One, _dafny.IntOfInt64(2), _dafny.IntOfInt64(3), _dafny.IntOfInt64(4), _dafny.IntOfInt64(5))
		}
	}
	{
		return _dafny.SetOf()
	}
}
func (_static *CompanionStruct_Default___) NamesR10(ins Instr) bool {
	var _source0 Instr = ins
	_ = _source0
	{
		if _source0.Is_Alu() {
			var _0_dst _dafny.Int = _source0.Get_().(Instr_Alu).Dst
			_ = _0_dst
			var _1_o Operand = _source0.Get_().(Instr_Alu).Opnd
			_ = _1_o
			return ((_0_dst).Cmp(_dafny.IntOfInt64(10)) == 0) || ((_1_o).Equals(Companion_Operand_.Create_Reg_(_dafny.IntOfInt64(10))))
		}
	}
	{
		if _source0.Is_Ldx() {
			var _2_dst _dafny.Int = _source0.Get_().(Instr_Ldx).Dst
			_ = _2_dst
			var _3_base _dafny.Int = _source0.Get_().(Instr_Ldx).Base
			_ = _3_base
			return ((_2_dst).Cmp(_dafny.IntOfInt64(10)) == 0) || ((_3_base).Cmp(_dafny.IntOfInt64(10)) == 0)
		}
	}
	{
		if _source0.Is_Stx() {
			var _4_base _dafny.Int = _source0.Get_().(Instr_Stx).Base
			_ = _4_base
			var _5_src _dafny.Int = _source0.Get_().(Instr_Stx).Src
			_ = _5_src
			return ((_4_base).Cmp(_dafny.IntOfInt64(10)) == 0) || ((_5_src).Cmp(_dafny.IntOfInt64(10)) == 0)
		}
	}
	{
		if _source0.Is_St() {
			var _6_base _dafny.Int = _source0.Get_().(Instr_St).Base
			_ = _6_base
			return (_6_base).Cmp(_dafny.IntOfInt64(10)) == 0
		}
	}
	{
		if _source0.Is_Jcond() {
			var _7_dst _dafny.Int = _source0.Get_().(Instr_Jcond).Dst
			_ = _7_dst
			return (_7_dst).Cmp(_dafny.IntOfInt64(10)) == 0
		}
	}
	{
		return false
	}
}
func (_static *CompanionStruct_Default___) SizeOf(op uint8) _dafny.Int {
	var _0_s uint8 = (op) & (uint8(24))
	_ = _0_s
	if (_0_s) == (uint8(0)) {
		return _dafny.IntOfInt64(4)
	} else if (_0_s) == (uint8(8)) {
		return _dafny.IntOfInt64(2)
	} else if (_0_s) == (uint8(16)) {
		return _dafny.One
	} else {
		return _dafny.IntOfInt64(8)
	}
}
func (_static *CompanionStruct_Default___) AluOpOf(code uint8) m_Bits.Option {
	if (code) == (uint8(0)) {
		return m_Bits.Companion_Option_.Create_Some_(Companion_AluOp_.Create_Add_())
	} else if (code) == (uint8(64)) {
		return m_Bits.Companion_Option_.Create_Some_(Companion_AluOp_.Create_Or_())
	} else if (code) == (uint8(80)) {
		return m_Bits.Companion_Option_.Create_Some_(Companion_AluOp_.Create_And_())
	} else if (code) == (uint8(96)) {
		return m_Bits.Companion_Option_.Create_Some_(Companion_AluOp_.Create_Lsh_())
	} else if (code) == (uint8(176)) {
		return m_Bits.Companion_Option_.Create_Some_(Companion_AluOp_.Create_Mov_())
	} else {
		return m_Bits.Companion_Option_.Create_None_()
	}
}
func (_static *CompanionStruct_Default___) Decode(b _dafny.Sequence) m_Bits.Option {
	var _0_op uint8 = (b).Select(0).(uint8)
	_ = _0_op
	var _1_dst _dafny.Int = _dafny.IntOfUint8(((b).Select(1).(uint8)) & (uint8(15)))
	_ = _1_dst
	var _2_src _dafny.Int = _dafny.IntOfUint8(((b).Select(1).(uint8)) >> (uint8(4)))
	_ = _2_src
	var _3_off uint16 = (uint16((b).Select(2).(uint8))) | ((uint16((b).Select(3).(uint8))) << (uint8(8)))
	_ = _3_off
	var _4_imm uint32 = (((uint32((b).Select(4).(uint8))) | ((uint32((b).Select(5).(uint8))) << (uint8(8)))) | ((uint32((b).Select(6).(uint8))) << (uint8(16)))) | ((uint32((b).Select(7).(uint8))) << (uint8(24)))
	_ = _4_imm
	var _5_cls uint8 = (_0_op) & (uint8(7))
	_ = _5_cls
	if ((_1_dst).Cmp(_dafny.IntOfInt64(10)) > 0) || ((_2_src).Cmp(_dafny.IntOfInt64(10)) > 0) {
		return m_Bits.Companion_Option_.Create_None_()
	} else if ((_5_cls) == (uint8(4))) || ((_5_cls) == (uint8(7))) {
		var _6_is64 bool = (_5_cls) == (uint8(7))
		_ = _6_is64
		var _7_aop m_Bits.Option = Companion_Default___.AluOpOf((_0_op) & (uint8(240)))
		_ = _7_aop
		if (((_7_aop).Is_None()) || ((_3_off) != (uint16(0)) /* dircomp */)) || ((_1_dst).Cmp(_dafny.IntOfInt64(10)) == 0) {
			return m_Bits.Companion_Option_.Create_None_()
		} else if ((_0_op) & (uint8(8))) == (uint8(0)) {
			if (_2_src).Sign() != 0 {
				return m_Bits.Companion_Option_.Create_None_()
			} else if (((_7_aop).Dtor_value().(AluOp)).Equals(Companion_AluOp_.Create_Lsh_())) && ((_4_imm) >= ((func() uint32 {
				if _6_is64 {
					return uint32(64)
				}
				return uint32(32)
			})())) {
				return m_Bits.Companion_Option_.Create_None_()
			} else {
				return m_Bits.Companion_Option_.Create_Some_(Companion_Instr_.Create_Alu_(_6_is64, (_7_aop).Dtor_value().(AluOp), _1_dst, Companion_Operand_.Create_Imm_(_4_imm)))
			}
		} else if (((_4_imm) != (uint32(0)) /* dircomp */) || (((_7_aop).Dtor_value().(AluOp)).Equals(Companion_AluOp_.Create_Add_()))) || (((_7_aop).Dtor_value().(AluOp)).Equals(Companion_AluOp_.Create_Lsh_())) {
			return m_Bits.Companion_Option_.Create_None_()
		} else {
			return m_Bits.Companion_Option_.Create_Some_(Companion_Instr_.Create_Alu_(_6_is64, (_7_aop).Dtor_value().(AluOp), _1_dst, Companion_Operand_.Create_Reg_(_2_src)))
		}
	} else if ((((_0_op) == (uint8(97))) || ((_0_op) == (uint8(105)))) || ((_0_op) == (uint8(113)))) || ((_0_op) == (uint8(121))) {
		if ((_4_imm) != (uint32(0)) /* dircomp */) || ((_1_dst).Cmp(_dafny.IntOfInt64(10)) == 0) {
			return m_Bits.Companion_Option_.Create_None_()
		} else {
			return m_Bits.Companion_Option_.Create_Some_(Companion_Instr_.Create_Ldx_(Companion_Default___.SizeOf(_0_op), _1_dst, _2_src, _3_off))
		}
	} else if ((((_0_op) == (uint8(99))) || ((_0_op) == (uint8(107)))) || ((_0_op) == (uint8(115)))) || ((_0_op) == (uint8(123))) {
		if (_4_imm) != (uint32(0)) /* dircomp */ {
			return m_Bits.Companion_Option_.Create_None_()
		} else {
			return m_Bits.Companion_Option_.Create_Some_(Companion_Instr_.Create_Stx_(Companion_Default___.SizeOf(_0_op), _1_dst, _2_src, _3_off))
		}
	} else if (_0_op) == (uint8(5)) {
		if (((_1_dst).Sign() != 0) || ((_2_src).Sign() != 0)) || ((_4_imm) != (uint32(0)) /* dircomp */) {
			return m_Bits.Companion_Option_.Create_None_()
		} else {
			return m_Bits.Companion_Option_.Create_Some_(Companion_Instr_.Create_Ja_(_3_off))
		}
	} else if (((_0_op) == (uint8(21))) || ((_0_op) == (uint8(85)))) || ((_0_op) == (uint8(118))) {
		if (_2_src).Sign() != 0 {
			return m_Bits.Companion_Option_.Create_None_()
		} else {
			return m_Bits.Companion_Option_.Create_Some_(Companion_Instr_.Create_Jcond_((func() Cond {
				if (_0_op) == (uint8(21)) {
					return Companion_Cond_.Create_JEq_()
				}
				return (func() Cond {
					if (_0_op) == (uint8(85)) {
						return Companion_Cond_.Create_JNe_()
					}
					return Companion_Cond_.Create_JSge32_()
				})()
			})(), _1_dst, _4_imm, _3_off))
		}
	} else if (_0_op) == (uint8(133)) {
		if ((_1_dst).Sign() != 0) || ((_3_off) != (uint16(0)) /* dircomp */) {
			return m_Bits.Companion_Option_.Create_None_()
		} else if (_2_src).Sign() == 0 {
			return m_Bits.Companion_Option_.Create_Some_(Companion_Instr_.Create_CallHelper_(_4_imm))
		} else if (_2_src).Cmp(_dafny.One) == 0 {
			return m_Bits.Companion_Option_.Create_Some_(Companion_Instr_.Create_CallLocal_(_4_imm))
		} else {
			return m_Bits.Companion_Option_.Create_None_()
		}
	} else if (_0_op) == (uint8(149)) {
		if ((((_1_dst).Sign() != 0) || ((_2_src).Sign() != 0)) || ((_3_off) != (uint16(0)) /* dircomp */)) || ((_4_imm) != (uint32(0)) /* dircomp */) {
			return m_Bits.Companion_Option_.Create_None_()
		} else {
			return m_Bits.Companion_Option_.Create_Some_(Companion_Instr_.Create_Exit_())
		}
	} else {
		return m_Bits.Companion_Option_.Create_None_()
	}
}
func (_static *CompanionStruct_Default___) NumInsns(raw _dafny.Sequence) _dafny.Int {
	return (_dafny.IntOfUint32((raw).Cardinality())).DivBy(_dafny.IntOfInt64(8))
}
func (_static *CompanionStruct_Default___) InsnAt(raw _dafny.Sequence, pc _dafny.Int) _dafny.Sequence {
	return (raw).Subsequence(((_dafny.IntOfInt64(8)).Times(pc)).Uint32(), (((_dafny.IntOfInt64(8)).Times(pc)).Plus(_dafny.IntOfInt64(8))).Uint32())
}
func (_static *CompanionStruct_Default___) CWF(s CState) bool {
	return ((_dafny.IntOfUint32(((s).Dtor_regs()).Cardinality())).Cmp(Companion_Default___.NREGS()) == 0) && ((_dafny.IntOfUint32(((s).Dtor_stack()).Cardinality())).Cmp(Companion_Default___.STACK()) == 0)
}
func (_static *CompanionStruct_Default___) Orc(oracle _dafny.Sequence, i _dafny.Int) uint64 {
	if (i).Cmp(_dafny.IntOfUint32((oracle).Cardinality())) < 0 {
		return (oracle).Select((i).Uint32()).(uint64)
	} else {
		return uint64(0)
	}
}
func (_static *CompanionStruct_Default___) Rel(a uint64, fp uint64) _dafny.Int {
	return m_Bits.Companion_Default___.Signed64((a) - (func() uint64 { return (fp) })())
}
func (_static *CompanionStruct_Default___) InFrame(rel _dafny.Int, w _dafny.Int) bool {
	return (((_dafny.Zero).Minus(Companion_Default___.STACK())).Cmp(rel) <= 0) && (((rel).Plus(w)).Sign() != 1)
}
func (_static *CompanionStruct_Default___) AluVal(is64 bool, op AluOp, a uint64, b uint64) uint64 {
	if is64 {
		var _source0 AluOp = op
		_ = _source0
		{
			if _source0.Is_Add() {
				return (a) + (b)
			}
		}
		{
			if _source0.Is_And() {
				return (a) & (b)
			}
		}
		{
			if _source0.Is_Or() {
				return (a) | (b)
			}
		}
		{
			if _source0.Is_Lsh() {
				return (a) << (uint8((b) & (uint64(63))))
			}
		}
		{
			return b
		}
	} else {
		var _source1 AluOp = op
		_ = _source1
		{
			if _source1.Is_Add() {
				return m_Bits.Companion_Default___.Low32((a) + (b))
			}
		}
		{
			if _source1.Is_And() {
				return m_Bits.Companion_Default___.Low32((a) & (b))
			}
		}
		{
			if _source1.Is_Or() {
				return m_Bits.Companion_Default___.Low32((a) | (b))
			}
		}
		{
			if _source1.Is_Lsh() {
				return m_Bits.Companion_Default___.Low32((a) << (uint8((b) & (uint64(31)))))
			}
		}
		{
			return m_Bits.Companion_Default___.Low32(b)
		}
	}
}
func (_static *CompanionStruct_Default___) OperandVal(is64 bool, o Operand, regs _dafny.Sequence) uint64 {
	var _source0 Operand = o
	_ = _source0
	{
		if _source0.Is_Reg() {
			var _0_r _dafny.Int = _source0.Get_().(Operand_Reg).R
			_ = _0_r
			if (_0_r).Cmp(Companion_Default___.NREGS()) < 0 {
				return (regs).Select((_0_r).Uint32()).(uint64)
			} else {
				return uint64(0)
			}
		}
	}
	{
		var _1_k uint32 = _source0.Get_().(Operand_Imm).K
		_ = _1_k
		if is64 {
			return m_Bits.Companion_Default___.Sext32(_1_k)
		} else {
			return uint64(_1_k)
		}
	}
}
func (_static *CompanionStruct_Default___) CondHolds(c Cond, v uint64, imm uint32) bool {
	var _source0 Cond = c
	_ = _source0
	{
		if _source0.Is_JEq() {
			return (v) == (m_Bits.Companion_Default___.Sext32(imm))
		}
	}
	{
		if _source0.Is_JNe() {
			return (v) != (m_Bits.Companion_Default___.Sext32(imm)) /* dircomp */
		}
	}
	{
		return (m_Bits.Companion_Default___.Signed32(uint32((v) & (uint64(4294967295))))).Cmp(m_Bits.Companion_Default___.Signed32(imm)) >= 0
	}
}
func (_static *CompanionStruct_Default___) SetReg(regs _dafny.Sequence, r _dafny.Int, v uint64) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Update(regs, (r).Uint32(), v)
}
func (_static *CompanionStruct_Default___) WriteBytes(st _dafny.Sequence, idx _dafny.Int, bs _dafny.Sequence) _dafny.Sequence {
	return _dafny.SeqCreate((_dafny.IntOfUint32((st).Cardinality())).Uint32(), func(coer1 func(_dafny.Int) uint8) func(_dafny.Int) interface{} {
		return func(arg1 _dafny.Int) interface{} {
			return coer1(arg1)
		}
	}((func(_0_idx _dafny.Int, _1_bs _dafny.Sequence, _2_st _dafny.Sequence) func(_dafny.Int) uint8 {
		return func(_3_i _dafny.Int) uint8 {
			return (func() uint8 {
				if ((_0_idx).Cmp(_3_i) <= 0) && ((_3_i).Cmp((_0_idx).Plus(_dafny.IntOfUint32((_1_bs).Cardinality()))) < 0) {
					return (_1_bs).Select(((_3_i).Minus(_0_idx)).Uint32()).(uint8)
				}
				return (_2_st).Select((_3_i).Uint32()).(uint8)
			})()
		}
	})(idx, bs, st)))
}
func (_static *CompanionStruct_Default___) HavocRegs(regs _dafny.Sequence, oracle _dafny.Sequence, oc _dafny.Int, n _dafny.Int) _dafny.Sequence {
	return _dafny.SeqCreate((Companion_Default___.NREGS()).Uint32(), func(coer2 func(_dafny.Int) uint64) func(_dafny.Int) interface{} {
		return func(arg2 _dafny.Int) interface{} {
			return coer2(arg2)
		}
	}((func(_0_n _dafny.Int, _1_oracle _dafny.Sequence, _2_oc _dafny.Int, _3_regs _dafny.Sequence) func(_dafny.Int) uint64 {
		return func(_4_k _dafny.Int) uint64 {
			return (func() uint64 {
				if (_4_k).Cmp(_0_n) < 0 {
					return Companion_Default___.Orc(_1_oracle, (_2_oc).Plus(_4_k))
				}
				return (_3_regs).Select((_4_k).Uint32()).(uint64)
			})()
		}
	})(n, oracle, oc, regs)))
}
func (_static *CompanionStruct_Default___) Step(floor _dafny.Int, ins Instr, s CState, oracle _dafny.Sequence) StepRes {
	var _pat_let_tv0 = s
	_ = _pat_let_tv0
	var _pat_let_tv1 = s
	_ = _pat_let_tv1
	var _pat_let_tv2 = s
	_ = _pat_let_tv2
	var _pat_let_tv3 = s
	_ = _pat_let_tv3
	var _source0 Instr = ins
	_ = _source0
	{
		if _source0.Is_Alu() {
			var _0_is64 bool = _source0.Get_().(Instr_Alu).Is64
			_ = _0_is64
			var _1_op AluOp = _source0.Get_().(Instr_Alu).Op
			_ = _1_op
			var _2_dst _dafny.Int = _source0.Get_().(Instr_Alu).Dst
			_ = _2_dst
			var _3_opnd Operand = _source0.Get_().(Instr_Alu).Opnd
			_ = _3_opnd
			if (_2_dst).Cmp(_dafny.IntOfInt64(10)) >= 0 {
				return Companion_StepRes_.Create_Stuck_()
			} else {
				return Companion_Default___.AluStep(s, _0_is64, _1_op, _2_dst, _3_opnd)
			}
		}
	}
	{
		if _source0.Is_Ldx() {
			var _4_w _dafny.Int = _source0.Get_().(Instr_Ldx).Size
			_ = _4_w
			var _5_dst _dafny.Int = _source0.Get_().(Instr_Ldx).Dst
			_ = _5_dst
			var _6_base _dafny.Int = _source0.Get_().(Instr_Ldx).Base
			_ = _6_base
			var _7_off uint16 = _source0.Get_().(Instr_Ldx).Off
			_ = _7_off
			if (((_5_dst).Cmp(_dafny.IntOfInt64(10)) >= 0) || ((_6_base).Cmp(_dafny.IntOfInt64(10)) > 0)) || ((_4_w).Cmp(_dafny.IntOfInt64(8)) > 0) {
				return Companion_StepRes_.Create_Stuck_()
			} else {
				return Companion_Default___.LdxStep(s, _4_w, _5_dst, _6_base, _7_off, oracle)
			}
		}
	}
	{
		if _source0.Is_Stx() {
			var _8_w _dafny.Int = _source0.Get_().(Instr_Stx).Size
			_ = _8_w
			var _9_base _dafny.Int = _source0.Get_().(Instr_Stx).Base
			_ = _9_base
			var _10_src _dafny.Int = _source0.Get_().(Instr_Stx).Src
			_ = _10_src
			var _11_off uint16 = _source0.Get_().(Instr_Stx).Off
			_ = _11_off
			if (((_9_base).Cmp(_dafny.IntOfInt64(10)) > 0) || ((_10_src).Cmp(_dafny.IntOfInt64(10)) > 0)) || ((_8_w).Cmp(_dafny.IntOfInt64(8)) > 0) {
				return Companion_StepRes_.Create_Stuck_()
			} else {
				return Companion_Default___.StoreStep(s, (((s).Dtor_regs()).Select((_9_base).Uint32()).(uint64))+(m_Bits.Companion_Default___.Sext16(_11_off)), _8_w, ((s).Dtor_regs()).Select((_10_src).Uint32()).(uint64))
			}
		}
	}
	{
		if _source0.Is_St() {
			var _12_w _dafny.Int = _source0.Get_().(Instr_St).Size
			_ = _12_w
			var _13_base _dafny.Int = _source0.Get_().(Instr_St).Base
			_ = _13_base
			var _14_off uint16 = _source0.Get_().(Instr_St).Off
			_ = _14_off
			var _15_imm uint32 = _source0.Get_().(Instr_St).Imm
			_ = _15_imm
			if ((_13_base).Cmp(_dafny.IntOfInt64(10)) > 0) || ((_12_w).Cmp(_dafny.IntOfInt64(8)) > 0) {
				return Companion_StepRes_.Create_Stuck_()
			} else {
				return Companion_Default___.StoreStep(s, (((s).Dtor_regs()).Select((_13_base).Uint32()).(uint64))+(m_Bits.Companion_Default___.Sext16(_14_off)), _12_w, m_Bits.Companion_Default___.Sext32(_15_imm))
			}
		}
	}
	{
		if _source0.Is_Ja() {
			var _16_off uint16 = _source0.Get_().(Instr_Ja).Off
			_ = _16_off
			return Companion_StepRes_.Create_Next_(func(_pat_let0_0 CState) CState {
				return func(_17_dt__update__tmp_h0 CState) CState {
					return func(_pat_let1_0 _dafny.Int) CState {
						return func(_18_dt__update_hpc_h0 _dafny.Int) CState {
							return Companion_CState_.Create_CState_(_18_dt__update_hpc_h0, (_17_dt__update__tmp_h0).Dtor_regs(), (_17_dt__update__tmp_h0).Dtor_stack(), (_17_dt__update__tmp_h0).Dtor_log(), (_17_dt__update__tmp_h0).Dtor_oc(), (_17_dt__update__tmp_h0).Dtor_events())
						}(_pat_let1_0)
					}((((_pat_let_tv0).Dtor_pc()).Plus(_dafny.One)).Plus(m_Bits.Companion_Default___.Signed16(_16_off)))
				}(_pat_let0_0)
			}(s))
		}
	}
	{
		if _source0.Is_Jcond() {
			var _19_c Cond = _source0.Get_().(Instr_Jcond).Cond
			_ = _19_c
			var _20_dst _dafny.Int = _source0.Get_().(Instr_Jcond).Dst
			_ = _20_dst
			var _21_imm uint32 = _source0.Get_().(Instr_Jcond).Imm
			_ = _21_imm
			var _22_off uint16 = _source0.Get_().(Instr_Jcond).Off
			_ = _22_off
			if (_20_dst).Cmp(_dafny.IntOfInt64(10)) > 0 {
				return Companion_StepRes_.Create_Stuck_()
			} else {
				return Companion_StepRes_.Create_Next_(func(_pat_let2_0 CState) CState {
					return func(_23_dt__update__tmp_h1 CState) CState {
						return func(_pat_let3_0 _dafny.Int) CState {
							return func(_24_dt__update_hpc_h1 _dafny.Int) CState {
								return Companion_CState_.Create_CState_(_24_dt__update_hpc_h1, (_23_dt__update__tmp_h1).Dtor_regs(), (_23_dt__update__tmp_h1).Dtor_stack(), (_23_dt__update__tmp_h1).Dtor_log(), (_23_dt__update__tmp_h1).Dtor_oc(), (_23_dt__update__tmp_h1).Dtor_events())
							}(_pat_let3_0)
						}((func() _dafny.Int {
							if Companion_Default___.CondHolds(_19_c, ((_pat_let_tv1).Dtor_regs()).Select((_20_dst).Uint32()).(uint64), _21_imm) {
								return (((_pat_let_tv2).Dtor_pc()).Plus(_dafny.One)).Plus(m_Bits.Companion_Default___.Signed16(_22_off))
							}
							return ((_pat_let_tv3).Dtor_pc()).Plus(_dafny.One)
						})())
					}(_pat_let2_0)
				}(s))
			}
		}
	}
	{
		if _source0.Is_CallHelper() {
			var _25_id uint32 = _source0.Get_().(Instr_CallHelper).Id
			_ = _25_id
			return Companion_Default___.HelperStep(floor, s, oracle, _25_id)
		}
	}
	{
		if _source0.Is_CallLocal() {
			return Companion_Default___.HookStep(s, oracle)
		}
	}
	{
		return Companion_StepRes_.Create_Halt_(s)
	}
}
func (_static *CompanionStruct_Default___) AluStep(s CState, is64 bool, op AluOp, dst _dafny.Int, opnd Operand) StepRes {
	var _pat_let_tv0 = s
	_ = _pat_let_tv0
	var _pat_let_tv1 = dst
	_ = _pat_let_tv1
	var _pat_let_tv2 = s
	_ = _pat_let_tv2
	var _0_v uint64 = Companion_Default___.AluVal(is64, op, ((s).Dtor_regs()).Select((dst).Uint32()).(uint64), Companion_Default___.OperandVal(is64, opnd, (s).Dtor_regs()))
	_ = _0_v
	return Companion_StepRes_.Create_Next_(func(_pat_let4_0 CState) CState {
		return func(_1_dt__update__tmp_h0 CState) CState {
			return func(_pat_let5_0 _dafny.Sequence) CState {
				return func(_2_dt__update_hregs_h0 _dafny.Sequence) CState {
					return func(_pat_let6_0 _dafny.Int) CState {
						return func(_3_dt__update_hpc_h0 _dafny.Int) CState {
							return Companion_CState_.Create_CState_(_3_dt__update_hpc_h0, _2_dt__update_hregs_h0, (_1_dt__update__tmp_h0).Dtor_stack(), (_1_dt__update__tmp_h0).Dtor_log(), (_1_dt__update__tmp_h0).Dtor_oc(), (_1_dt__update__tmp_h0).Dtor_events())
						}(_pat_let6_0)
					}(((_pat_let_tv2).Dtor_pc()).Plus(_dafny.One))
				}(_pat_let5_0)
			}(Companion_Default___.SetReg((_pat_let_tv0).Dtor_regs(), _pat_let_tv1, _0_v))
		}(_pat_let4_0)
	}(s))
}
func (_static *CompanionStruct_Default___) LoadVal(s CState, addr uint64, w _dafny.Int, oracle _dafny.Sequence) uint64 {
	var _0_rel _dafny.Int = Companion_Default___.Rel(addr, ((s).Dtor_regs()).Select(10).(uint64))
	_ = _0_rel
	if Companion_Default___.InFrame(_0_rel, w) {
		return m_Bits.Companion_Default___.LE(((s).Dtor_stack()).Subsequence(((_0_rel).Plus(_dafny.IntOfInt64(512))).Uint32(), (((_0_rel).Plus(_dafny.IntOfInt64(512))).Plus(w)).Uint32()))
	} else {
		return m_Bits.Companion_Default___.LE(m_Bits.Companion_Default___.BytesOf(Companion_Default___.Orc(oracle, (s).Dtor_oc()), w))
	}
}
func (_static *CompanionStruct_Default___) LdxStep(s CState, w _dafny.Int, dst _dafny.Int, base _dafny.Int, off uint16, oracle _dafny.Sequence) StepRes {
	var _pat_let_tv0 = s
	_ = _pat_let_tv0
	var _pat_let_tv1 = s
	_ = _pat_let_tv1
	var _pat_let_tv2 = dst
	_ = _pat_let_tv2
	var _pat_let_tv3 = s
	_ = _pat_let_tv3
	var _0_addr uint64 = (((s).Dtor_regs()).Select((base).Uint32()).(uint64)) + (m_Bits.Companion_Default___.Sext16(off))
	_ = _0_addr
	var _1_v uint64 = Companion_Default___.LoadVal(s, _0_addr, w, oracle)
	_ = _1_v
	var _2_oc_k _dafny.Int = (func() _dafny.Int {
		if Companion_Default___.InFrame(Companion_Default___.Rel(_0_addr, ((s).Dtor_regs()).Select(10).(uint64)), w) {
			return (s).Dtor_oc()
		}
		return ((s).Dtor_oc()).Plus(_dafny.One)
	})()
	_ = _2_oc_k
	return Companion_StepRes_.Create_Next_(func(_pat_let7_0 CState) CState {
		return func(_3_dt__update__tmp_h0 CState) CState {
			return func(_pat_let8_0 _dafny.Int) CState {
				return func(_4_dt__update_hoc_h0 _dafny.Int) CState {
					return func(_pat_let9_0 _dafny.Sequence) CState {
						return func(_5_dt__update_hlog_h0 _dafny.Sequence) CState {
							return func(_pat_let10_0 _dafny.Sequence) CState {
								return func(_6_dt__update_hregs_h0 _dafny.Sequence) CState {
									return func(_pat_let11_0 _dafny.Int) CState {
										return func(_7_dt__update_hpc_h0 _dafny.Int) CState {
											return Companion_CState_.Create_CState_(_7_dt__update_hpc_h0, _6_dt__update_hregs_h0, (_3_dt__update__tmp_h0).Dtor_stack(), _5_dt__update_hlog_h0, _4_dt__update_hoc_h0, (_3_dt__update__tmp_h0).Dtor_events())
										}(_pat_let11_0)
									}(((_pat_let_tv3).Dtor_pc()).Plus(_dafny.One))
								}(_pat_let10_0)
							}(Companion_Default___.SetReg((_pat_let_tv1).Dtor_regs(), _pat_let_tv2, _1_v))
						}(_pat_let9_0)
					}(_dafny.Companion_Sequence_.Concatenate((_pat_let_tv0).Dtor_log(), _dafny.SeqOf(_1_v)))
				}(_pat_let8_0)
			}(_2_oc_k)
		}(_pat_let7_0)
	}(s))
}
func (_static *CompanionStruct_Default___) StoreStep(s CState, addr uint64, w _dafny.Int, v uint64) StepRes {
	var _pat_let_tv0 = s
	_ = _pat_let_tv0
	var _pat_let_tv1 = addr
	_ = _pat_let_tv1
	var _pat_let_tv2 = w
	_ = _pat_let_tv2
	var _pat_let_tv3 = s
	_ = _pat_let_tv3
	var _0_rel _dafny.Int = Companion_Default___.Rel(addr, ((s).Dtor_regs()).Select(10).(uint64))
	_ = _0_rel
	var _1_stack_k _dafny.Sequence = (func() _dafny.Sequence {
		if Companion_Default___.InFrame(_0_rel, w) {
			return Companion_Default___.WriteBytes((s).Dtor_stack(), (_0_rel).Plus(_dafny.IntOfInt64(512)), m_Bits.Companion_Default___.BytesOf(v, w))
		}
		return (s).Dtor_stack()
	})()
	_ = _1_stack_k
	return Companion_StepRes_.Create_Next_(func(_pat_let12_0 CState) CState {
		return func(_2_dt__update__tmp_h0 CState) CState {
			return func(_pat_let13_0 _dafny.Sequence) CState {
				return func(_3_dt__update_hevents_h0 _dafny.Sequence) CState {
					return func(_pat_let14_0 _dafny.Sequence) CState {
						return func(_4_dt__update_hstack_h0 _dafny.Sequence) CState {
							return func(_pat_let15_0 _dafny.Int) CState {
								return func(_5_dt__update_hpc_h0 _dafny.Int) CState {
									return Companion_CState_.Create_CState_(_5_dt__update_hpc_h0, (_2_dt__update__tmp_h0).Dtor_regs(), _4_dt__update_hstack_h0, (_2_dt__update__tmp_h0).Dtor_log(), (_2_dt__update__tmp_h0).Dtor_oc(), _3_dt__update_hevents_h0)
								}(_pat_let15_0)
							}(((_pat_let_tv3).Dtor_pc()).Plus(_dafny.One))
						}(_pat_let14_0)
					}(_1_stack_k)
				}(_pat_let13_0)
			}(_dafny.Companion_Sequence_.Concatenate((_pat_let_tv0).Dtor_events(), _dafny.SeqOf(Companion_Event_.Create_EStore_(_pat_let_tv1, _pat_let_tv2))))
		}(_pat_let12_0)
	}(s))
}
func (_static *CompanionStruct_Default___) HelperStack(floor _dafny.Int, s CState, oracle _dafny.Sequence) _dafny.Sequence {
	var _0_lo _dafny.Int = (_dafny.IntOfInt64(512)).Plus(floor)
	_ = _0_lo
	return _dafny.SeqCreate((Companion_Default___.STACK()).Uint32(), func(coer3 func(_dafny.Int) uint8) func(_dafny.Int) interface{} {
		return func(arg3 _dafny.Int) interface{} {
			return coer3(arg3)
		}
	}((func(_1_lo _dafny.Int, _2_oracle _dafny.Sequence, _3_s CState) func(_dafny.Int) uint8 {
		return func(_4_i _dafny.Int) uint8 {
			return (func() uint8 {
				if (_4_i).Cmp(_1_lo) >= 0 {
					return m_Bits.Companion_Default___.ByteOf(Companion_Default___.Orc(_2_oracle, (((_3_s).Dtor_oc()).Plus(_dafny.IntOfInt64(6))).Plus((_4_i).Minus(_1_lo))), _dafny.Zero)
				}
				return ((_3_s).Dtor_stack()).Select((_4_i).Uint32()).(uint8)
			})()
		}
	})(_0_lo, oracle, s)))
}
func (_static *CompanionStruct_Default___) HelperStep(floor _dafny.Int, s CState, oracle _dafny.Sequence, id uint32) StepRes {
	var _pat_let_tv0 = s
	_ = _pat_let_tv0
	var _pat_let_tv1 = s
	_ = _pat_let_tv1
	var _pat_let_tv2 = id
	_ = _pat_let_tv2
	var _pat_let_tv3 = s
	_ = _pat_let_tv3
	var _pat_let_tv4 = s
	_ = _pat_let_tv4
	var _pat_let_tv5 = s
	_ = _pat_let_tv5
	var _0_regs_k _dafny.Sequence = Companion_Default___.HavocRegs((s).Dtor_regs(), oracle, (s).Dtor_oc(), _dafny.IntOfInt64(6))
	_ = _0_regs_k
	var _1_up _dafny.Int = (_dafny.Zero).Minus(floor)
	_ = _1_up
	var _2_lo _dafny.Int = (_dafny.IntOfInt64(512)).Plus(floor)
	_ = _2_lo
	var _3_stack_k _dafny.Sequence = Companion_Default___.HelperStack(floor, s, oracle)
	_ = _3_stack_k
	var _4_newVals _dafny.Sequence = _dafny.Companion_Sequence_.Concatenate((_0_regs_k).Subsequence(0, 6), _dafny.SeqCreate((_1_up).Uint32(), func(coer4 func(_dafny.Int) uint64) func(_dafny.Int) interface{} {
		return func(arg4 _dafny.Int) interface{} {
			return coer4(arg4)
		}
	}((func(_5_stack_k _dafny.Sequence, _6_lo _dafny.Int, _7_up _dafny.Int) func(_dafny.Int) uint64 {
		return func(_8_j _dafny.Int) uint64 {
			return m_Bits.Companion_Default___.Zext8((_5_stack_k).Select(((_6_lo).Plus(_8_j)).Uint32()).(uint8))
		}
	})(_3_stack_k, _2_lo, _1_up))))
	_ = _4_newVals
	return Companion_StepRes_.Create_Next_(func(_pat_let16_0 CState) CState {
		return func(_9_dt__update__tmp_h0 CState) CState {
			return func(_pat_let17_0 _dafny.Sequence) CState {
				return func(_10_dt__update_hevents_h0 _dafny.Sequence) CState {
					return func(_pat_let18_0 _dafny.Int) CState {
						return func(_11_dt__update_hoc_h0 _dafny.Int) CState {
							return func(_pat_let19_0 _dafny.Sequence) CState {
								return func(_12_dt__update_hlog_h0 _dafny.Sequence) CState {
									return func(_pat_let20_0 _dafny.Sequence) CState {
										return func(_13_dt__update_hstack_h0 _dafny.Sequence) CState {
											return func(_pat_let21_0 _dafny.Sequence) CState {
												return func(_14_dt__update_hregs_h0 _dafny.Sequence) CState {
													return func(_pat_let22_0 _dafny.Int) CState {
														return func(_15_dt__update_hpc_h0 _dafny.Int) CState {
															return Companion_CState_.Create_CState_(_15_dt__update_hpc_h0, _14_dt__update_hregs_h0, _13_dt__update_hstack_h0, _12_dt__update_hlog_h0, _11_dt__update_hoc_h0, _10_dt__update_hevents_h0)
														}(_pat_let22_0)
													}(((_pat_let_tv5).Dtor_pc()).Plus(_dafny.One))
												}(_pat_let21_0)
											}(_0_regs_k)
										}(_pat_let20_0)
									}(_3_stack_k)
								}(_pat_let19_0)
							}(_dafny.Companion_Sequence_.Concatenate((_pat_let_tv4).Dtor_log(), _4_newVals))
						}(_pat_let18_0)
					}((((_pat_let_tv3).Dtor_oc()).Plus(_dafny.IntOfInt64(6))).Plus(_1_up))
				}(_pat_let17_0)
			}(_dafny.Companion_Sequence_.Concatenate((_pat_let_tv0).Dtor_events(), _dafny.SeqOf(Companion_Event_.Create_EHelper_(((_pat_let_tv1).Dtor_regs()).Subsequence(1, 6), (_0_regs_k).Select(0).(uint64), _3_stack_k, _pat_let_tv2))))
		}(_pat_let16_0)
	}(s))
}
func (_static *CompanionStruct_Default___) HookStep(s CState, oracle _dafny.Sequence) StepRes {
	var _pat_let_tv0 = s
	_ = _pat_let_tv0
	var _pat_let_tv1 = s
	_ = _pat_let_tv1
	var _pat_let_tv2 = s
	_ = _pat_let_tv2
	var _pat_let_tv3 = s
	_ = _pat_let_tv3
	var _pat_let_tv4 = s
	_ = _pat_let_tv4
	var _pat_let_tv5 = s
	_ = _pat_let_tv5
	var _pat_let_tv6 = s
	_ = _pat_let_tv6
	var _pat_let_tv7 = s
	_ = _pat_let_tv7
	var _0_regs_k _dafny.Sequence = Companion_Default___.HavocRegs((s).Dtor_regs(), oracle, (s).Dtor_oc(), _dafny.IntOfInt64(6))
	_ = _0_regs_k
	return Companion_StepRes_.Create_Next_(func(_pat_let23_0 CState) CState {
		return func(_1_dt__update__tmp_h0 CState) CState {
			return func(_pat_let24_0 _dafny.Sequence) CState {
				return func(_2_dt__update_hevents_h0 _dafny.Sequence) CState {
					return func(_pat_let25_0 _dafny.Int) CState {
						return func(_3_dt__update_hoc_h0 _dafny.Int) CState {
							return func(_pat_let26_0 _dafny.Sequence) CState {
								return func(_4_dt__update_hlog_h0 _dafny.Sequence) CState {
									return func(_pat_let27_0 _dafny.Sequence) CState {
										return func(_5_dt__update_hregs_h0 _dafny.Sequence) CState {
											return func(_pat_let28_0 _dafny.Int) CState {
												return func(_6_dt__update_hpc_h0 _dafny.Int) CState {
													return Companion_CState_.Create_CState_(_6_dt__update_hpc_h0, _5_dt__update_hregs_h0, (_1_dt__update__tmp_h0).Dtor_stack(), _4_dt__update_hlog_h0, _3_dt__update_hoc_h0, _2_dt__update_hevents_h0)
												}(_pat_let28_0)
											}(((_pat_let_tv7).Dtor_pc()).Plus(_dafny.One))
										}(_pat_let27_0)
									}(_0_regs_k)
								}(_pat_let26_0)
							}(_dafny.Companion_Sequence_.Concatenate((_pat_let_tv6).Dtor_log(), (_0_regs_k).Subsequence(0, 6)))
						}(_pat_let25_0)
					}(((_pat_let_tv5).Dtor_oc()).Plus(_dafny.IntOfInt64(6)))
				}(_pat_let24_0)
			}(_dafny.Companion_Sequence_.Concatenate((_pat_let_tv0).Dtor_events(), _dafny.SeqOf(Companion_Event_.Create_EHook_((_pat_let_tv1).Dtor_pc(), ((_pat_let_tv2).Dtor_regs()).Subsequence(1, 6), ((_pat_let_tv3).Dtor_regs()).Select(0).(uint64), ((_pat_let_tv4).Dtor_regs()).Select(10).(uint64)))))
		}(_pat_let23_0)
	}(s))
}
func (_static *CompanionStruct_Default___) Run(raw _dafny.Sequence, floor _dafny.Int, s CState, oracle _dafny.Sequence, fuel _dafny.Int) Outcome {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if ((s).Dtor_pc()).Cmp(Companion_Default___.NumInsns(raw)) == 0 {
		return Companion_Outcome_.Create_Done_(s)
	} else if (((s).Dtor_pc()).Sign() == -1) || (((s).Dtor_pc()).Cmp(Companion_Default___.NumInsns(raw)) > 0) {
		return Companion_Outcome_.Create_Escaped_(s)
	} else if (fuel).Sign() == 0 {
		return Companion_Outcome_.Create_OutOfFuel_(s)
	} else {
		var _source0 m_Bits.Option = Companion_Default___.Decode(Companion_Default___.InsnAt(raw, (s).Dtor_pc()))
		_ = _source0
		{
			if _source0.Is_None() {
				return Companion_Outcome_.Create_Escaped_(s)
			}
		}
		{
			var _0_ins Instr = _source0.Get_().(m_Bits.Option_Some).Value.(Instr)
			_ = _0_ins
			var _source1 StepRes = Companion_Default___.Step(floor, _0_ins, s, oracle)
			_ = _source1
			{
				if _source1.Is_Stuck() {
					return Companion_Outcome_.Create_Escaped_(s)
				}
			}
			{
				if _source1.Is_Halt() {
					var _1_s_k CState = _source1.Get_().(StepRes_Halt).S
					_ = _1_s_k
					return Companion_Outcome_.Create_Exited_(_1_s_k)
				}
			}
			{
				var _2_s_k CState = _source1.Get_().(StepRes_Next).S
				_ = _2_s_k
				if Companion_Default___.CWF(_2_s_k) {
					var _in0 _dafny.Sequence = raw
					_ = _in0
					var _in1 _dafny.Int = floor
					_ = _in1
					var _in2 CState = _2_s_k
					_ = _in2
					var _in3 _dafny.Sequence = oracle
					_ = _in3
					var _in4 _dafny.Int = (fuel).Minus(_dafny.One)
					_ = _in4
					raw = _in0
					floor = _in1
					s = _in2
					oracle = _in3
					fuel = _in4
					goto TAIL_CALL_START
				} else {
					return Companion_Outcome_.Create_Escaped_(_2_s_k)
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) WPart(raw _dafny.Sequence) _dafny.Sequence {
	return (raw).Take(((_dafny.IntOfInt64(8)).Times((Companion_Default___.NumInsns(raw)).Minus(_dafny.One))).Uint32())
}
func (_static *CompanionStruct_Default___) EnterW(s CState, oracle _dafny.Sequence) CState {
	var _0_regs _dafny.Sequence = _dafny.SeqCreate((Companion_Default___.NREGS()).Uint32(), func(coer5 func(_dafny.Int) uint64) func(_dafny.Int) interface{} {
		return func(arg5 _dafny.Int) interface{} {
			return coer5(arg5)
		}
	}((func(_1_s CState, _2_oracle _dafny.Sequence) func(_dafny.Int) uint64 {
		return func(_3_k _dafny.Int) uint64 {
			return (func() uint64 {
				if (((_dafny.One).Cmp(_3_k) <= 0) && ((_3_k).Cmp(_dafny.IntOfInt64(5)) <= 0)) || ((_3_k).Cmp(_dafny.IntOfInt64(10)) == 0) {
					return ((_1_s).Dtor_regs()).Select((_3_k).Uint32()).(uint64)
				}
				return Companion_Default___.Orc(_2_oracle, ((_1_s).Dtor_oc()).Plus((func() _dafny.Int {
					if (_3_k).Sign() == 0 {
						return _dafny.Zero
					}
					return (_3_k).Minus(_dafny.IntOfInt64(5))
				})()))
			})()
		}
	})(s, oracle)))
	_ = _0_regs
	return Companion_CState_.Create_CState_(_dafny.Zero, _0_regs, (s).Dtor_stack(), _dafny.Companion_Sequence_.Concatenate((s).Dtor_log(), _dafny.SeqOf((_0_regs).Select(0).(uint64), (_0_regs).Select(6).(uint64), (_0_regs).Select(7).(uint64), (_0_regs).Select(8).(uint64), (_0_regs).Select(9).(uint64))), ((s).Dtor_oc()).Plus(_dafny.IntOfInt64(5)), _dafny.Companion_Sequence_.Concatenate((s).Dtor_events(), _dafny.SeqOf(Companion_Event_.Create_ECallW_((s).Dtor_regs()))))
}
func (_static *CompanionStruct_Default___) ReturnW(s1 CState, t CState, oracle _dafny.Sequence) CState {
	var _0_regs _dafny.Sequence = _dafny.SeqCreate((Companion_Default___.NREGS()).Uint32(), func(coer6 func(_dafny.Int) uint64) func(_dafny.Int) interface{} {
		return func(arg6 _dafny.Int) interface{} {
			return coer6(arg6)
		}
	}((func(_1_t CState, _2_oracle _dafny.Sequence, _3_s1 CState) func(_dafny.Int) uint64 {
		return func(_4_k _dafny.Int) uint64 {
			return (func() uint64 {
				if (_4_k).Sign() == 0 {
					return ((_1_t).Dtor_regs()).Select(0).(uint64)
				}
				return (func() uint64 {
					if (_4_k).Cmp(_dafny.IntOfInt64(5)) <= 0 {
						return Companion_Default___.Orc(_2_oracle, ((_1_t).Dtor_oc()).Plus((_4_k).Minus(_dafny.One)))
					}
					return ((_3_s1).Dtor_regs()).Select((_4_k).Uint32()).(uint64)
				})()
			})()
		}
	})(t, oracle, s1)))
	_ = _0_regs
	return Companion_CState_.Create_CState_(((s1).Dtor_pc()).Plus(_dafny.One), _0_regs, (t).Dtor_stack(), _dafny.Companion_Sequence_.Concatenate((t).Dtor_log(), (_0_regs).Subsequence(1, 6)), ((t).Dtor_oc()).Plus(_dafny.IntOfInt64(5)), _dafny.Companion_Sequence_.Concatenate((t).Dtor_events(), _dafny.SeqOf(Companion_Event_.Create_ERet_(((t).Dtor_regs()).Select(0).(uint64)))))
}
func (_static *CompanionStruct_Default___) WPost(s1 CState, oracle _dafny.Sequence, o Outcome) Outcome {
	var _source0 Outcome = o
	_ = _source0
	{
		if _source0.Is_Exited() {
			var _0_t CState = _source0.Get_().(Outcome_Exited).S
			_ = _0_t
			if (Companion_Default___.CWF(s1)) && (Companion_Default___.CWF(_0_t)) {
				return Companion_Outcome_.Create_Done_(Companion_Default___.ReturnW(s1, _0_t, oracle))
			} else {
				return Companion_Outcome_.Create_Escaped_(_0_t)
			}
		}
	}
	{
		if _source0.Is_Done() {
			var _1_t CState = _source0.Get_().(Outcome_Done).S
			_ = _1_t
			return Companion_Outcome_.Create_Escaped_(_1_t)
		}
	}
	{
		return o
	}
}
func (_static *CompanionStruct_Default___) CallW(raw _dafny.Sequence, wraw _dafny.Sequence, floor _dafny.Int, s1 CState, oracle _dafny.Sequence, fuel _dafny.Int) Outcome {
	if (!(Companion_Default___.CWF(s1))) || (((s1).Dtor_pc()).Cmp((Companion_Default___.NumInsns(raw)).Minus(_dafny.One)) != 0) {
		return Companion_Outcome_.Create_Escaped_(s1)
	} else {
		var _source0 m_Bits.Option = Companion_Default___.Decode(Companion_Default___.InsnAt(raw, (s1).Dtor_pc()))
		_ = _source0
		{
			if _source0.Is_Some() {
				var value0 Instr = _source0.Get_().(m_Bits.Option_Some).Value.(Instr)
				_ = value0
				if value0.Is_CallLocal() {
					return Companion_Default___.WPost(s1, oracle, Companion_Default___.Run(wraw, floor, Companion_Default___.EnterW(s1, oracle), oracle, fuel))
				}
			}
		}
		{
			return Companion_Outcome_.Create_Escaped_(s1)
		}
	}
}
func (_static *CompanionStruct_Default___) WPPost(raw _dafny.Sequence, wraw _dafny.Sequence, floor _dafny.Int, oracle _dafny.Sequence, fuel _dafny.Int, o Outcome) Outcome {
	var _source0 Outcome = o
	_ = _source0
	{
		if _source0.Is_Done() {
			var _0_s1 CState = _source0.Get_().(Outcome_Done).S
			_ = _0_s1
			return Companion_Default___.CallW(raw, wraw, floor, _0_s1, oracle, fuel)
		}
	}
	{
		if _source0.Is_Escaped() {
			var _1_s1 CState = _source0.Get_().(Outcome_Escaped).S
			_ = _1_s1
			if ((_1_s1).Dtor_pc()).Cmp(Companion_Default___.NumInsns(raw)) == 0 {
				return Companion_Outcome_.Create_Done_(_1_s1)
			} else {
				return o
			}
		}
	}
	{
		return o
	}
}
func (_static *CompanionStruct_Default___) RunWrap(raw _dafny.Sequence, wraw _dafny.Sequence, floor _dafny.Int, s CState, oracle _dafny.Sequence, fuel _dafny.Int) Outcome {
	if (Companion_Default___.NumInsns(raw)).Sign() == 0 {
		return Companion_Outcome_.Create_Escaped_(s)
	} else {
		return Companion_Default___.WPPost(raw, wraw, floor, oracle, fuel, Companion_Default___.Run(Companion_Default___.WPart(raw), floor, s, oracle, fuel))
	}
}
func (_static *CompanionStruct_Default___) InitState(regs _dafny.Sequence, stack _dafny.Sequence) CState {
	return Companion_CState_.Create_CState_(_dafny.Zero, regs, stack, _dafny.SeqOf(), _dafny.Zero, _dafny.SeqOf())
}
func (_static *CompanionStruct_Default___) NREGS() _dafny.Int {
	return _dafny.IntOfInt64(11)
}
func (_static *CompanionStruct_Default___) STACK() _dafny.Int {
	return _dafny.IntOfInt64(512)
}

// End of class Default__

// Definition of datatype AluOp
type AluOp struct {
	Data_AluOp_
}

func (_this AluOp) Get_() Data_AluOp_ {
	return _this.Data_AluOp_
}

type Data_AluOp_ interface {
	isAluOp()
}

type CompanionStruct_AluOp_ struct {
}

var Companion_AluOp_ = CompanionStruct_AluOp_{}

type AluOp_Add struct {
}

func (AluOp_Add) isAluOp() {}

func (CompanionStruct_AluOp_) Create_Add_() AluOp {
	return AluOp{AluOp_Add{}}
}

func (_this AluOp) Is_Add() bool {
	_, ok := _this.Get_().(AluOp_Add)
	return ok
}

type AluOp_And struct {
}

func (AluOp_And) isAluOp() {}

func (CompanionStruct_AluOp_) Create_And_() AluOp {
	return AluOp{AluOp_And{}}
}

func (_this AluOp) Is_And() bool {
	_, ok := _this.Get_().(AluOp_And)
	return ok
}

type AluOp_Or struct {
}

func (AluOp_Or) isAluOp() {}

func (CompanionStruct_AluOp_) Create_Or_() AluOp {
	return AluOp{AluOp_Or{}}
}

func (_this AluOp) Is_Or() bool {
	_, ok := _this.Get_().(AluOp_Or)
	return ok
}

type AluOp_Lsh struct {
}

func (AluOp_Lsh) isAluOp() {}

func (CompanionStruct_AluOp_) Create_Lsh_() AluOp {
	return AluOp{AluOp_Lsh{}}
}

func (_this AluOp) Is_Lsh() bool {
	_, ok := _this.Get_().(AluOp_Lsh)
	return ok
}

type AluOp_Mov struct {
}

func (AluOp_Mov) isAluOp() {}

func (CompanionStruct_AluOp_) Create_Mov_() AluOp {
	return AluOp{AluOp_Mov{}}
}

func (_this AluOp) Is_Mov() bool {
	_, ok := _this.Get_().(AluOp_Mov)
	return ok
}

func (CompanionStruct_AluOp_) Default() AluOp {
	return Companion_AluOp_.Create_Add_()
}

func (_ CompanionStruct_AluOp_) AllSingletonConstructors() _dafny.Iterator {
	i := -1
	return func() (interface{}, bool) {
		i++
		switch i {
		case 0:
			return Companion_AluOp_.Create_Add_(), true
		case 1:
			return Companion_AluOp_.Create_And_(), true
		case 2:
			return Companion_AluOp_.Create_Or_(), true
		case 3:
			return Companion_AluOp_.Create_Lsh_(), true
		case 4:
			return Companion_AluOp_.Create_Mov_(), true
		default:
			return AluOp{}, false
		}
	}
}

func (_this AluOp) String() string {
	switch _this.Get_().(type) {
	case nil:
		return "null"
	case AluOp_Add:
		{
			return "Semantics.AluOp.Add"
		}
	case AluOp_And:
		{
			return "Semantics.AluOp.And"
		}
	case AluOp_Or:
		{
			return "Semantics.AluOp.Or"
		}
	case AluOp_Lsh:
		{
			return "Semantics.AluOp.Lsh"
		}
	case AluOp_Mov:
		{
			return "Semantics.AluOp.Mov"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this AluOp) Equals(other AluOp) bool {
	switch _this.Get_().(type) {
	case AluOp_Add:
		{
			_, ok := other.Get_().(AluOp_Add)
			return ok
		}
	case AluOp_And:
		{
			_, ok := other.Get_().(AluOp_And)
			return ok
		}
	case AluOp_Or:
		{
			_, ok := other.Get_().(AluOp_Or)
			return ok
		}
	case AluOp_Lsh:
		{
			_, ok := other.Get_().(AluOp_Lsh)
			return ok
		}
	case AluOp_Mov:
		{
			_, ok := other.Get_().(AluOp_Mov)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this AluOp) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(AluOp)
	return ok && _this.Equals(typed)
}

func Type_AluOp_() _dafny.TypeDescriptor {
	return type_AluOp_{}
}

type type_AluOp_ struct {
}

func (_this type_AluOp_) Default() interface{} {
	return Companion_AluOp_.Default()
}

func (_this type_AluOp_) String() string {
	return "Semantics.AluOp"
}
func (_this AluOp) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = AluOp{}

// End of datatype AluOp

// Definition of datatype Operand
type Operand struct {
	Data_Operand_
}

func (_this Operand) Get_() Data_Operand_ {
	return _this.Data_Operand_
}

type Data_Operand_ interface {
	isOperand()
}

type CompanionStruct_Operand_ struct {
}

var Companion_Operand_ = CompanionStruct_Operand_{}

type Operand_Reg struct {
	R _dafny.Int
}

func (Operand_Reg) isOperand() {}

func (CompanionStruct_Operand_) Create_Reg_(R _dafny.Int) Operand {
	return Operand{Operand_Reg{R}}
}

func (_this Operand) Is_Reg() bool {
	_, ok := _this.Get_().(Operand_Reg)
	return ok
}

type Operand_Imm struct {
	K uint32
}

func (Operand_Imm) isOperand() {}

func (CompanionStruct_Operand_) Create_Imm_(K uint32) Operand {
	return Operand{Operand_Imm{K}}
}

func (_this Operand) Is_Imm() bool {
	_, ok := _this.Get_().(Operand_Imm)
	return ok
}

func (CompanionStruct_Operand_) Default() Operand {
	return Companion_Operand_.Create_Reg_(_dafny.Zero)
}

func (_this Operand) Dtor_r() _dafny.Int {
	return _this.Get_().(Operand_Reg).R
}

func (_this Operand) Dtor_k() uint32 {
	return _this.Get_().(Operand_Imm).K
}

func (_this Operand) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Operand_Reg:
		{
			return "Semantics.Operand.Reg" + "(" + _dafny.String(data.R) + ")"
		}
	case Operand_Imm:
		{
			return "Semantics.Operand.Imm" + "(" + _dafny.String(data.K) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Operand) Equals(other Operand) bool {
	switch data1 := _this.Get_().(type) {
	case Operand_Reg:
		{
			data2, ok := other.Get_().(Operand_Reg)
			return ok && data1.R.Cmp(data2.R) == 0
		}
	case Operand_Imm:
		{
			data2, ok := other.Get_().(Operand_Imm)
			return ok && data1.K == data2.K
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Operand) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Operand)
	return ok && _this.Equals(typed)
}

func Type_Operand_() _dafny.TypeDescriptor {
	return type_Operand_{}
}

type type_Operand_ struct {
}

func (_this type_Operand_) Default() interface{} {
	return Companion_Operand_.Default()
}

func (_this type_Operand_) String() string {
	return "Semantics.Operand"
}
func (_this Operand) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Operand{}

// End of datatype Operand

// Definition of datatype Cond
type Cond struct {
	Data_Cond_
}

func (_this Cond) Get_() Data_Cond_ {
	return _this.Data_Cond_
}

type Data_Cond_ interface {
	isCond()
}

type CompanionStruct_Cond_ struct {
}

var Companion_Cond_ = CompanionStruct_Cond_{}

type Cond_JEq struct {
}

func (Cond_JEq) isCond() {}

func (CompanionStruct_Cond_) Create_JEq_() Cond {
	return Cond{Cond_JEq{}}
}

func (_this Cond) Is_JEq() bool {
	_, ok := _this.Get_().(Cond_JEq)
	return ok
}

type Cond_JNe struct {
}

func (Cond_JNe) isCond() {}

func (CompanionStruct_Cond_) Create_JNe_() Cond {
	return Cond{Cond_JNe{}}
}

func (_this Cond) Is_JNe() bool {
	_, ok := _this.Get_().(Cond_JNe)
	return ok
}

type Cond_JSge32 struct {
}

func (Cond_JSge32) isCond() {}

func (CompanionStruct_Cond_) Create_JSge32_() Cond {
	return Cond{Cond_JSge32{}}
}

func (_this Cond) Is_JSge32() bool {
	_, ok := _this.Get_().(Cond_JSge32)
	return ok
}

func (CompanionStruct_Cond_) Default() Cond {
	return Companion_Cond_.Create_JEq_()
}

func (_ CompanionStruct_Cond_) AllSingletonConstructors() _dafny.Iterator {
	i := -1
	return func() (interface{}, bool) {
		i++
		switch i {
		case 0:
			return Companion_Cond_.Create_JEq_(), true
		case 1:
			return Companion_Cond_.Create_JNe_(), true
		case 2:
			return Companion_Cond_.Create_JSge32_(), true
		default:
			return Cond{}, false
		}
	}
}

func (_this Cond) String() string {
	switch _this.Get_().(type) {
	case nil:
		return "null"
	case Cond_JEq:
		{
			return "Semantics.Cond.JEq"
		}
	case Cond_JNe:
		{
			return "Semantics.Cond.JNe"
		}
	case Cond_JSge32:
		{
			return "Semantics.Cond.JSge32"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Cond) Equals(other Cond) bool {
	switch _this.Get_().(type) {
	case Cond_JEq:
		{
			_, ok := other.Get_().(Cond_JEq)
			return ok
		}
	case Cond_JNe:
		{
			_, ok := other.Get_().(Cond_JNe)
			return ok
		}
	case Cond_JSge32:
		{
			_, ok := other.Get_().(Cond_JSge32)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Cond) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Cond)
	return ok && _this.Equals(typed)
}

func Type_Cond_() _dafny.TypeDescriptor {
	return type_Cond_{}
}

type type_Cond_ struct {
}

func (_this type_Cond_) Default() interface{} {
	return Companion_Cond_.Default()
}

func (_this type_Cond_) String() string {
	return "Semantics.Cond"
}
func (_this Cond) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Cond{}

// End of datatype Cond

// Definition of datatype Instr
type Instr struct {
	Data_Instr_
}

func (_this Instr) Get_() Data_Instr_ {
	return _this.Data_Instr_
}

type Data_Instr_ interface {
	isInstr()
}

type CompanionStruct_Instr_ struct {
}

var Companion_Instr_ = CompanionStruct_Instr_{}

type Instr_Alu struct {
	Is64 bool
	Op   AluOp
	Dst  _dafny.Int
	Opnd Operand
}

func (Instr_Alu) isInstr() {}

func (CompanionStruct_Instr_) Create_Alu_(Is64 bool, Op AluOp, Dst _dafny.Int, Opnd Operand) Instr {
	return Instr{Instr_Alu{Is64, Op, Dst, Opnd}}
}

func (_this Instr) Is_Alu() bool {
	_, ok := _this.Get_().(Instr_Alu)
	return ok
}

type Instr_Ldx struct {
	Size _dafny.Int
	Dst  _dafny.Int
	Base _dafny.Int
	Off  uint16
}

func (Instr_Ldx) isInstr() {}

func (CompanionStruct_Instr_) Create_Ldx_(Size _dafny.Int, Dst _dafny.Int, Base _dafny.Int, Off uint16) Instr {
	return Instr{Instr_Ldx{Size, Dst, Base, Off}}
}

func (_this Instr) Is_Ldx() bool {
	_, ok := _this.Get_().(Instr_Ldx)
	return ok
}

type Instr_Stx struct {
	Size _dafny.Int
	Base _dafny.Int
	Src  _dafny.Int
	Off  uint16
}

func (Instr_Stx) isInstr() {}

func (CompanionStruct_Instr_) Create_Stx_(Size _dafny.Int, Base _dafny.Int, Src _dafny.Int, Off uint16) Instr {
	return Instr{Instr_Stx{Size, Base, Src, Off}}
}

func (_this Instr) Is_Stx() bool {
	_, ok := _this.Get_().(Instr_Stx)
	return ok
}

type Instr_St struct {
	Size _dafny.Int
	Base _dafny.Int
	Off  uint16
	Imm  uint32
}

func (Instr_St) isInstr() {}

func (CompanionStruct_Instr_) Create_St_(Size _dafny.Int, Base _dafny.Int, Off uint16, Imm uint32) Instr {
	return Instr{Instr_St{Size, Base, Off, Imm}}
}

func (_this Instr) Is_St() bool {
	_, ok := _this.Get_().(Instr_St)
	return ok
}

type Instr_Ja struct {
	Off uint16
}

func (Instr_Ja) isInstr() {}

func (CompanionStruct_Instr_) Create_Ja_(Off uint16) Instr {
	return Instr{Instr_Ja{Off}}
}

func (_this Instr) Is_Ja() bool {
	_, ok := _this.Get_().(Instr_Ja)
	return ok
}

type Instr_Jcond struct {
	Cond Cond
	Dst  _dafny.Int
	Imm  uint32
	Off  uint16
}

func (Instr_Jcond) isInstr() {}

func (CompanionStruct_Instr_) Create_Jcond_(Cond Cond, Dst _dafny.Int, Imm uint32, Off uint16) Instr {
	return Instr{Instr_Jcond{Cond, Dst, Imm, Off}}
}

func (_this Instr) Is_Jcond() bool {
	_, ok := _this.Get_().(Instr_Jcond)
	return ok
}

type Instr_CallHelper struct {
	Id uint32
}

func (Instr_CallHelper) isInstr() {}

func (CompanionStruct_Instr_) Create_CallHelper_(Id uint32) Instr {
	return Instr{Instr_CallHelper{Id}}
}

func (_this Instr) Is_CallHelper() bool {
	_, ok := _this.Get_().(Instr_CallHelper)
	return ok
}

type Instr_CallLocal struct {
	Imm uint32
}

func (Instr_CallLocal) isInstr() {}

func (CompanionStruct_Instr_) Create_CallLocal_(Imm uint32) Instr {
	return Instr{Instr_CallLocal{Imm}}
}

func (_this Instr) Is_CallLocal() bool {
	_, ok := _this.Get_().(Instr_CallLocal)
	return ok
}

type Instr_Exit struct {
}

func (Instr_Exit) isInstr() {}

func (CompanionStruct_Instr_) Create_Exit_() Instr {
	return Instr{Instr_Exit{}}
}

func (_this Instr) Is_Exit() bool {
	_, ok := _this.Get_().(Instr_Exit)
	return ok
}

func (CompanionStruct_Instr_) Default() Instr {
	return Companion_Instr_.Create_Alu_(false, Companion_AluOp_.Default(), _dafny.Zero, Companion_Operand_.Default())
}

func (_this Instr) Dtor_is64() bool {
	return _this.Get_().(Instr_Alu).Is64
}

func (_this Instr) Dtor_op() AluOp {
	return _this.Get_().(Instr_Alu).Op
}

func (_this Instr) Dtor_dst() _dafny.Int {
	switch data := _this.Get_().(type) {
	case Instr_Alu:
		return data.Dst
	case Instr_Ldx:
		return data.Dst
	default:
		return data.(Instr_Jcond).Dst
	}
}

func (_this Instr) Dtor_opnd() Operand {
	return _this.Get_().(Instr_Alu).Opnd
}

func (_this Instr) Dtor_size() _dafny.Int {
	switch data := _this.Get_().(type) {
	case Instr_Ldx:
		return data.Size
	case Instr_Stx:
		return data.Size
	default:
		return data.(Instr_St).Size
	}
}

func (_this Instr) Dtor_base() _dafny.Int {
	switch data := _this.Get_().(type) {
	case Instr_Ldx:
		return data.Base
	case Instr_Stx:
		return data.Base
	default:
		return data.(Instr_St).Base
	}
}

func (_this Instr) Dtor_off() uint16 {
	switch data := _this.Get_().(type) {
	case Instr_Ldx:
		return data.Off
	case Instr_Stx:
		return data.Off
	case Instr_St:
		return data.Off
	case Instr_Ja:
		return data.Off
	default:
		return data.(Instr_Jcond).Off
	}
}

func (_this Instr) Dtor_src() _dafny.Int {
	return _this.Get_().(Instr_Stx).Src
}

func (_this Instr) Dtor_imm() uint32 {
	switch data := _this.Get_().(type) {
	case Instr_St:
		return data.Imm
	case Instr_Jcond:
		return data.Imm
	default:
		return data.(Instr_CallLocal).Imm
	}
}

func (_this Instr) Dtor_cond() Cond {
	return _this.Get_().(Instr_Jcond).Cond
}

func (_this Instr) Dtor_id() uint32 {
	return _this.Get_().(Instr_CallHelper).Id
}

func (_this Instr) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Instr_Alu:
		{
			return "Semantics.Instr.Alu" + "(" + _dafny.String(data.Is64) + ", " + _dafny.String(data.Op) + ", " + _dafny.String(data.Dst) + ", " + _dafny.String(data.Opnd) + ")"
		}
	case Instr_Ldx:
		{
			return "Semantics.Instr.Ldx" + "(" + _dafny.String(data.Size) + ", " + _dafny.String(data.Dst) + ", " + _dafny.String(data.Base) + ", " + _dafny.String(data.Off) + ")"
		}
	case Instr_Stx:
		{
			return "Semantics.Instr.Stx" + "(" + _dafny.String(data.Size) + ", " + _dafny.String(data.Base) + ", " + _dafny.String(data.Src) + ", " + _dafny.String(data.Off) + ")"
		}
	case Instr_St:
		{
			return "Semantics.Instr.St" + "(" + _dafny.String(data.Size) + ", " + _dafny.String(data.Base) + ", " + _dafny.String(data.Off) + ", " + _dafny.String(data.Imm) + ")"
		}
	case Instr_Ja:
		{
			return "Semantics.Instr.Ja" + "(" + _dafny.String(data.Off) + ")"
		}
	case Instr_Jcond:
		{
			return "Semantics.Instr.Jcond" + "(" + _dafny.String(data.Cond) + ", " + _dafny.String(data.Dst) + ", " + _dafny.String(data.Imm) + ", " + _dafny.String(data.Off) + ")"
		}
	case Instr_CallHelper:
		{
			return "Semantics.Instr.CallHelper" + "(" + _dafny.String(data.Id) + ")"
		}
	case Instr_CallLocal:
		{
			return "Semantics.Instr.CallLocal" + "(" + _dafny.String(data.Imm) + ")"
		}
	case Instr_Exit:
		{
			return "Semantics.Instr.Exit"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Instr) Equals(other Instr) bool {
	switch data1 := _this.Get_().(type) {
	case Instr_Alu:
		{
			data2, ok := other.Get_().(Instr_Alu)
			return ok && data1.Is64 == data2.Is64 && data1.Op.Equals(data2.Op) && data1.Dst.Cmp(data2.Dst) == 0 && data1.Opnd.Equals(data2.Opnd)
		}
	case Instr_Ldx:
		{
			data2, ok := other.Get_().(Instr_Ldx)
			return ok && data1.Size.Cmp(data2.Size) == 0 && data1.Dst.Cmp(data2.Dst) == 0 && data1.Base.Cmp(data2.Base) == 0 && data1.Off == data2.Off
		}
	case Instr_Stx:
		{
			data2, ok := other.Get_().(Instr_Stx)
			return ok && data1.Size.Cmp(data2.Size) == 0 && data1.Base.Cmp(data2.Base) == 0 && data1.Src.Cmp(data2.Src) == 0 && data1.Off == data2.Off
		}
	case Instr_St:
		{
			data2, ok := other.Get_().(Instr_St)
			return ok && data1.Size.Cmp(data2.Size) == 0 && data1.Base.Cmp(data2.Base) == 0 && data1.Off == data2.Off && data1.Imm == data2.Imm
		}
	case Instr_Ja:
		{
			data2, ok := other.Get_().(Instr_Ja)
			return ok && data1.Off == data2.Off
		}
	case Instr_Jcond:
		{
			data2, ok := other.Get_().(Instr_Jcond)
			return ok && data1.Cond.Equals(data2.Cond) && data1.Dst.Cmp(data2.Dst) == 0 && data1.Imm == data2.Imm && data1.Off == data2.Off
		}
	case Instr_CallHelper:
		{
			data2, ok := other.Get_().(Instr_CallHelper)
			return ok && data1.Id == data2.Id
		}
	case Instr_CallLocal:
		{
			data2, ok := other.Get_().(Instr_CallLocal)
			return ok && data1.Imm == data2.Imm
		}
	case Instr_Exit:
		{
			_, ok := other.Get_().(Instr_Exit)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Instr) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Instr)
	return ok && _this.Equals(typed)
}

func Type_Instr_() _dafny.TypeDescriptor {
	return type_Instr_{}
}

type type_Instr_ struct {
}

func (_this type_Instr_) Default() interface{} {
	return Companion_Instr_.Default()
}

func (_this type_Instr_) String() string {
	return "Semantics.Instr"
}
func (_this Instr) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Instr{}

// End of datatype Instr

// Definition of datatype Event
type Event struct {
	Data_Event_
}

func (_this Event) Get_() Data_Event_ {
	return _this.Data_Event_
}

type Data_Event_ interface {
	isEvent()
}

type CompanionStruct_Event_ struct {
}

var Companion_Event_ = CompanionStruct_Event_{}

type Event_EStore struct {
	Addr  uint64
	Width _dafny.Int
}

func (Event_EStore) isEvent() {}

func (CompanionStruct_Event_) Create_EStore_(Addr uint64, Width _dafny.Int) Event {
	return Event{Event_EStore{Addr, Width}}
}

func (_this Event) Is_EStore() bool {
	_, ok := _this.Get_().(Event_EStore)
	return ok
}

type Event_EHelper struct {
	Args       _dafny.Sequence
	Ret        uint64
	StackAfter _dafny.Sequence
	Id         uint32
}

func (Event_EHelper) isEvent() {}

func (CompanionStruct_Event_) Create_EHelper_(Args _dafny.Sequence, Ret uint64, StackAfter _dafny.Sequence, Id uint32) Event {
	return Event{Event_EHelper{Args, Ret, StackAfter, Id}}
}

func (_this Event) Is_EHelper() bool {
	_, ok := _this.Get_().(Event_EHelper)
	return ok
}

type Event_EHook struct {
	Pc   _dafny.Int
	Args _dafny.Sequence
	R0   uint64
	Fp   uint64
}

func (Event_EHook) isEvent() {}

func (CompanionStruct_Event_) Create_EHook_(Pc _dafny.Int, Args _dafny.Sequence, R0 uint64, Fp uint64) Event {
	return Event{Event_EHook{Pc, Args, R0, Fp}}
}

func (_this Event) Is_EHook() bool {
	_, ok := _this.Get_().(Event_EHook)
	return ok
}

type Event_ECallW struct {
	Regs _dafny.Sequence
}

func (Event_ECallW) isEvent() {}

func (CompanionStruct_Event_) Create_ECallW_(Regs _dafny.Sequence) Event {
	return Event{Event_ECallW{Regs}}
}

func (_this Event) Is_ECallW() bool {
	_, ok := _this.Get_().(Event_ECallW)
	return ok
}

type Event_ERet struct {
	R0 uint64
}

func (Event_ERet) isEvent() {}

func (CompanionStruct_Event_) Create_ERet_(R0 uint64) Event {
	return Event{Event_ERet{R0}}
}

func (_this Event) Is_ERet() bool {
	_, ok := _this.Get_().(Event_ERet)
	return ok
}

func (CompanionStruct_Event_) Default() Event {
	return Companion_Event_.Create_EStore_(0, _dafny.Zero)
}

func (_this Event) Dtor_addr() uint64 {
	return _this.Get_().(Event_EStore).Addr
}

func (_this Event) Dtor_width() _dafny.Int {
	return _this.Get_().(Event_EStore).Width
}

func (_this Event) Dtor_args() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case Event_EHelper:
		return data.Args
	default:
		return data.(Event_EHook).Args
	}
}

func (_this Event) Dtor_ret() uint64 {
	return _this.Get_().(Event_EHelper).Ret
}

func (_this Event) Dtor_stackAfter() _dafny.Sequence {
	return _this.Get_().(Event_EHelper).StackAfter
}

func (_this Event) Dtor_id() uint32 {
	return _this.Get_().(Event_EHelper).Id
}

func (_this Event) Dtor_pc() _dafny.Int {
	return _this.Get_().(Event_EHook).Pc
}

func (_this Event) Dtor_r0() uint64 {
	switch data := _this.Get_().(type) {
	case Event_EHook:
		return data.R0
	default:
		return data.(Event_ERet).R0
	}
}

func (_this Event) Dtor_fp() uint64 {
	return _this.Get_().(Event_EHook).Fp
}

func (_this Event) Dtor_regs() _dafny.Sequence {
	return _this.Get_().(Event_ECallW).Regs
}

func (_this Event) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Event_EStore:
		{
			return "Semantics.Event.EStore" + "(" + _dafny.String(data.Addr) + ", " + _dafny.String(data.Width) + ")"
		}
	case Event_EHelper:
		{
			return "Semantics.Event.EHelper" + "(" + _dafny.String(data.Args) + ", " + _dafny.String(data.Ret) + ", " + _dafny.String(data.StackAfter) + ", " + _dafny.String(data.Id) + ")"
		}
	case Event_EHook:
		{
			return "Semantics.Event.EHook" + "(" + _dafny.String(data.Pc) + ", " + _dafny.String(data.Args) + ", " + _dafny.String(data.R0) + ", " + _dafny.String(data.Fp) + ")"
		}
	case Event_ECallW:
		{
			return "Semantics.Event.ECallW" + "(" + _dafny.String(data.Regs) + ")"
		}
	case Event_ERet:
		{
			return "Semantics.Event.ERet" + "(" + _dafny.String(data.R0) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Event) Equals(other Event) bool {
	switch data1 := _this.Get_().(type) {
	case Event_EStore:
		{
			data2, ok := other.Get_().(Event_EStore)
			return ok && data1.Addr == data2.Addr && data1.Width.Cmp(data2.Width) == 0
		}
	case Event_EHelper:
		{
			data2, ok := other.Get_().(Event_EHelper)
			return ok && data1.Args.Equals(data2.Args) && data1.Ret == data2.Ret && data1.StackAfter.Equals(data2.StackAfter) && data1.Id == data2.Id
		}
	case Event_EHook:
		{
			data2, ok := other.Get_().(Event_EHook)
			return ok && data1.Pc.Cmp(data2.Pc) == 0 && data1.Args.Equals(data2.Args) && data1.R0 == data2.R0 && data1.Fp == data2.Fp
		}
	case Event_ECallW:
		{
			data2, ok := other.Get_().(Event_ECallW)
			return ok && data1.Regs.Equals(data2.Regs)
		}
	case Event_ERet:
		{
			data2, ok := other.Get_().(Event_ERet)
			return ok && data1.R0 == data2.R0
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Event) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Event)
	return ok && _this.Equals(typed)
}

func Type_Event_() _dafny.TypeDescriptor {
	return type_Event_{}
}

type type_Event_ struct {
}

func (_this type_Event_) Default() interface{} {
	return Companion_Event_.Default()
}

func (_this type_Event_) String() string {
	return "Semantics.Event"
}
func (_this Event) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Event{}

// End of datatype Event

// Definition of datatype CState
type CState struct {
	Data_CState_
}

func (_this CState) Get_() Data_CState_ {
	return _this.Data_CState_
}

type Data_CState_ interface {
	isCState()
}

type CompanionStruct_CState_ struct {
}

var Companion_CState_ = CompanionStruct_CState_{}

type CState_CState struct {
	Pc     _dafny.Int
	Regs   _dafny.Sequence
	Stack  _dafny.Sequence
	Log    _dafny.Sequence
	Oc     _dafny.Int
	Events _dafny.Sequence
}

func (CState_CState) isCState() {}

func (CompanionStruct_CState_) Create_CState_(Pc _dafny.Int, Regs _dafny.Sequence, Stack _dafny.Sequence, Log _dafny.Sequence, Oc _dafny.Int, Events _dafny.Sequence) CState {
	return CState{CState_CState{Pc, Regs, Stack, Log, Oc, Events}}
}

func (_this CState) Is_CState() bool {
	_, ok := _this.Get_().(CState_CState)
	return ok
}

func (CompanionStruct_CState_) Default() CState {
	return Companion_CState_.Create_CState_(_dafny.Zero, _dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, _dafny.Zero, _dafny.EmptySeq)
}

func (_this CState) Dtor_pc() _dafny.Int {
	return _this.Get_().(CState_CState).Pc
}

func (_this CState) Dtor_regs() _dafny.Sequence {
	return _this.Get_().(CState_CState).Regs
}

func (_this CState) Dtor_stack() _dafny.Sequence {
	return _this.Get_().(CState_CState).Stack
}

func (_this CState) Dtor_log() _dafny.Sequence {
	return _this.Get_().(CState_CState).Log
}

func (_this CState) Dtor_oc() _dafny.Int {
	return _this.Get_().(CState_CState).Oc
}

func (_this CState) Dtor_events() _dafny.Sequence {
	return _this.Get_().(CState_CState).Events
}

func (_this CState) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case CState_CState:
		{
			return "Semantics.CState.CState" + "(" + _dafny.String(data.Pc) + ", " + _dafny.String(data.Regs) + ", " + _dafny.String(data.Stack) + ", " + _dafny.String(data.Log) + ", " + _dafny.String(data.Oc) + ", " + _dafny.String(data.Events) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this CState) Equals(other CState) bool {
	switch data1 := _this.Get_().(type) {
	case CState_CState:
		{
			data2, ok := other.Get_().(CState_CState)
			return ok && data1.Pc.Cmp(data2.Pc) == 0 && data1.Regs.Equals(data2.Regs) && data1.Stack.Equals(data2.Stack) && data1.Log.Equals(data2.Log) && data1.Oc.Cmp(data2.Oc) == 0 && data1.Events.Equals(data2.Events)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this CState) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(CState)
	return ok && _this.Equals(typed)
}

func Type_CState_() _dafny.TypeDescriptor {
	return type_CState_{}
}

type type_CState_ struct {
}

func (_this type_CState_) Default() interface{} {
	return Companion_CState_.Default()
}

func (_this type_CState_) String() string {
	return "Semantics.CState"
}
func (_this CState) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = CState{}

// End of datatype CState

// Definition of datatype StepRes
type StepRes struct {
	Data_StepRes_
}

func (_this StepRes) Get_() Data_StepRes_ {
	return _this.Data_StepRes_
}

type Data_StepRes_ interface {
	isStepRes()
}

type CompanionStruct_StepRes_ struct {
}

var Companion_StepRes_ = CompanionStruct_StepRes_{}

type StepRes_Next struct {
	S CState
}

func (StepRes_Next) isStepRes() {}

func (CompanionStruct_StepRes_) Create_Next_(S CState) StepRes {
	return StepRes{StepRes_Next{S}}
}

func (_this StepRes) Is_Next() bool {
	_, ok := _this.Get_().(StepRes_Next)
	return ok
}

type StepRes_Halt struct {
	S CState
}

func (StepRes_Halt) isStepRes() {}

func (CompanionStruct_StepRes_) Create_Halt_(S CState) StepRes {
	return StepRes{StepRes_Halt{S}}
}

func (_this StepRes) Is_Halt() bool {
	_, ok := _this.Get_().(StepRes_Halt)
	return ok
}

type StepRes_Stuck struct {
}

func (StepRes_Stuck) isStepRes() {}

func (CompanionStruct_StepRes_) Create_Stuck_() StepRes {
	return StepRes{StepRes_Stuck{}}
}

func (_this StepRes) Is_Stuck() bool {
	_, ok := _this.Get_().(StepRes_Stuck)
	return ok
}

func (CompanionStruct_StepRes_) Default() StepRes {
	return Companion_StepRes_.Create_Next_(Companion_CState_.Default())
}

func (_this StepRes) Dtor_s() CState {
	switch data := _this.Get_().(type) {
	case StepRes_Next:
		return data.S
	default:
		return data.(StepRes_Halt).S
	}
}

func (_this StepRes) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case StepRes_Next:
		{
			return "Semantics.StepRes.Next" + "(" + _dafny.String(data.S) + ")"
		}
	case StepRes_Halt:
		{
			return "Semantics.StepRes.Halt" + "(" + _dafny.String(data.S) + ")"
		}
	case StepRes_Stuck:
		{
			return "Semantics.StepRes.Stuck"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this StepRes) Equals(other StepRes) bool {
	switch data1 := _this.Get_().(type) {
	case StepRes_Next:
		{
			data2, ok := other.Get_().(StepRes_Next)
			return ok && data1.S.Equals(data2.S)
		}
	case StepRes_Halt:
		{
			data2, ok := other.Get_().(StepRes_Halt)
			return ok && data1.S.Equals(data2.S)
		}
	case StepRes_Stuck:
		{
			_, ok := other.Get_().(StepRes_Stuck)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this StepRes) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(StepRes)
	return ok && _this.Equals(typed)
}

func Type_StepRes_() _dafny.TypeDescriptor {
	return type_StepRes_{}
}

type type_StepRes_ struct {
}

func (_this type_StepRes_) Default() interface{} {
	return Companion_StepRes_.Default()
}

func (_this type_StepRes_) String() string {
	return "Semantics.StepRes"
}
func (_this StepRes) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = StepRes{}

// End of datatype StepRes

// Definition of datatype Outcome
type Outcome struct {
	Data_Outcome_
}

func (_this Outcome) Get_() Data_Outcome_ {
	return _this.Data_Outcome_
}

type Data_Outcome_ interface {
	isOutcome()
}

type CompanionStruct_Outcome_ struct {
}

var Companion_Outcome_ = CompanionStruct_Outcome_{}

type Outcome_Done struct {
	S CState
}

func (Outcome_Done) isOutcome() {}

func (CompanionStruct_Outcome_) Create_Done_(S CState) Outcome {
	return Outcome{Outcome_Done{S}}
}

func (_this Outcome) Is_Done() bool {
	_, ok := _this.Get_().(Outcome_Done)
	return ok
}

type Outcome_Exited struct {
	S CState
}

func (Outcome_Exited) isOutcome() {}

func (CompanionStruct_Outcome_) Create_Exited_(S CState) Outcome {
	return Outcome{Outcome_Exited{S}}
}

func (_this Outcome) Is_Exited() bool {
	_, ok := _this.Get_().(Outcome_Exited)
	return ok
}

type Outcome_Escaped struct {
	S CState
}

func (Outcome_Escaped) isOutcome() {}

func (CompanionStruct_Outcome_) Create_Escaped_(S CState) Outcome {
	return Outcome{Outcome_Escaped{S}}
}

func (_this Outcome) Is_Escaped() bool {
	_, ok := _this.Get_().(Outcome_Escaped)
	return ok
}

type Outcome_OutOfFuel struct {
	S CState
}

func (Outcome_OutOfFuel) isOutcome() {}

func (CompanionStruct_Outcome_) Create_OutOfFuel_(S CState) Outcome {
	return Outcome{Outcome_OutOfFuel{S}}
}

func (_this Outcome) Is_OutOfFuel() bool {
	_, ok := _this.Get_().(Outcome_OutOfFuel)
	return ok
}

func (CompanionStruct_Outcome_) Default() Outcome {
	return Companion_Outcome_.Create_Done_(Companion_CState_.Default())
}

func (_this Outcome) Dtor_s() CState {
	switch data := _this.Get_().(type) {
	case Outcome_Done:
		return data.S
	case Outcome_Exited:
		return data.S
	case Outcome_Escaped:
		return data.S
	default:
		return data.(Outcome_OutOfFuel).S
	}
}

func (_this Outcome) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Outcome_Done:
		{
			return "Semantics.Outcome.Done" + "(" + _dafny.String(data.S) + ")"
		}
	case Outcome_Exited:
		{
			return "Semantics.Outcome.Exited" + "(" + _dafny.String(data.S) + ")"
		}
	case Outcome_Escaped:
		{
			return "Semantics.Outcome.Escaped" + "(" + _dafny.String(data.S) + ")"
		}
	case Outcome_OutOfFuel:
		{
			return "Semantics.Outcome.OutOfFuel" + "(" + _dafny.String(data.S) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Outcome) Equals(other Outcome) bool {
	switch data1 := _this.Get_().(type) {
	case Outcome_Done:
		{
			data2, ok := other.Get_().(Outcome_Done)
			return ok && data1.S.Equals(data2.S)
		}
	case Outcome_Exited:
		{
			data2, ok := other.Get_().(Outcome_Exited)
			return ok && data1.S.Equals(data2.S)
		}
	case Outcome_Escaped:
		{
			data2, ok := other.Get_().(Outcome_Escaped)
			return ok && data1.S.Equals(data2.S)
		}
	case Outcome_OutOfFuel:
		{
			data2, ok := other.Get_().(Outcome_OutOfFuel)
			return ok && data1.S.Equals(data2.S)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Outcome) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Outcome)
	return ok && _this.Equals(typed)
}

func Type_Outcome_() _dafny.TypeDescriptor {
	return type_Outcome_{}
}

type type_Outcome_ struct {
}

func (_this type_Outcome_) Default() interface{} {
	return Companion_Outcome_.Default()
}

func (_this type_Outcome_) String() string {
	return "Semantics.Outcome"
}
func (_this Outcome) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Outcome{}

// End of datatype Outcome
