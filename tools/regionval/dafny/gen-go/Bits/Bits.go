// Package Bits
// Dafny module Bits compiled into Go

package Bits

import (
	os "os"

	m__System "github.com/dafny-lang/DafnyRuntimeGo/v4/System_"
	_dafny "github.com/dafny-lang/DafnyRuntimeGo/v4/dafny"
)

var _ = os.Args
var _ _dafny.Dummy__
var _ m__System.Dummy__

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
	return "Bits.Default__"
}
func (_this *Default__) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Default__{}

func (_static *CompanionStruct_Default___) Signed64(x uint64) _dafny.Int {
	if (x) < (uint64(9223372036854775808)) {
		return _dafny.IntOfUint64(x)
	} else {
		return (_dafny.IntOfUint64(x)).Minus(Companion_Default___.TWO64())
	}
}
func (_static *CompanionStruct_Default___) Signed32(x uint32) _dafny.Int {
	if (x) < (uint32(2147483648)) {
		return _dafny.IntOfUint32(x)
	} else {
		return (_dafny.IntOfUint32(x)).Minus(_dafny.IntOfInt64(4294967296))
	}
}
func (_static *CompanionStruct_Default___) Signed16(x uint16) _dafny.Int {
	if (x) < (uint16(32768)) {
		return _dafny.IntOfUint16(x)
	} else {
		return (_dafny.IntOfUint16(x)).Minus(_dafny.IntOfInt64(65536))
	}
}
func (_static *CompanionStruct_Default___) Sext32(x uint32) uint64 {
	if ((x) & (uint32(2147483648))) == (uint32(0)) {
		return uint64(x)
	} else {
		return (uint64(x)) | (uint64(18446744069414584320))
	}
}
func (_static *CompanionStruct_Default___) Sext16(x uint16) uint64 {
	if ((x) & (uint16(32768))) == (uint16(0)) {
		return uint64(x)
	} else {
		return (uint64(x)) | (uint64(18446744073709486080))
	}
}
func (_static *CompanionStruct_Default___) Low32(x uint64) uint64 {
	return (x) & (uint64(4294967295))
}
func (_static *CompanionStruct_Default___) Zext8(b uint8) uint64 {
	return uint64(b)
}
func (_static *CompanionStruct_Default___) ByteOf(x uint64, i _dafny.Int) uint8 {
	var _0_y uint64 = (func() uint64 {
		if (i).Sign() == 0 {
			return x
		}
		return (func() uint64 {
			if (i).Cmp(_dafny.One) == 0 {
				return (x) >> (uint8(8))
			}
			return (func() uint64 {
				if (i).Cmp(_dafny.IntOfInt64(2)) == 0 {
					return (x) >> (uint8(16))
				}
				return (func() uint64 {
					if (i).Cmp(_dafny.IntOfInt64(3)) == 0 {
						return (x) >> (uint8(24))
					}
					return (func() uint64 {
						if (i).Cmp(_dafny.IntOfInt64(4)) == 0 {
							return (x) >> (uint8(32))
						}
						return (func() uint64 {
							if (i).Cmp(_dafny.IntOfInt64(5)) == 0 {
								return (x) >> (uint8(40))
							}
							return (func() uint64 {
								if (i).Cmp(_dafny.IntOfInt64(6)) == 0 {
									return (x) >> (uint8(48))
								}
								return (x) >> (uint8(56))
							})()
						})()
					})()
				})()
			})()
		})()
	})()
	_ = _0_y
	return uint8((_0_y) & (uint64(255)))
}
func (_static *CompanionStruct_Default___) LE(bs _dafny.Sequence) uint64 {
	if (_dafny.IntOfUint32((bs).Cardinality())).Sign() == 0 {
		return uint64(0)
	} else {
		return (uint64((bs).Select(0).(uint8))) | ((Companion_Default___.LE((bs).Drop(1))) << (uint8(8)))
	}
}
func (_static *CompanionStruct_Default___) BytesOf(x uint64, w _dafny.Int) _dafny.Sequence {
	return _dafny.SeqCreate((w).Uint32(), func(coer0 func(_dafny.Int) uint8) func(_dafny.Int) interface{} {
		return func(arg0 _dafny.Int) interface{} {
			return coer0(arg0)
		}
	}((func(_0_x uint64, _1_w _dafny.Int) func(_dafny.Int) uint8 {
		return func(_2_i _dafny.Int) uint8 {
			return Companion_Default___.ByteOf(_0_x, _2_i)
		}
	})(x, w)))
}
func (_static *CompanionStruct_Default___) TWO64() _dafny.Int {
	return _dafny.IntOfString("18446744073709551616")
}

// End of class Default__

// Definition of datatype Option
type Option struct {
	Data_Option_
}

func (_this Option) Get_() Data_Option_ {
	return _this.Data_Option_
}

type Data_Option_ interface {
	isOption()
}

type CompanionStruct_Option_ struct {
}

var Companion_Option_ = CompanionStruct_Option_{}

type Option_None struct {
}

func (Option_None) isOption() {}

func (CompanionStruct_Option_) Create_None_() Option {
	return Option{Option_None{}}
}

func (_this Option) Is_None() bool {
	_, ok := _this.Get_().(Option_None)
	return ok
}

type Option_Some struct {
	Value interface{}
}

func (Option_Some) isOption() {}

func (CompanionStruct_Option_) Create_Some_(Value interface{}) Option {
	return Option{Option_Some{Value}}
}

func (_this Option) Is_Some() bool {
	_, ok := _this.Get_().(Option_Some)
	return ok
}

func (CompanionStruct_Option_) Default() Option {
	return Companion_Option_.Create_None_()
}

func (_this Option) Dtor_value() interface{} {
	return _this.Get_().(Option_Some).Value
}

func (_this Option) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Option_None:
		{
			return "Bits.Option.None"
		}
	case Option_Some:
		{
			return "Bits.Option.Some" + "(" + _dafny.String(data.Value) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Option) Equals(other Option) bool {
	switch data1 := _this.Get_().(type) {
	case Option_None:
		{
			_, ok := other.Get_().(Option_None)
			return ok
		}
	case Option_Some:
		{
			data2, ok := other.Get_().(Option_Some)
			return ok && _dafny.AreEqual(data1.Value, data2.Value)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Option) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Option)
	return ok && _this.Equals(typed)
}

func Type_Option_() _dafny.TypeDescriptor {
	return type_Option_{}
}

type type_Option_ struct {
}

func (_this type_Option_) Default() interface{} {
	return Companion_Option_.Default()
}

func (_this type_Option_) String() string {
	return "Bits.Option"
}
func (_this Option) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Option{}

// End of datatype Option
