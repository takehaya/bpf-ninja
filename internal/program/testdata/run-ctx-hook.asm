StXMemDW dst: rfp src: r1 off: -48 imm: 0
LdXMemDW dst: r6 src: r1 off: 0 imm: 0
LdXMemDW dst: r7 src: r6 off: 0 imm: 0
LdXMemDW dst: r8 src: r6 off: 8 imm: 0
MovReg dst: r9 src: r8
SubReg dst: r9 src: r7
StXMemDW dst: rfp src: r6 off: -216 imm: 0
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -216
LoadMapPtr dst: r1 fd: 123
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <untracked>
MovReg dst: r8 src: r0
LdXMemW dst: r1 src: r8 off: 20 imm: 0
JSetImm dst: r1 off: 0 imm: 4 <exit>
AndImm dst: r1 imm: 3
JEqImm dst: r1 off: 0 imm: 1 <record>
JEqImm dst: r1 off: 0 imm: 2 <blocked>
Ja off: 0 <exit>
record:
LdXMemW dst: r1 src: r8 off: 16 imm: 0
StXMemDW dst: rfp src: r1 off: -8 imm: 0
LdXMemDW dst: r1 src: r8 off: 8 imm: 0
StXMemDW dst: rfp src: r1 off: -24 imm: 0
Call FnKtimeGetNs
StXMemDW dst: rfp src: r0 off: -56 imm: 0
Call FnGetSmpProcessorId
StXMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 120
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <rb_lookup_fail>
MovReg dst: r1 src: r0
MovImm dst: r2 imm: 92
MovImm dst: r3 imm: 0
Call FnRingbufReserve
JEqImm dst: r0 off: 0 imm: 0 <rb_fail>
StXMemDW dst: rfp src: r0 off: -32 imm: 0
LdXMemDW dst: r1 src: rfp off: -56 imm: 0
StXMemDW dst: r0 src: r1 off: 0 imm: 0
LdXMemDW dst: r1 src: rfp off: -24 imm: 0
StXMemDW dst: r0 src: r1 off: 20 imm: 0
StMemW dst: r0 src: r0 off: 8 imm: 0
StMemB dst: r0 src: r0 off: 12 imm: 0
StMemB dst: r0 src: r0 off: 13 imm: 1
MovReg dst: r3 src: r9
JLEImm dst: r3 off: 0 imm: 64 <rb_cap_ok>
MovImm dst: r3 imm: 64
rb_cap_ok:
StXMemW dst: rfp src: r3 off: -40 imm: 0
StXMemH dst: r0 src: r3 off: 14 imm: 0
LdXMemDW dst: r1 src: rfp off: -8 imm: 0
StXMemW dst: r0 src: r1 off: 16 imm: 0
MovReg dst: r1 src: r0
AddImm dst: r1 imm: 28
MovReg dst: r2 src: r3
MovReg dst: r3 src: r7
Call FnProbeReadKernel
JNEImm dst: r0 off: 0 imm: 0 <rb_copy_fail>
LdXMemDW dst: r1 src: rfp off: -32 imm: 0
MovImm dst: r2 imm: 0
Call FnRingbufSubmit
Ja off: 0 <rb_submitted>
untracked:
MovImm dst: r0 imm: 0
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 126
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
LdXMemW dst: r1 src: r0 off: 0 imm: 0
JNEImm dst: r1 off: 0 imm: 0 <exit>
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 124
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 1
StXAtomicAddDW dst: r0 src: r1 off: 40
Ja off: 0 <exit>
blocked:
MovImm dst: r0 imm: 0
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 124
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 1
StXAtomicAddDW dst: r0 src: r1 off: 16
Ja off: 0 <exit>
rb_submitted:
StMemW dst: rfp src: r0 off: -16 imm: 1
LoadMapPtr dst: r1 fd: 122
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 1
StXAtomicAddDW dst: r0 src: r1 off: 0
Ja off: 0 <exit>
rb_fail:
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 122
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 1
StXAtomicAddDW dst: r0 src: r1 off: 0
Ja off: 0 <exit>
rb_lookup_fail:
StMemW dst: rfp src: r0 off: -16 imm: 2
LoadMapPtr dst: r1 fd: 122
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 1
StXAtomicAddDW dst: r0 src: r1 off: 0
Ja off: 0 <exit>
rb_copy_fail:
LdXMemDW dst: r1 src: rfp off: -32 imm: 0
MovImm dst: r2 imm: 0
Call FnRingbufDiscard
rb_copy_count:
StMemW dst: rfp src: r0 off: -16 imm: 3
LoadMapPtr dst: r1 fd: 122
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 1
StXAtomicAddDW dst: r0 src: r1 off: 0
Ja off: 0 <exit>
exit:
MovImm dst: r0 imm: 0
Exit

