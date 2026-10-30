LdXMemDW dst: r6 src: r1 off: 0 imm: 0
StXMemDW dst: rfp src: r1 off: -48 imm: 0
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 126
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
LdXMemW dst: r9 src: r0 off: 0 imm: 0
JEqImm dst: r9 off: 0 imm: 1 <exit>
MovImm dst: r1 imm: 0
StXMemDW dst: rfp src: r1 off: -192 imm: 0
StXMemDW dst: rfp src: r1 off: -184 imm: 0
StXMemDW dst: rfp src: r1 off: -176 imm: 0
StXMemDW dst: rfp src: r1 off: -168 imm: 0
StXMemDW dst: rfp src: r6 off: -168 imm: 0
Call FnGetCurrentPidTgid
StXMemDW dst: rfp src: r0 off: -192 imm: 0
StXMemDW dst: rfp src: r6 off: -216 imm: 0
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -216
LoadMapPtr dst: r1 fd: 123
MovReg dst: r3 src: rfp
AddImm dst: r3 imm: -192
MovImm dst: r4 imm: 1
Call FnMapUpdateElem
JEqImm dst: r0 off: 0 imm: 0 <created>
JNE32Imm dst: r0 off: 0 imm: -17 <insert_failed>
StXMemDW dst: rfp src: r6 off: -216 imm: 0
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -216
LoadMapPtr dst: r1 fd: 123
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <insert_failed>
MovImm dst: r1 imm: 2
StXMemW dst: r0 src: r1 off: 20 imm: 0
MovImm dst: r1 imm: 0
StXMemDW dst: r0 src: r1 off: 8 imm: 0
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 124
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 1
StXAtomicAddDW dst: r0 src: r1 off: 24
Ja off: 0 <exit>
insert_failed:
MovImm dst: r0 imm: 0
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 124
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 1
StXAtomicAddDW dst: r0 src: r1 off: 32
StXMemDW dst: rfp src: r6 off: -216 imm: 0
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -216
LoadMapPtr dst: r1 fd: 123
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 2
StXMemW dst: r0 src: r1 off: 20 imm: 0
MovImm dst: r1 imm: 0
StXMemDW dst: r0 src: r1 off: 8 imm: 0
Ja off: 0 <exit>
created:
MovImm dst: r0 imm: 0
StXMemDW dst: rfp src: r6 off: -216 imm: 0
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -216
LoadMapPtr dst: r1 fd: 123
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovReg dst: r8 src: r0
JNEImm dst: r9 off: 0 imm: 0 <pre_tracking>
Ja off: 0 <exit>
pre_tracking:
MovImm dst: r1 imm: 6
StXMemW dst: r8 src: r1 off: 20 imm: 0
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 124
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 1
StXAtomicAddDW dst: r0 src: r1 off: 96
Ja off: 0 <exit>
exit:
MovImm dst: r0 imm: 0
Exit

