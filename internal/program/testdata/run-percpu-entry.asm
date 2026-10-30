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
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 123
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
LdXMemW dst: r2 src: r0 off: 0 imm: 0
MovReg dst: r3 src: r2
AddImm dst: r3 imm: 1
StXMemW dst: r0 src: r3 off: 0 imm: 0
JGEImm dst: r2 off: 0 imm: 8 <overflow>
MulImm dst: r2 imm: 32
AddImm dst: r2 imm: 16
MovReg dst: r8 src: r0
AddReg dst: r8 src: r2
MovImm dst: r1 imm: 0
StXMemDW dst: r8 src: r1 off: 0 imm: 0
StXMemDW dst: r8 src: r1 off: 8 imm: 0
StXMemDW dst: r8 src: r1 off: 16 imm: 0
StXMemDW dst: r8 src: r6 off: 24 imm: 0
LdXMemW dst: r1 src: r0 off: 4 imm: 0
JEqImm dst: r1 off: 0 imm: 0 <unpoisoned_entry>
MovImm dst: r1 imm: 2
StXMemW dst: r8 src: r1 off: 20 imm: 0
Ja off: 0 <exit>
unpoisoned_entry:
Call FnGetCurrentPidTgid
StXMemDW dst: r8 src: r0 off: 0 imm: 0
Ja off: 0 <created>
overflow:
MovImm dst: r0 imm: 0
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 124
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 1
StXAtomicAddDW dst: r0 src: r1 off: 64
Ja off: 0 <exit>
created:
MovImm dst: r0 imm: 0
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

