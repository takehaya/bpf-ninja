LdXMemDW dst: r6 src: r1 off: 0 imm: 0
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 123
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <untracked>
LdXMemW dst: r1 src: r0 off: 4 imm: 0
JNEImm dst: r1 off: 0 imm: 0 <untracked>
LdXMemW dst: r1 src: r0 off: 0 imm: 0
SubImm dst: r1 imm: 1
JGEImm dst: r1 off: 0 imm: 8 <untracked>
MulImm dst: r1 imm: 32
AddImm dst: r1 imm: 16
AddReg dst: r0 src: r1
MovReg dst: r8 src: r0
LdXMemDW dst: r1 src: r8 off: 24 imm: 0
JNEReg dst: r1 off: 0 src: r6 <mismatch>
Ja off: 0 <release>
mismatch:
MovImm dst: r0 imm: 0
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 126
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
LdXMemW dst: r1 src: r0 off: 0 imm: 0
JEqImm dst: r1 off: 0 imm: 1 <exit>
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 124
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 1
StXAtomicAddDW dst: r0 src: r1 off: 0
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 123
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
LdXMemW dst: r1 src: r0 off: 4 imm: 0
JNEImm dst: r1 off: 0 imm: 0 <already_poisoned>
MovImm dst: r1 imm: 1
StXMemW dst: r0 src: r1 off: 4 imm: 0
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 124
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 1
StXAtomicAddDW dst: r0 src: r1 off: 8
already_poisoned:
MovImm dst: r0 imm: 0
Ja off: 0 <release>
untracked:
MovImm dst: r0 imm: 0
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 126
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
LdXMemW dst: r1 src: r0 off: 0 imm: 0
JEqImm dst: r1 off: 0 imm: 2 <pre_tracking>
JNEImm dst: r1 off: 0 imm: 0 <exit>
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 124
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 1
StXAtomicAddDW dst: r0 src: r1 off: 48
release:
MovImm dst: r0 imm: 0
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 123
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
LdXMemW dst: r1 src: r0 off: 0 imm: 0
JEqImm dst: r1 off: 0 imm: 0 <exit>
SubImm dst: r1 imm: 1
StXMemW dst: r0 src: r1 off: 0 imm: 0
JNEImm dst: r1 off: 0 imm: 0 <exit>
StXMemW dst: r0 src: r1 off: 4 imm: 0
Ja off: 0 <exit>
pre_tracking:
MovImm dst: r0 imm: 0
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 124
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 1
StXAtomicAddDW dst: r0 src: r1 off: 96
exit:
MovImm dst: r0 imm: 0
Exit

