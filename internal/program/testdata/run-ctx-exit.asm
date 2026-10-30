LdXMemDW dst: r6 src: r1 off: 0 imm: 0
StXMemDW dst: rfp src: r6 off: -216 imm: 0
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -216
LoadMapPtr dst: r1 fd: 123
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <untracked>
MovReg dst: r8 src: r0
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
Ja off: 0 <exit>
release:
MovImm dst: r0 imm: 0
LdXMemW dst: r1 src: r8 off: 20 imm: 0
JSetImm dst: r1 off: 0 imm: 4 <delete>
AndImm dst: r1 imm: 3
JNEImm dst: r1 off: 0 imm: 2 <delete>
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 124
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 1
StXAtomicAddDW dst: r0 src: r1 off: 56
delete:
MovImm dst: r0 imm: 0
StXMemDW dst: rfp src: r6 off: -216 imm: 0
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -216
LoadMapPtr dst: r1 fd: 123
Call FnMapDeleteElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 124
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 1
StXAtomicAddDW dst: r0 src: r1 off: 80
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

