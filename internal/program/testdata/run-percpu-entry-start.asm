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
LdXMemDW dst: r1 src: rfp off: -48 imm: 0
StXMemDW dst: rfp src: r1 off: -48 imm: 0
LdXMemDW dst: r6 src: r1 off: 0 imm: 0
LdXMemDW dst: r7 src: r6 off: 0 imm: 0
LdXMemDW dst: r8 src: r6 off: 8 imm: 0
MovReg dst: r9 src: r8
SubReg dst: r9 src: r7
MovImm dst: r3 imm: 0
StXMemDW dst: rfp src: r3 off: -8 imm: 0
LoadMapPtr dst: r1 fd: 121
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
StMemW dst: r2 src: r0 off: 0 imm: 0
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
StXMemDW dst: rfp src: r0 off: -24 imm: 0
plain_copy:
LdXMemDW dst: r1 src: rfp off: -24 imm: 0
MovReg dst: r2 src: r9
JLEImm dst: r2 off: 0 imm: 14 <copy_len_ok>
MovImm dst: r2 imm: 14
copy_len_ok:
MovReg dst: r3 src: r7
Call FnProbeReadKernel
JNEImm dst: r0 off: 0 imm: 0 <predicate_failed>
LdXMemDW dst: r0 src: rfp off: -24 imm: 0
MovReg dst: r1 src: r9
JLEImm dst: r1 off: 0 imm: 14 <len_ok>
MovImm dst: r1 imm: 14
len_ok:
AddReg dst: r1 src: r0
MovImm dst: r4 imm: 0
MovReg dst: r3 src: r0
AddReg dst: r3 src: r4
AddImm dst: r3 imm: 14
JGTReg dst: r3 off: 0 src: r1 <dsl_reject>
MovReg dst: r3 src: r4
JGTImm dst: r3 off: 0 imm: 508 <dsl_reject>
AddReg dst: r3 src: r0
AddImm dst: r3 imm: 4
JGTReg dst: r3 off: 0 src: r1 <dsl_reject>
LdXMemW dst: r3 src: r3 off: -4 imm: 0
LdImmDW dst: r2 imm: 0
JNEReg dst: r3 off: 0 src: r2 <dsl_reject>
MovReg dst: r3 src: r4
AddImm dst: r3 imm: 4
JGTImm dst: r3 off: 0 imm: 510 <dsl_reject>
AddReg dst: r3 src: r0
AddImm dst: r3 imm: 2
JGTReg dst: r3 off: 0 src: r1 <dsl_reject>
LdXMemH dst: r3 src: r3 off: -2 imm: 0
LdImmDW dst: r2 imm: 0
JNEReg dst: r3 off: 0 src: r2 <dsl_reject>
AddImm dst: r4 imm: 14
MovImm dst: r2 imm: 1
Ja off: 0 <filter_result>
dsl_reject:
MovImm dst: r2 imm: 0
filter_result:
JEqImm dst: r2 off: 0 imm: 0 <exit>
LdXMemDW dst: r1 src: rfp off: -8 imm: 0
StXMemW dst: rfp src: r1 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 125
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JNEImm dst: r0 off: 0 imm: 0 <start_denied>
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
Call FnGetSmpProcessorId
JGTImm dst: r0 off: 0 imm: 65535 <seq_failed>
LShImm dst: r0 imm: 48
StXMemDW dst: rfp src: r0 off: -208 imm: 0
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 125
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <seq_failed>
LdXMemDW dst: r1 src: r0 off: 8 imm: 0
JNEImm dst: r1 off: 0 imm: 0 <seq_failed>
MovImm dst: r1 imm: 1
StXAtomicFetchAddDW dst: r0 src: r1 off: 0
LdImmDW dst: r2 imm: 281474976710655
JLTReg dst: r1 off: 0 src: r2 <start_id>
MovImm dst: r2 imm: 1
StXMemDW dst: r0 src: r2 off: 8 imm: 0
Ja off: 0 <seq_failed>
start_id:
AddImm dst: r1 imm: 1
LdXMemDW dst: r0 src: rfp off: -208 imm: 0
OrReg dst: r0 src: r1
StXMemDW dst: r8 src: r0 off: 8 imm: 0
LdXMemDW dst: r1 src: rfp off: -8 imm: 0
StXMemW dst: r8 src: r1 off: 16 imm: 0
MovImm dst: r1 imm: 1
StXMemW dst: r8 src: r1 off: 20 imm: 0
Ja off: 0 <started>
seq_failed:
MovImm dst: r0 imm: 0
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 124
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 1
StXAtomicAddDW dst: r0 src: r1 off: 72
start_denied:
MovImm dst: r0 imm: 0
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 123
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
LdXMemW dst: r1 src: r0 off: 4 imm: 0
JNEImm dst: r1 off: 0 imm: 0 <exit>
LdXMemW dst: r1 src: r0 off: 0 imm: 0
SubImm dst: r1 imm: 1
JGEImm dst: r1 off: 0 imm: 8 <exit>
MulImm dst: r1 imm: 32
AddImm dst: r1 imm: 16
AddReg dst: r0 src: r1
MovReg dst: r8 src: r0
LdXMemDW dst: r1 src: r8 off: 24 imm: 0
JNEReg dst: r1 off: 0 src: r6 <mismatch>
MovImm dst: r1 imm: 6
StXMemW dst: r8 src: r1 off: 20 imm: 0
Ja off: 0 <exit>
started:
MovImm dst: r0 imm: 0
Ja off: 0 <exit>
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
Ja off: 0 <exit>
untracked:
MovImm dst: r0 imm: 0
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
predicate_failed:
MovImm dst: r0 imm: 0
StMemW dst: rfp src: r0 off: -16 imm: 0
LoadMapPtr dst: r1 fd: 124
MovReg dst: r2 src: rfp
AddImm dst: r2 imm: -16
Call FnMapLookupElem
JEqImm dst: r0 off: 0 imm: 0 <exit>
MovImm dst: r1 imm: 1
StXAtomicAddDW dst: r0 src: r1 off: 88
Ja off: 0 <start_denied>
exit:
MovImm dst: r0 imm: 0
Exit

