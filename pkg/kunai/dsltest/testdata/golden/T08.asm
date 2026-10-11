# host: tc_entry
# expr: eth/ipv4/tcp capture headers+64
# sets: -
== Main
	  0: MovImm dst: r4 imm: 0
	  1: MovReg dst: r3 src: r0
	  2: AddReg dst: r3 src: r4
	  3: AddImm dst: r3 imm: 14
	  4: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	  5: AddImm dst: r4 imm: 14
	  6: MovReg dst: r3 src: r0
	  7: AddReg dst: r3 src: r4
	  8: LdXMemH dst: r3 src: r3 off: -2 imm: 0
	  9: JNEImm dst: r3 off: -1 imm: 8 <dsl_reject>
	 10: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 11: MovImm dst: r3 imm: 0
	 12: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 13: MovReg dst: r3 src: r0
	 14: AddReg dst: r3 src: r4
	 15: AddImm dst: r3 imm: 20
	 16: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 17: AddImm dst: r4 imm: 20
	 18: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 19: MovReg dst: r3 src: r4
	 20: SubImm dst: r3 imm: 20
	 21: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 22: MovReg dst: r5 src: r0
	 23: AddReg dst: r5 src: r3
	 24: AddImm dst: r5 imm: 1
	 25: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 26: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 27: AndImm dst: r5 imm: 15
	 28: LShImm dst: r5 imm: 2
	 29: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 30: SubImm dst: r5 imm: 20
	 31: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 32: MovReg dst: r3 src: r0
	 33: AddReg dst: r3 src: r4
	 34: LdXMemB dst: r3 src: r3 off: -20 imm: 0
	 35: RShImm dst: r3 imm: 4
	 36: AndImm dst: r3 imm: 15
	 37: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_1_0_case_1_skip>
	 38: Ja off: -1 <dsl_pm_ipv4_1_0_walk>
dsl_pm_ipv4_1_0_case_1_skip:
	 39: MovReg dst: r3 src: r3
	 40: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_1_0_walk:
	 41: MovReg dst: r3 src: r3
	 42: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 43: MovReg dst: r3 src: r4
	 44: SubImm dst: r3 imm: 20
	 45: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 46: MovReg dst: r5 src: r0
	 47: AddReg dst: r5 src: r3
	 48: AddImm dst: r5 imm: 1
	 49: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 50: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 51: AndImm dst: r5 imm: 15
	 52: LShImm dst: r5 imm: 2
	 53: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 54: SubImm dst: r5 imm: 20
	 55: AddReg dst: r4 src: r5
	 56: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 57: MovReg dst: r3 src: r0
	 58: AddReg dst: r3 src: r4
	 59: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 60: Ja off: -1 <dsl_pm_ipv4_1_0_done>
dsl_pm_ipv4_1_0_done:
	 61: MovReg dst: r0 src: r0
	 62: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	 63: AddReg dst: r3 src: r0
	 64: LdXMemB dst: r3 src: r3 off: 9 imm: 0
	 65: JNEImm dst: r3 off: -1 imm: 6 <dsl_reject>
	 66: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 67: MovImm dst: r3 imm: 0
	 68: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 69: MovReg dst: r3 src: r0
	 70: AddReg dst: r3 src: r4
	 71: AddImm dst: r3 imm: 20
	 72: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 73: AddImm dst: r4 imm: 20
	 74: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 75: MovReg dst: r3 src: r4
	 76: SubImm dst: r3 imm: 8
	 77: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 78: MovReg dst: r5 src: r0
	 79: AddReg dst: r5 src: r3
	 80: AddImm dst: r5 imm: 1
	 81: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 82: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 83: AndImm dst: r5 imm: 240
	 84: RShImm dst: r5 imm: 4
	 85: LShImm dst: r5 imm: 2
	 86: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 87: SubImm dst: r5 imm: 20
	 88: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 89: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 90: MovReg dst: r5 src: r4
	 91: SubImm dst: r5 imm: 8
	 92: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	 93: MovReg dst: r3 src: r0
	 94: AddReg dst: r3 src: r5
	 95: AddImm dst: r3 imm: 1
	 96: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 97: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 98: RShImm dst: r3 imm: 4
	 99: AndImm dst: r3 imm: 15
	100: JNEImm dst: r3 off: -1 imm: 5 <dsl_pm_tcp_2_0_case_1_skip>
	101: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_case_1_skip:
	102: MovReg dst: r3 src: r3
	103: Ja off: -1 <dsl_pm_tcp_2_0_parse_options>
dsl_pm_tcp_2_0_parse_options:
	104: MovReg dst: r3 src: r3
	105: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	106: MovReg dst: r3 src: r4
	107: SubImm dst: r3 imm: 8
	108: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	109: MovReg dst: r5 src: r0
	110: AddReg dst: r5 src: r3
	111: AddImm dst: r5 imm: 1
	112: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	113: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	114: AndImm dst: r5 imm: 240
	115: RShImm dst: r5 imm: 4
	116: LShImm dst: r5 imm: 2
	117: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	118: SubImm dst: r5 imm: 20
	119: AddReg dst: r4 src: r5
	120: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	121: MovReg dst: r3 src: r0
	122: AddReg dst: r3 src: r4
	123: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	124: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_done:
	125: MovReg dst: r0 src: r0
	126: MovImm dst: r2 imm: 1
	127: Ja off: -1 <filter_result>
dsl_reject:
	128: MovImm dst: r2 imm: 0
== Callbacks
== Funcs
== Capture MaxCapLen=118 FilterMinPrefix=0
== WireFrame false
== Extractions
== Warnings
