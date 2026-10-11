# host: tc_entry
# expr: eth/ipv4{1,2}/tcp
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
	 65: JNEImm dst: r3 off: -1 imm: 4 <dsl_chain_done_1>
	 66: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 67: MovImm dst: r3 imm: 0
	 68: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 69: MovReg dst: r3 src: r0
	 70: AddReg dst: r3 src: r4
	 71: AddImm dst: r3 imm: 20
	 72: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 73: AddImm dst: r4 imm: 20
	 74: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 75: MovReg dst: r3 src: r4
	 76: SubImm dst: r3 imm: 20
	 77: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 78: MovReg dst: r5 src: r0
	 79: AddReg dst: r5 src: r3
	 80: AddImm dst: r5 imm: 1
	 81: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 82: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 83: AndImm dst: r5 imm: 15
	 84: LShImm dst: r5 imm: 2
	 85: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 86: SubImm dst: r5 imm: 20
	 87: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 88: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 89: MovReg dst: r5 src: r4
	 90: SubImm dst: r5 imm: 20
	 91: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	 92: MovReg dst: r3 src: r0
	 93: AddReg dst: r3 src: r5
	 94: AddImm dst: r3 imm: 1
	 95: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 96: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 97: RShImm dst: r3 imm: 4
	 98: AndImm dst: r3 imm: 15
	 99: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_1_0_i1_case_1_skip>
	100: Ja off: -1 <dsl_pm_ipv4_1_0_i1_walk>
dsl_pm_ipv4_1_0_i1_case_1_skip:
	101: MovReg dst: r3 src: r3
	102: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_1_0_i1_walk:
	103: MovReg dst: r3 src: r3
	104: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	105: MovReg dst: r3 src: r4
	106: SubImm dst: r3 imm: 20
	107: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	108: MovReg dst: r5 src: r0
	109: AddReg dst: r5 src: r3
	110: AddImm dst: r5 imm: 1
	111: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	112: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	113: AndImm dst: r5 imm: 15
	114: LShImm dst: r5 imm: 2
	115: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	116: SubImm dst: r5 imm: 20
	117: AddReg dst: r4 src: r5
	118: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	119: MovReg dst: r3 src: r0
	120: AddReg dst: r3 src: r4
	121: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	122: Ja off: -1 <dsl_pm_ipv4_1_0_i1_done>
dsl_pm_ipv4_1_0_i1_done:
	123: MovReg dst: r0 src: r0
dsl_chain_done_1:
	124: MovReg dst: r0 src: r0
	125: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	126: MovReg dst: r5 src: r3
	127: AddImm dst: r5 imm: 9
	128: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	129: MovReg dst: r3 src: r0
	130: AddReg dst: r3 src: r5
	131: AddImm dst: r3 imm: 1
	132: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	133: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	134: JNEImm dst: r3 off: -1 imm: 6 <dsl_reject>
	135: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	136: MovImm dst: r3 imm: 0
	137: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	138: MovReg dst: r3 src: r0
	139: AddReg dst: r3 src: r4
	140: AddImm dst: r3 imm: 20
	141: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	142: AddImm dst: r4 imm: 20
	143: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	144: MovReg dst: r3 src: r4
	145: SubImm dst: r3 imm: 8
	146: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	147: MovReg dst: r5 src: r0
	148: AddReg dst: r5 src: r3
	149: AddImm dst: r5 imm: 1
	150: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	151: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	152: AndImm dst: r5 imm: 240
	153: RShImm dst: r5 imm: 4
	154: LShImm dst: r5 imm: 2
	155: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	156: SubImm dst: r5 imm: 20
	157: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	158: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	159: MovReg dst: r5 src: r4
	160: SubImm dst: r5 imm: 8
	161: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	162: MovReg dst: r3 src: r0
	163: AddReg dst: r3 src: r5
	164: AddImm dst: r3 imm: 1
	165: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	166: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	167: RShImm dst: r3 imm: 4
	168: AndImm dst: r3 imm: 15
	169: JNEImm dst: r3 off: -1 imm: 5 <dsl_pm_tcp_2_0_case_1_skip>
	170: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_case_1_skip:
	171: MovReg dst: r3 src: r3
	172: Ja off: -1 <dsl_pm_tcp_2_0_parse_options>
dsl_pm_tcp_2_0_parse_options:
	173: MovReg dst: r3 src: r3
	174: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	175: MovReg dst: r3 src: r4
	176: SubImm dst: r3 imm: 8
	177: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	178: MovReg dst: r5 src: r0
	179: AddReg dst: r5 src: r3
	180: AddImm dst: r5 imm: 1
	181: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	182: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	183: AndImm dst: r5 imm: 240
	184: RShImm dst: r5 imm: 4
	185: LShImm dst: r5 imm: 2
	186: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	187: SubImm dst: r5 imm: 20
	188: AddReg dst: r4 src: r5
	189: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	190: MovReg dst: r3 src: r0
	191: AddReg dst: r3 src: r4
	192: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	193: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_done:
	194: MovReg dst: r0 src: r0
	195: MovImm dst: r2 imm: 1
	196: Ja off: -1 <filter_result>
dsl_reject:
	197: MovImm dst: r2 imm: 0
== Callbacks
== Funcs
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame false
== Extractions
== Warnings
