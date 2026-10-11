# host: tc_entry
# expr: eth/ipv4/ipv4/tcp
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
	 65: JNEImm dst: r3 off: -1 imm: 4 <dsl_reject>
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
	 99: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_2_1_case_1_skip>
	100: Ja off: -1 <dsl_pm_ipv4_2_1_walk>
dsl_pm_ipv4_2_1_case_1_skip:
	101: MovReg dst: r3 src: r3
	102: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_2_1_walk:
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
	122: Ja off: -1 <dsl_pm_ipv4_2_1_done>
dsl_pm_ipv4_2_1_done:
	123: MovReg dst: r0 src: r0
	124: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	125: MovReg dst: r5 src: r3
	126: AddImm dst: r5 imm: 9
	127: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	128: MovReg dst: r3 src: r0
	129: AddReg dst: r3 src: r5
	130: AddImm dst: r3 imm: 1
	131: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	132: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	133: JNEImm dst: r3 off: -1 imm: 6 <dsl_reject>
	134: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	135: MovImm dst: r3 imm: 0
	136: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	137: MovReg dst: r3 src: r0
	138: AddReg dst: r3 src: r4
	139: AddImm dst: r3 imm: 20
	140: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	141: AddImm dst: r4 imm: 20
	142: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	143: MovReg dst: r3 src: r4
	144: SubImm dst: r3 imm: 8
	145: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	146: MovReg dst: r5 src: r0
	147: AddReg dst: r5 src: r3
	148: AddImm dst: r5 imm: 1
	149: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	150: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	151: AndImm dst: r5 imm: 240
	152: RShImm dst: r5 imm: 4
	153: LShImm dst: r5 imm: 2
	154: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	155: SubImm dst: r5 imm: 20
	156: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	157: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	158: MovReg dst: r5 src: r4
	159: SubImm dst: r5 imm: 8
	160: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	161: MovReg dst: r3 src: r0
	162: AddReg dst: r3 src: r5
	163: AddImm dst: r3 imm: 1
	164: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	165: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	166: RShImm dst: r3 imm: 4
	167: AndImm dst: r3 imm: 15
	168: JNEImm dst: r3 off: -1 imm: 5 <dsl_pm_tcp_3_0_case_1_skip>
	169: Ja off: -1 <dsl_pm_tcp_3_0_done>
dsl_pm_tcp_3_0_case_1_skip:
	170: MovReg dst: r3 src: r3
	171: Ja off: -1 <dsl_pm_tcp_3_0_parse_options>
dsl_pm_tcp_3_0_parse_options:
	172: MovReg dst: r3 src: r3
	173: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	174: MovReg dst: r3 src: r4
	175: SubImm dst: r3 imm: 8
	176: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	177: MovReg dst: r5 src: r0
	178: AddReg dst: r5 src: r3
	179: AddImm dst: r5 imm: 1
	180: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	181: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	182: AndImm dst: r5 imm: 240
	183: RShImm dst: r5 imm: 4
	184: LShImm dst: r5 imm: 2
	185: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	186: SubImm dst: r5 imm: 20
	187: AddReg dst: r4 src: r5
	188: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	189: MovReg dst: r3 src: r0
	190: AddReg dst: r3 src: r4
	191: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	192: Ja off: -1 <dsl_pm_tcp_3_0_done>
dsl_pm_tcp_3_0_done:
	193: MovReg dst: r0 src: r0
	194: MovImm dst: r2 imm: 1
	195: Ja off: -1 <filter_result>
dsl_reject:
	196: MovImm dst: r2 imm: 0
== Callbacks
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame false
== Extractions
== Warnings
