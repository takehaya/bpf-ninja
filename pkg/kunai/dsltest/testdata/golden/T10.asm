# host: tc_entry
# expr: eth/mpls+/ipv4/tcp
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
	  8: AddImm dst: r3 imm: 4
	  9: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 10: MovReg dst: r3 src: r0
	 11: AddReg dst: r3 src: r4
	 12: LdXMemH dst: r3 src: r3 off: -2 imm: 0
	 13: JNEImm dst: r3 off: -1 imm: 18312 <dsl_reject>
	 14: AddImm dst: r4 imm: 4
	 15: JLTImm dst: r4 off: -1 imm: 2 <dsl_chain_done_1>
	 16: MovReg dst: r3 src: r4
	 17: SubImm dst: r3 imm: 2
	 18: JGTImm dst: r3 off: -1 imm: 511 <dsl_chain_done_1>
	 19: MovReg dst: r5 src: r0
	 20: AddReg dst: r5 src: r3
	 21: AddImm dst: r5 imm: 1
	 22: JGTReg dst: r5 off: -1 src: r1 <dsl_chain_done_1>
	 23: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 24: AndImm dst: r5 imm: 1
	 25: JEqImm dst: r5 off: -1 imm: 1 <dsl_chain_done_1>
	 26: StXMemDW dst: rfp src: r4 off: -208 imm: 0
	 27: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 28: StXMemDW dst: rfp src: r0 off: -200 imm: 0
	 29: StXMemDW dst: rfp src: r1 off: -192 imm: 0
	 30: MovImm dst: r1 imm: 7
	 31: LdImmDW dst: r2 imm: -1 <dsl_chain_cb_1>
	 33: MovReg dst: r3 src: rfp
	 34: AddImm dst: r3 imm: -208
	 35: MovImm dst: r4 imm: 0
	 36: Call FnLoop
	 37: LdXMemDW dst: r4 src: rfp off: -208 imm: 0
	 38: LdXMemDW dst: r0 src: rfp off: -200 imm: 0
	 39: LdXMemDW dst: r1 src: rfp off: -192 imm: 0
	 40: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 41: JLTImm dst: r4 off: -1 imm: 2 <dsl_reject>
	 42: MovReg dst: r3 src: r4
	 43: SubImm dst: r3 imm: 2
	 44: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 45: MovReg dst: r5 src: r0
	 46: AddReg dst: r5 src: r3
	 47: AddImm dst: r5 imm: 1
	 48: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 49: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 50: AndImm dst: r5 imm: 1
	 51: JNEImm dst: r5 off: -1 imm: 1 <dsl_reject>
dsl_chain_done_1:
	 52: MovReg dst: r0 src: r0
	 53: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 54: MovImm dst: r3 imm: 0
	 55: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 56: MovReg dst: r3 src: r0
	 57: AddReg dst: r3 src: r4
	 58: AddImm dst: r3 imm: 20
	 59: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 60: AddImm dst: r4 imm: 20
	 61: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 62: MovReg dst: r3 src: r4
	 63: SubImm dst: r3 imm: 20
	 64: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 65: MovReg dst: r5 src: r0
	 66: AddReg dst: r5 src: r3
	 67: AddImm dst: r5 imm: 1
	 68: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 69: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 70: AndImm dst: r5 imm: 15
	 71: LShImm dst: r5 imm: 2
	 72: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 73: SubImm dst: r5 imm: 20
	 74: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 75: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 76: MovReg dst: r5 src: r4
	 77: SubImm dst: r5 imm: 20
	 78: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	 79: MovReg dst: r3 src: r0
	 80: AddReg dst: r3 src: r5
	 81: AddImm dst: r3 imm: 1
	 82: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 83: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 84: RShImm dst: r3 imm: 4
	 85: AndImm dst: r3 imm: 15
	 86: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_2_0_case_1_skip>
	 87: Ja off: -1 <dsl_pm_ipv4_2_0_walk>
dsl_pm_ipv4_2_0_case_1_skip:
	 88: MovReg dst: r3 src: r3
	 89: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_2_0_walk:
	 90: MovReg dst: r3 src: r3
	 91: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 92: MovReg dst: r3 src: r4
	 93: SubImm dst: r3 imm: 20
	 94: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 95: MovReg dst: r5 src: r0
	 96: AddReg dst: r5 src: r3
	 97: AddImm dst: r5 imm: 1
	 98: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 99: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	100: AndImm dst: r5 imm: 15
	101: LShImm dst: r5 imm: 2
	102: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	103: SubImm dst: r5 imm: 20
	104: AddReg dst: r4 src: r5
	105: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	106: MovReg dst: r3 src: r0
	107: AddReg dst: r3 src: r4
	108: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	109: Ja off: -1 <dsl_pm_ipv4_2_0_done>
dsl_pm_ipv4_2_0_done:
	110: MovReg dst: r0 src: r0
	111: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	112: MovReg dst: r5 src: r3
	113: AddImm dst: r5 imm: 9
	114: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	115: MovReg dst: r3 src: r0
	116: AddReg dst: r3 src: r5
	117: AddImm dst: r3 imm: 1
	118: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	119: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	120: JNEImm dst: r3 off: -1 imm: 6 <dsl_reject>
	121: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	122: MovImm dst: r3 imm: 0
	123: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	124: MovReg dst: r3 src: r0
	125: AddReg dst: r3 src: r4
	126: AddImm dst: r3 imm: 20
	127: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	128: AddImm dst: r4 imm: 20
	129: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	130: MovReg dst: r3 src: r4
	131: SubImm dst: r3 imm: 8
	132: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	133: MovReg dst: r5 src: r0
	134: AddReg dst: r5 src: r3
	135: AddImm dst: r5 imm: 1
	136: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	137: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	138: AndImm dst: r5 imm: 240
	139: RShImm dst: r5 imm: 4
	140: LShImm dst: r5 imm: 2
	141: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	142: SubImm dst: r5 imm: 20
	143: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	144: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	145: MovReg dst: r5 src: r4
	146: SubImm dst: r5 imm: 8
	147: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	148: MovReg dst: r3 src: r0
	149: AddReg dst: r3 src: r5
	150: AddImm dst: r3 imm: 1
	151: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	152: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	153: RShImm dst: r3 imm: 4
	154: AndImm dst: r3 imm: 15
	155: JNEImm dst: r3 off: -1 imm: 5 <dsl_pm_tcp_3_0_case_1_skip>
	156: Ja off: -1 <dsl_pm_tcp_3_0_done>
dsl_pm_tcp_3_0_case_1_skip:
	157: MovReg dst: r3 src: r3
	158: Ja off: -1 <dsl_pm_tcp_3_0_parse_options>
dsl_pm_tcp_3_0_parse_options:
	159: MovReg dst: r3 src: r3
	160: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	161: MovReg dst: r3 src: r4
	162: SubImm dst: r3 imm: 8
	163: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	164: MovReg dst: r5 src: r0
	165: AddReg dst: r5 src: r3
	166: AddImm dst: r5 imm: 1
	167: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	168: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	169: AndImm dst: r5 imm: 240
	170: RShImm dst: r5 imm: 4
	171: LShImm dst: r5 imm: 2
	172: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	173: SubImm dst: r5 imm: 20
	174: AddReg dst: r4 src: r5
	175: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	176: MovReg dst: r3 src: r0
	177: AddReg dst: r3 src: r4
	178: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	179: Ja off: -1 <dsl_pm_tcp_3_0_done>
dsl_pm_tcp_3_0_done:
	180: MovReg dst: r0 src: r0
	181: MovImm dst: r2 imm: 1
	182: Ja off: -1 <filter_result>
dsl_reject:
	183: MovImm dst: r2 imm: 0
== Callbacks
dsl_chain_cb_1:
	 0: LdXMemDW dst: r3 src: r2 off: 0 imm: 0
	 1: LdXMemDW dst: r4 src: r2 off: 8 imm: 0
	 2: LdXMemDW dst: r5 src: r2 off: 16 imm: 0
	 3: JGTImm dst: r3 off: -1 imm: 512 <dsl_chain_cb_1_reject>
	 4: MovReg dst: r0 src: r4
	 5: AddReg dst: r0 src: r3
	 6: AddImm dst: r0 imm: 4
	 7: JGTReg dst: r0 off: -1 src: r5 <dsl_chain_cb_1_reject>
	 8: AddImm dst: r3 imm: 4
	 9: AndImm dst: r3 imm: 1023
	10: StXMemDW dst: r2 src: r3 off: 0 imm: 0
	11: JLTImm dst: r3 off: -1 imm: 2 <dsl_chain_cb_1_break>
	12: MovReg dst: r1 src: r3
	13: SubImm dst: r1 imm: 2
	14: JGTImm dst: r1 off: -1 imm: 511 <dsl_chain_cb_1_break>
	15: MovReg dst: r0 src: r4
	16: AddReg dst: r0 src: r1
	17: AddImm dst: r0 imm: 1
	18: JGTReg dst: r0 off: -1 src: r5 <dsl_chain_cb_1_break>
	19: LdXMemB dst: r0 src: r0 off: -1 imm: 0
	20: AndImm dst: r0 imm: 1
	21: JEqImm dst: r0 off: -1 imm: 1 <dsl_chain_cb_1_break>
	22: MovImm dst: r0 imm: 0
	23: Exit
dsl_chain_cb_1_reject:
	24: MovImm dst: r0 imm: -1
	25: StXMemDW dst: r2 src: r0 off: 0 imm: 0
dsl_chain_cb_1_break:
	26: MovImm dst: r0 imm: 1
	27: Exit
== Funcs
183: dsl_chain_cb_1
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame false
== Extractions
== Warnings
