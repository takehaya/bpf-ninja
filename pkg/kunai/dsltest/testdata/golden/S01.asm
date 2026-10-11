# host: xdp_entry
# expr: eth/ipv4[src in @hosts]/tcp[dport in @ports]
# sets: hosts:32,ports:16
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
	 17: MovReg dst: r3 src: r4
	 18: AddImm dst: r3 imm: 12
	 19: JGTImm dst: r3 off: -1 imm: 508 <dsl_reject>
	 20: AddReg dst: r3 src: r0
	 21: AddImm dst: r3 imm: 4
	 22: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 23: LdXMemW dst: r3 src: r3 off: -4 imm: 0
	 24: SwapBE dst: r3
	 25: StXMemW dst: rfp src: r3 off: -28 imm: 0
	 26: AddImm dst: r4 imm: 20
	 27: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 28: MovReg dst: r3 src: r4
	 29: SubImm dst: r3 imm: 20
	 30: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 31: MovReg dst: r5 src: r0
	 32: AddReg dst: r5 src: r3
	 33: AddImm dst: r5 imm: 1
	 34: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 35: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 36: AndImm dst: r5 imm: 15
	 37: LShImm dst: r5 imm: 2
	 38: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 39: SubImm dst: r5 imm: 20
	 40: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 41: MovReg dst: r3 src: r0
	 42: AddReg dst: r3 src: r4
	 43: LdXMemB dst: r3 src: r3 off: -20 imm: 0
	 44: RShImm dst: r3 imm: 4
	 45: AndImm dst: r3 imm: 15
	 46: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_1_0_case_1_skip>
	 47: Ja off: -1 <dsl_pm_ipv4_1_0_walk>
dsl_pm_ipv4_1_0_case_1_skip:
	 48: MovReg dst: r3 src: r3
	 49: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_1_0_walk:
	 50: MovReg dst: r3 src: r3
	 51: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 52: MovReg dst: r3 src: r4
	 53: SubImm dst: r3 imm: 20
	 54: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 55: MovReg dst: r5 src: r0
	 56: AddReg dst: r5 src: r3
	 57: AddImm dst: r5 imm: 1
	 58: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 59: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 60: AndImm dst: r5 imm: 15
	 61: LShImm dst: r5 imm: 2
	 62: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 63: SubImm dst: r5 imm: 20
	 64: AddReg dst: r4 src: r5
	 65: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 66: MovReg dst: r3 src: r0
	 67: AddReg dst: r3 src: r4
	 68: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 69: Ja off: -1 <dsl_pm_ipv4_1_0_done>
dsl_pm_ipv4_1_0_done:
	 70: MovReg dst: r0 src: r0
	 71: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	 72: AddReg dst: r3 src: r0
	 73: LdXMemB dst: r3 src: r3 off: 9 imm: 0
	 74: JNEImm dst: r3 off: -1 imm: 6 <dsl_reject>
	 75: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 76: MovImm dst: r3 imm: 0
	 77: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 78: MovReg dst: r3 src: r0
	 79: AddReg dst: r3 src: r4
	 80: AddImm dst: r3 imm: 20
	 81: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 82: MovReg dst: r3 src: r4
	 83: AddImm dst: r3 imm: 2
	 84: JGTImm dst: r3 off: -1 imm: 510 <dsl_reject>
	 85: AddReg dst: r3 src: r0
	 86: AddImm dst: r3 imm: 2
	 87: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 88: LdXMemH dst: r3 src: r3 off: -2 imm: 0
	 89: SwapBE dst: r3
	 90: StXMemH dst: rfp src: r3 off: -30 imm: 0
	 91: AddImm dst: r4 imm: 20
	 92: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 93: MovReg dst: r3 src: r4
	 94: SubImm dst: r3 imm: 8
	 95: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 96: MovReg dst: r5 src: r0
	 97: AddReg dst: r5 src: r3
	 98: AddImm dst: r5 imm: 1
	 99: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	100: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	101: AndImm dst: r5 imm: 240
	102: RShImm dst: r5 imm: 4
	103: LShImm dst: r5 imm: 2
	104: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	105: SubImm dst: r5 imm: 20
	106: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	107: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	108: MovReg dst: r5 src: r4
	109: SubImm dst: r5 imm: 8
	110: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	111: MovReg dst: r3 src: r0
	112: AddReg dst: r3 src: r5
	113: AddImm dst: r3 imm: 1
	114: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	115: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	116: RShImm dst: r3 imm: 4
	117: AndImm dst: r3 imm: 15
	118: JNEImm dst: r3 off: -1 imm: 5 <dsl_pm_tcp_2_0_case_1_skip>
	119: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_case_1_skip:
	120: MovReg dst: r3 src: r3
	121: Ja off: -1 <dsl_pm_tcp_2_0_parse_options>
dsl_pm_tcp_2_0_parse_options:
	122: MovReg dst: r3 src: r3
	123: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	124: MovReg dst: r3 src: r4
	125: SubImm dst: r3 imm: 8
	126: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	127: MovReg dst: r5 src: r0
	128: AddReg dst: r5 src: r3
	129: AddImm dst: r5 imm: 1
	130: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	131: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	132: AndImm dst: r5 imm: 240
	133: RShImm dst: r5 imm: 4
	134: LShImm dst: r5 imm: 2
	135: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	136: SubImm dst: r5 imm: 20
	137: AddReg dst: r4 src: r5
	138: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	139: MovReg dst: r3 src: r0
	140: AddReg dst: r3 src: r4
	141: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	142: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_done:
	143: MovReg dst: r0 src: r0
	144: MovImm dst: r2 imm: 1
	145: Ja off: -1 <filter_result>
dsl_reject:
	146: MovImm dst: r2 imm: 0
== Callbacks
== Funcs
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame true
== Extractions
hosts src off=-28 size=4
ports dport off=-30 size=2
== Warnings
