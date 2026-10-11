# host: xdp_entry
# expr: eth/ipv4/tcp where tcp.dport == 443
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
	 67: StXMemDW dst: rfp src: r4 off: -232 imm: 0
	 68: MovImm dst: r3 imm: 0
	 69: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 70: MovReg dst: r3 src: r0
	 71: AddReg dst: r3 src: r4
	 72: AddImm dst: r3 imm: 20
	 73: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 74: AddImm dst: r4 imm: 20
	 75: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 76: MovReg dst: r3 src: r4
	 77: SubImm dst: r3 imm: 8
	 78: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 79: MovReg dst: r5 src: r0
	 80: AddReg dst: r5 src: r3
	 81: AddImm dst: r5 imm: 1
	 82: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 83: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 84: AndImm dst: r5 imm: 240
	 85: RShImm dst: r5 imm: 4
	 86: LShImm dst: r5 imm: 2
	 87: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 88: SubImm dst: r5 imm: 20
	 89: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 90: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 91: MovReg dst: r5 src: r4
	 92: SubImm dst: r5 imm: 8
	 93: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	 94: MovReg dst: r3 src: r0
	 95: AddReg dst: r3 src: r5
	 96: AddImm dst: r3 imm: 1
	 97: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 98: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 99: RShImm dst: r3 imm: 4
	100: AndImm dst: r3 imm: 15
	101: JNEImm dst: r3 off: -1 imm: 5 <dsl_pm_tcp_2_0_case_1_skip>
	102: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_case_1_skip:
	103: MovReg dst: r3 src: r3
	104: Ja off: -1 <dsl_pm_tcp_2_0_parse_options>
dsl_pm_tcp_2_0_parse_options:
	105: MovReg dst: r3 src: r3
	106: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	107: MovReg dst: r3 src: r4
	108: SubImm dst: r3 imm: 8
	109: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	110: MovReg dst: r5 src: r0
	111: AddReg dst: r5 src: r3
	112: AddImm dst: r5 imm: 1
	113: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	114: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	115: AndImm dst: r5 imm: 240
	116: RShImm dst: r5 imm: 4
	117: LShImm dst: r5 imm: 2
	118: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	119: SubImm dst: r5 imm: 20
	120: AddReg dst: r4 src: r5
	121: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	122: MovReg dst: r3 src: r0
	123: AddReg dst: r3 src: r4
	124: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	125: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_done:
	126: MovReg dst: r0 src: r0
	127: LdXMemDW dst: r3 src: rfp off: -232 imm: 0
	128: AddImm dst: r3 imm: 2
	129: JGTImm dst: r3 off: -1 imm: 510 <dsl_reject>
	130: AddReg dst: r3 src: r0
	131: AddImm dst: r3 imm: 2
	132: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	133: LdXMemH dst: r3 src: r3 off: -2 imm: 0
	134: SwapBE dst: r3
	135: StXMemDW dst: rfp src: r3 off: -56 imm: 0
	136: MovImm dst: r3 imm: 443
	137: LdXMemDW dst: r5 src: rfp off: -56 imm: 0
	138: JNEReg dst: r5 off: -1 src: r3 <dsl_reject>
	139: MovImm dst: r2 imm: 1
	140: Ja off: -1 <filter_result>
dsl_reject:
	141: MovImm dst: r2 imm: 0
== Callbacks
== Funcs
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame true
== Extractions
== Warnings
