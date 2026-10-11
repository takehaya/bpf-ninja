# host: xdp_entry
# expr: eth/ipv4[src==10.0.0.0/8]/tcp where tcp.dport == 80
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
	 17: MovReg dst: r3 src: r4
	 18: AddImm dst: r3 imm: 12
	 19: JGTImm dst: r3 off: -1 imm: 508 <dsl_reject>
	 20: AddReg dst: r3 src: r0
	 21: AddImm dst: r3 imm: 4
	 22: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 23: LdXMemW dst: r3 src: r3 off: -4 imm: 0
	 24: AndImm dst: r3 imm: 255
	 25: LdImmDW dst: r5 imm: 10
	 27: JNEReg dst: r3 off: -1 src: r5 <dsl_reject>
	 28: AddImm dst: r4 imm: 20
	 29: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 30: MovReg dst: r3 src: r4
	 31: SubImm dst: r3 imm: 20
	 32: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 33: MovReg dst: r5 src: r0
	 34: AddReg dst: r5 src: r3
	 35: AddImm dst: r5 imm: 1
	 36: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 37: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 38: AndImm dst: r5 imm: 15
	 39: LShImm dst: r5 imm: 2
	 40: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 41: SubImm dst: r5 imm: 20
	 42: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 43: MovReg dst: r3 src: r0
	 44: AddReg dst: r3 src: r4
	 45: LdXMemB dst: r3 src: r3 off: -20 imm: 0
	 46: RShImm dst: r3 imm: 4
	 47: AndImm dst: r3 imm: 15
	 48: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_1_0_case_1_skip>
	 49: Ja off: -1 <dsl_pm_ipv4_1_0_walk>
dsl_pm_ipv4_1_0_case_1_skip:
	 50: MovReg dst: r3 src: r3
	 51: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_1_0_walk:
	 52: MovReg dst: r3 src: r3
	 53: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 54: MovReg dst: r3 src: r4
	 55: SubImm dst: r3 imm: 20
	 56: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 57: MovReg dst: r5 src: r0
	 58: AddReg dst: r5 src: r3
	 59: AddImm dst: r5 imm: 1
	 60: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 61: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 62: AndImm dst: r5 imm: 15
	 63: LShImm dst: r5 imm: 2
	 64: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 65: SubImm dst: r5 imm: 20
	 66: AddReg dst: r4 src: r5
	 67: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 68: MovReg dst: r3 src: r0
	 69: AddReg dst: r3 src: r4
	 70: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 71: Ja off: -1 <dsl_pm_ipv4_1_0_done>
dsl_pm_ipv4_1_0_done:
	 72: MovReg dst: r0 src: r0
	 73: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	 74: AddReg dst: r3 src: r0
	 75: LdXMemB dst: r3 src: r3 off: 9 imm: 0
	 76: JNEImm dst: r3 off: -1 imm: 6 <dsl_reject>
	 77: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 78: StXMemDW dst: rfp src: r4 off: -232 imm: 0
	 79: MovImm dst: r3 imm: 0
	 80: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 81: MovReg dst: r3 src: r0
	 82: AddReg dst: r3 src: r4
	 83: AddImm dst: r3 imm: 20
	 84: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 85: AddImm dst: r4 imm: 20
	 86: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 87: MovReg dst: r3 src: r4
	 88: SubImm dst: r3 imm: 8
	 89: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 90: MovReg dst: r5 src: r0
	 91: AddReg dst: r5 src: r3
	 92: AddImm dst: r5 imm: 1
	 93: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 94: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 95: AndImm dst: r5 imm: 240
	 96: RShImm dst: r5 imm: 4
	 97: LShImm dst: r5 imm: 2
	 98: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 99: SubImm dst: r5 imm: 20
	100: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	101: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	102: MovReg dst: r5 src: r4
	103: SubImm dst: r5 imm: 8
	104: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	105: MovReg dst: r3 src: r0
	106: AddReg dst: r3 src: r5
	107: AddImm dst: r3 imm: 1
	108: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	109: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	110: RShImm dst: r3 imm: 4
	111: AndImm dst: r3 imm: 15
	112: JNEImm dst: r3 off: -1 imm: 5 <dsl_pm_tcp_2_0_case_1_skip>
	113: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_case_1_skip:
	114: MovReg dst: r3 src: r3
	115: Ja off: -1 <dsl_pm_tcp_2_0_parse_options>
dsl_pm_tcp_2_0_parse_options:
	116: MovReg dst: r3 src: r3
	117: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	118: MovReg dst: r3 src: r4
	119: SubImm dst: r3 imm: 8
	120: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	121: MovReg dst: r5 src: r0
	122: AddReg dst: r5 src: r3
	123: AddImm dst: r5 imm: 1
	124: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	125: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	126: AndImm dst: r5 imm: 240
	127: RShImm dst: r5 imm: 4
	128: LShImm dst: r5 imm: 2
	129: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	130: SubImm dst: r5 imm: 20
	131: AddReg dst: r4 src: r5
	132: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	133: MovReg dst: r3 src: r0
	134: AddReg dst: r3 src: r4
	135: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	136: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_done:
	137: MovReg dst: r0 src: r0
	138: LdXMemDW dst: r3 src: rfp off: -232 imm: 0
	139: AddImm dst: r3 imm: 2
	140: JGTImm dst: r3 off: -1 imm: 510 <dsl_reject>
	141: AddReg dst: r3 src: r0
	142: AddImm dst: r3 imm: 2
	143: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	144: LdXMemH dst: r3 src: r3 off: -2 imm: 0
	145: SwapBE dst: r3
	146: StXMemDW dst: rfp src: r3 off: -56 imm: 0
	147: MovImm dst: r3 imm: 80
	148: LdXMemDW dst: r5 src: rfp off: -56 imm: 0
	149: JNEReg dst: r5 off: -1 src: r3 <dsl_reject>
	150: MovImm dst: r2 imm: 1
	151: Ja off: -1 <filter_result>
dsl_reject:
	152: MovImm dst: r2 imm: 0
== Callbacks
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame true
== Extractions
== Warnings
