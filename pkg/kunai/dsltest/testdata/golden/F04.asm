# host: xdp_entry
# expr: eth/vlan[tci==100]/ipv4/tcp where tcp.dport == 80
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
	 13: JNEImm dst: r3 off: -1 imm: 129 <dsl_reject>
	 14: MovReg dst: r3 src: r4
	 15: JGTImm dst: r3 off: -1 imm: 510 <dsl_reject>
	 16: AddReg dst: r3 src: r0
	 17: AddImm dst: r3 imm: 2
	 18: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 19: LdXMemH dst: r3 src: r3 off: -2 imm: 0
	 20: JNEImm dst: r3 off: -1 imm: 25600 <dsl_reject>
	 21: AddImm dst: r4 imm: 4
	 22: MovReg dst: r3 src: r0
	 23: AddReg dst: r3 src: r4
	 24: LdXMemH dst: r3 src: r3 off: -2 imm: 0
	 25: JNEImm dst: r3 off: -1 imm: 8 <dsl_reject>
	 26: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 27: MovImm dst: r3 imm: 0
	 28: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 29: MovReg dst: r3 src: r0
	 30: AddReg dst: r3 src: r4
	 31: AddImm dst: r3 imm: 20
	 32: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 33: AddImm dst: r4 imm: 20
	 34: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 35: MovReg dst: r3 src: r4
	 36: SubImm dst: r3 imm: 20
	 37: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 38: MovReg dst: r5 src: r0
	 39: AddReg dst: r5 src: r3
	 40: AddImm dst: r5 imm: 1
	 41: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 42: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 43: AndImm dst: r5 imm: 15
	 44: LShImm dst: r5 imm: 2
	 45: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 46: SubImm dst: r5 imm: 20
	 47: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 48: MovReg dst: r3 src: r0
	 49: AddReg dst: r3 src: r4
	 50: LdXMemB dst: r3 src: r3 off: -20 imm: 0
	 51: RShImm dst: r3 imm: 4
	 52: AndImm dst: r3 imm: 15
	 53: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_2_0_case_1_skip>
	 54: Ja off: -1 <dsl_pm_ipv4_2_0_walk>
dsl_pm_ipv4_2_0_case_1_skip:
	 55: MovReg dst: r3 src: r3
	 56: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_2_0_walk:
	 57: MovReg dst: r3 src: r3
	 58: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 59: MovReg dst: r3 src: r4
	 60: SubImm dst: r3 imm: 20
	 61: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 62: MovReg dst: r5 src: r0
	 63: AddReg dst: r5 src: r3
	 64: AddImm dst: r5 imm: 1
	 65: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 66: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 67: AndImm dst: r5 imm: 15
	 68: LShImm dst: r5 imm: 2
	 69: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 70: SubImm dst: r5 imm: 20
	 71: AddReg dst: r4 src: r5
	 72: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 73: MovReg dst: r3 src: r0
	 74: AddReg dst: r3 src: r4
	 75: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 76: Ja off: -1 <dsl_pm_ipv4_2_0_done>
dsl_pm_ipv4_2_0_done:
	 77: MovReg dst: r0 src: r0
	 78: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	 79: AddReg dst: r3 src: r0
	 80: LdXMemB dst: r3 src: r3 off: 9 imm: 0
	 81: JNEImm dst: r3 off: -1 imm: 6 <dsl_reject>
	 82: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 83: StXMemDW dst: rfp src: r4 off: -232 imm: 0
	 84: MovImm dst: r3 imm: 0
	 85: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 86: MovReg dst: r3 src: r0
	 87: AddReg dst: r3 src: r4
	 88: AddImm dst: r3 imm: 20
	 89: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 90: AddImm dst: r4 imm: 20
	 91: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 92: MovReg dst: r3 src: r4
	 93: SubImm dst: r3 imm: 8
	 94: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 95: MovReg dst: r5 src: r0
	 96: AddReg dst: r5 src: r3
	 97: AddImm dst: r5 imm: 1
	 98: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 99: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	100: AndImm dst: r5 imm: 240
	101: RShImm dst: r5 imm: 4
	102: LShImm dst: r5 imm: 2
	103: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	104: SubImm dst: r5 imm: 20
	105: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	106: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	107: MovReg dst: r5 src: r4
	108: SubImm dst: r5 imm: 8
	109: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	110: MovReg dst: r3 src: r0
	111: AddReg dst: r3 src: r5
	112: AddImm dst: r3 imm: 1
	113: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	114: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	115: RShImm dst: r3 imm: 4
	116: AndImm dst: r3 imm: 15
	117: JNEImm dst: r3 off: -1 imm: 5 <dsl_pm_tcp_3_0_case_1_skip>
	118: Ja off: -1 <dsl_pm_tcp_3_0_done>
dsl_pm_tcp_3_0_case_1_skip:
	119: MovReg dst: r3 src: r3
	120: Ja off: -1 <dsl_pm_tcp_3_0_parse_options>
dsl_pm_tcp_3_0_parse_options:
	121: MovReg dst: r3 src: r3
	122: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	123: MovReg dst: r3 src: r4
	124: SubImm dst: r3 imm: 8
	125: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	126: MovReg dst: r5 src: r0
	127: AddReg dst: r5 src: r3
	128: AddImm dst: r5 imm: 1
	129: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	130: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	131: AndImm dst: r5 imm: 240
	132: RShImm dst: r5 imm: 4
	133: LShImm dst: r5 imm: 2
	134: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	135: SubImm dst: r5 imm: 20
	136: AddReg dst: r4 src: r5
	137: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	138: MovReg dst: r3 src: r0
	139: AddReg dst: r3 src: r4
	140: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	141: Ja off: -1 <dsl_pm_tcp_3_0_done>
dsl_pm_tcp_3_0_done:
	142: MovReg dst: r0 src: r0
	143: LdXMemDW dst: r3 src: rfp off: -232 imm: 0
	144: AddImm dst: r3 imm: 2
	145: JGTImm dst: r3 off: -1 imm: 510 <dsl_reject>
	146: AddReg dst: r3 src: r0
	147: AddImm dst: r3 imm: 2
	148: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	149: LdXMemH dst: r3 src: r3 off: -2 imm: 0
	150: SwapBE dst: r3
	151: StXMemDW dst: rfp src: r3 off: -56 imm: 0
	152: MovImm dst: r3 imm: 80
	153: LdXMemDW dst: r5 src: rfp off: -56 imm: 0
	154: JNEReg dst: r5 off: -1 src: r3 <dsl_reject>
	155: MovImm dst: r2 imm: 1
	156: Ja off: -1 <filter_result>
dsl_reject:
	157: MovImm dst: r2 imm: 0
== Callbacks
== Funcs
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame true
== Extractions
== Warnings
