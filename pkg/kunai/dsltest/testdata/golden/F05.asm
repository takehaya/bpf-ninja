# host: xdp_entry
# expr: eth/qinq/vlan/ipv4/tcp where tcp.dport == 80
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
	 13: JNEImm dst: r3 off: -1 imm: 43144 <dsl_reject>
	 14: AddImm dst: r4 imm: 4
	 15: MovReg dst: r3 src: r0
	 16: AddReg dst: r3 src: r4
	 17: AddImm dst: r3 imm: 4
	 18: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 19: MovReg dst: r3 src: r0
	 20: AddReg dst: r3 src: r4
	 21: LdXMemH dst: r3 src: r3 off: -2 imm: 0
	 22: JNEImm dst: r3 off: -1 imm: 129 <dsl_reject>
	 23: AddImm dst: r4 imm: 4
	 24: MovReg dst: r3 src: r0
	 25: AddReg dst: r3 src: r4
	 26: LdXMemH dst: r3 src: r3 off: -2 imm: 0
	 27: JNEImm dst: r3 off: -1 imm: 8 <dsl_reject>
	 28: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 29: MovImm dst: r3 imm: 0
	 30: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 31: MovReg dst: r3 src: r0
	 32: AddReg dst: r3 src: r4
	 33: AddImm dst: r3 imm: 20
	 34: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 35: AddImm dst: r4 imm: 20
	 36: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 37: MovReg dst: r3 src: r4
	 38: SubImm dst: r3 imm: 20
	 39: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 40: MovReg dst: r5 src: r0
	 41: AddReg dst: r5 src: r3
	 42: AddImm dst: r5 imm: 1
	 43: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 44: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 45: AndImm dst: r5 imm: 15
	 46: LShImm dst: r5 imm: 2
	 47: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 48: SubImm dst: r5 imm: 20
	 49: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 50: MovReg dst: r3 src: r0
	 51: AddReg dst: r3 src: r4
	 52: LdXMemB dst: r3 src: r3 off: -20 imm: 0
	 53: RShImm dst: r3 imm: 4
	 54: AndImm dst: r3 imm: 15
	 55: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_3_0_case_1_skip>
	 56: Ja off: -1 <dsl_pm_ipv4_3_0_walk>
dsl_pm_ipv4_3_0_case_1_skip:
	 57: MovReg dst: r3 src: r3
	 58: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_3_0_walk:
	 59: MovReg dst: r3 src: r3
	 60: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 61: MovReg dst: r3 src: r4
	 62: SubImm dst: r3 imm: 20
	 63: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 64: MovReg dst: r5 src: r0
	 65: AddReg dst: r5 src: r3
	 66: AddImm dst: r5 imm: 1
	 67: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 68: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 69: AndImm dst: r5 imm: 15
	 70: LShImm dst: r5 imm: 2
	 71: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 72: SubImm dst: r5 imm: 20
	 73: AddReg dst: r4 src: r5
	 74: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 75: MovReg dst: r3 src: r0
	 76: AddReg dst: r3 src: r4
	 77: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 78: Ja off: -1 <dsl_pm_ipv4_3_0_done>
dsl_pm_ipv4_3_0_done:
	 79: MovReg dst: r0 src: r0
	 80: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	 81: AddReg dst: r3 src: r0
	 82: LdXMemB dst: r3 src: r3 off: 9 imm: 0
	 83: JNEImm dst: r3 off: -1 imm: 6 <dsl_reject>
	 84: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 85: StXMemDW dst: rfp src: r4 off: -232 imm: 0
	 86: MovImm dst: r3 imm: 0
	 87: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 88: MovReg dst: r3 src: r0
	 89: AddReg dst: r3 src: r4
	 90: AddImm dst: r3 imm: 20
	 91: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 92: AddImm dst: r4 imm: 20
	 93: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 94: MovReg dst: r3 src: r4
	 95: SubImm dst: r3 imm: 8
	 96: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 97: MovReg dst: r5 src: r0
	 98: AddReg dst: r5 src: r3
	 99: AddImm dst: r5 imm: 1
	100: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	101: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	102: AndImm dst: r5 imm: 240
	103: RShImm dst: r5 imm: 4
	104: LShImm dst: r5 imm: 2
	105: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	106: SubImm dst: r5 imm: 20
	107: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	108: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	109: MovReg dst: r5 src: r4
	110: SubImm dst: r5 imm: 8
	111: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	112: MovReg dst: r3 src: r0
	113: AddReg dst: r3 src: r5
	114: AddImm dst: r3 imm: 1
	115: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	116: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	117: RShImm dst: r3 imm: 4
	118: AndImm dst: r3 imm: 15
	119: JNEImm dst: r3 off: -1 imm: 5 <dsl_pm_tcp_4_0_case_1_skip>
	120: Ja off: -1 <dsl_pm_tcp_4_0_done>
dsl_pm_tcp_4_0_case_1_skip:
	121: MovReg dst: r3 src: r3
	122: Ja off: -1 <dsl_pm_tcp_4_0_parse_options>
dsl_pm_tcp_4_0_parse_options:
	123: MovReg dst: r3 src: r3
	124: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	125: MovReg dst: r3 src: r4
	126: SubImm dst: r3 imm: 8
	127: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	128: MovReg dst: r5 src: r0
	129: AddReg dst: r5 src: r3
	130: AddImm dst: r5 imm: 1
	131: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	132: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	133: AndImm dst: r5 imm: 240
	134: RShImm dst: r5 imm: 4
	135: LShImm dst: r5 imm: 2
	136: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	137: SubImm dst: r5 imm: 20
	138: AddReg dst: r4 src: r5
	139: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	140: MovReg dst: r3 src: r0
	141: AddReg dst: r3 src: r4
	142: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	143: Ja off: -1 <dsl_pm_tcp_4_0_done>
dsl_pm_tcp_4_0_done:
	144: MovReg dst: r0 src: r0
	145: LdXMemDW dst: r3 src: rfp off: -232 imm: 0
	146: AddImm dst: r3 imm: 2
	147: JGTImm dst: r3 off: -1 imm: 510 <dsl_reject>
	148: AddReg dst: r3 src: r0
	149: AddImm dst: r3 imm: 2
	150: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	151: LdXMemH dst: r3 src: r3 off: -2 imm: 0
	152: SwapBE dst: r3
	153: StXMemDW dst: rfp src: r3 off: -56 imm: 0
	154: MovImm dst: r3 imm: 80
	155: LdXMemDW dst: r5 src: rfp off: -56 imm: 0
	156: JNEReg dst: r5 off: -1 src: r3 <dsl_reject>
	157: MovImm dst: r2 imm: 1
	158: Ja off: -1 <filter_result>
dsl_reject:
	159: MovImm dst: r2 imm: 0
== Callbacks
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame true
== Extractions
== Warnings
