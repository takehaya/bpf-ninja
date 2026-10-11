# host: netfilter_entry
# expr: ipv4/tcp where tcp.dport == 443
# sets: -
== Main
	  0: MovImm dst: r4 imm: 0
	  1: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	  2: MovImm dst: r3 imm: 0
	  3: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	  4: MovReg dst: r3 src: r0
	  5: AddReg dst: r3 src: r4
	  6: AddImm dst: r3 imm: 20
	  7: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	  8: AddImm dst: r4 imm: 20
	  9: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 10: MovReg dst: r3 src: r4
	 11: SubImm dst: r3 imm: 20
	 12: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 13: MovReg dst: r5 src: r0
	 14: AddReg dst: r5 src: r3
	 15: AddImm dst: r5 imm: 1
	 16: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 17: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 18: AndImm dst: r5 imm: 15
	 19: LShImm dst: r5 imm: 2
	 20: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 21: SubImm dst: r5 imm: 20
	 22: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 23: MovReg dst: r3 src: r0
	 24: AddReg dst: r3 src: r4
	 25: LdXMemB dst: r3 src: r3 off: -20 imm: 0
	 26: RShImm dst: r3 imm: 4
	 27: AndImm dst: r3 imm: 15
	 28: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_0_0_case_1_skip>
	 29: Ja off: -1 <dsl_pm_ipv4_0_0_walk>
dsl_pm_ipv4_0_0_case_1_skip:
	 30: MovReg dst: r3 src: r3
	 31: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_0_0_walk:
	 32: MovReg dst: r3 src: r3
	 33: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 34: MovReg dst: r3 src: r4
	 35: SubImm dst: r3 imm: 20
	 36: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 37: MovReg dst: r5 src: r0
	 38: AddReg dst: r5 src: r3
	 39: AddImm dst: r5 imm: 1
	 40: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 41: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 42: AndImm dst: r5 imm: 15
	 43: LShImm dst: r5 imm: 2
	 44: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 45: SubImm dst: r5 imm: 20
	 46: AddReg dst: r4 src: r5
	 47: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 48: MovReg dst: r3 src: r0
	 49: AddReg dst: r3 src: r4
	 50: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 51: Ja off: -1 <dsl_pm_ipv4_0_0_done>
dsl_pm_ipv4_0_0_done:
	 52: MovReg dst: r0 src: r0
	 53: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	 54: AddReg dst: r3 src: r0
	 55: LdXMemB dst: r3 src: r3 off: 9 imm: 0
	 56: JNEImm dst: r3 off: -1 imm: 6 <dsl_reject>
	 57: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 58: StXMemDW dst: rfp src: r4 off: -232 imm: 0
	 59: MovImm dst: r3 imm: 0
	 60: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 61: MovReg dst: r3 src: r0
	 62: AddReg dst: r3 src: r4
	 63: AddImm dst: r3 imm: 20
	 64: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 65: AddImm dst: r4 imm: 20
	 66: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 67: MovReg dst: r3 src: r4
	 68: SubImm dst: r3 imm: 8
	 69: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 70: MovReg dst: r5 src: r0
	 71: AddReg dst: r5 src: r3
	 72: AddImm dst: r5 imm: 1
	 73: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 74: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 75: AndImm dst: r5 imm: 240
	 76: RShImm dst: r5 imm: 4
	 77: LShImm dst: r5 imm: 2
	 78: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 79: SubImm dst: r5 imm: 20
	 80: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 81: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 82: MovReg dst: r5 src: r4
	 83: SubImm dst: r5 imm: 8
	 84: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	 85: MovReg dst: r3 src: r0
	 86: AddReg dst: r3 src: r5
	 87: AddImm dst: r3 imm: 1
	 88: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 89: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 90: RShImm dst: r3 imm: 4
	 91: AndImm dst: r3 imm: 15
	 92: JNEImm dst: r3 off: -1 imm: 5 <dsl_pm_tcp_1_0_case_1_skip>
	 93: Ja off: -1 <dsl_pm_tcp_1_0_done>
dsl_pm_tcp_1_0_case_1_skip:
	 94: MovReg dst: r3 src: r3
	 95: Ja off: -1 <dsl_pm_tcp_1_0_parse_options>
dsl_pm_tcp_1_0_parse_options:
	 96: MovReg dst: r3 src: r3
	 97: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 98: MovReg dst: r3 src: r4
	 99: SubImm dst: r3 imm: 8
	100: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	101: MovReg dst: r5 src: r0
	102: AddReg dst: r5 src: r3
	103: AddImm dst: r5 imm: 1
	104: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	105: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	106: AndImm dst: r5 imm: 240
	107: RShImm dst: r5 imm: 4
	108: LShImm dst: r5 imm: 2
	109: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	110: SubImm dst: r5 imm: 20
	111: AddReg dst: r4 src: r5
	112: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	113: MovReg dst: r3 src: r0
	114: AddReg dst: r3 src: r4
	115: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	116: Ja off: -1 <dsl_pm_tcp_1_0_done>
dsl_pm_tcp_1_0_done:
	117: MovReg dst: r0 src: r0
	118: LdXMemDW dst: r3 src: rfp off: -232 imm: 0
	119: AddImm dst: r3 imm: 2
	120: JGTImm dst: r3 off: -1 imm: 510 <dsl_reject>
	121: AddReg dst: r3 src: r0
	122: AddImm dst: r3 imm: 2
	123: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	124: LdXMemH dst: r3 src: r3 off: -2 imm: 0
	125: SwapBE dst: r3
	126: StXMemDW dst: rfp src: r3 off: -56 imm: 0
	127: MovImm dst: r3 imm: 443
	128: LdXMemDW dst: r5 src: rfp off: -56 imm: 0
	129: JNEReg dst: r5 off: -1 src: r3 <dsl_reject>
	130: MovImm dst: r2 imm: 1
	131: Ja off: -1 <filter_result>
dsl_reject:
	132: MovImm dst: r2 imm: 0
== Callbacks
== Funcs
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame false
== Extractions
== Warnings
