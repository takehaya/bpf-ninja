# host: xdp_entry
# expr: eth/mpls[label in [1..5, 100]]{1,3}/ipv4
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
	 14: MovReg dst: r3 src: r4
	 15: JGTImm dst: r3 off: -1 imm: 508 <dsl_reject>
	 16: AddReg dst: r3 src: r0
	 17: AddImm dst: r3 imm: 4
	 18: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 19: LdXMemW dst: r3 src: r3 off: -4 imm: 0
	 20: SwapBE dst: r3
	 21: RShImm dst: r3 imm: 12
	 22: AndImm dst: r3 imm: 1048575
	 23: JLTImm dst: r3 off: -1 imm: 1 <dsl_pred_in_next_1>
	 24: JLEImm dst: r3 off: -1 imm: 5 <dsl_pred_match_1>
dsl_pred_in_next_1:
	 25: JEqImm dst: r3 off: -1 imm: 100 <dsl_pred_match_1>
	 26: Ja off: -1 <dsl_reject>
dsl_pred_match_1:
	 27: MovReg dst: r3 src: r3
	 28: AddImm dst: r4 imm: 4
	 29: JLTImm dst: r4 off: -1 imm: 2 <dsl_chain_done_1>
	 30: MovReg dst: r3 src: r4
	 31: SubImm dst: r3 imm: 2
	 32: JGTImm dst: r3 off: -1 imm: 511 <dsl_chain_done_1>
	 33: MovReg dst: r5 src: r0
	 34: AddReg dst: r5 src: r3
	 35: AddImm dst: r5 imm: 1
	 36: JGTReg dst: r5 off: -1 src: r1 <dsl_chain_done_1>
	 37: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 38: AndImm dst: r5 imm: 1
	 39: JEqImm dst: r5 off: -1 imm: 1 <dsl_chain_done_1>
	 40: MovReg dst: r3 src: r0
	 41: AddReg dst: r3 src: r4
	 42: AddImm dst: r3 imm: 4
	 43: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 44: MovReg dst: r3 src: r4
	 45: JGTImm dst: r3 off: -1 imm: 508 <dsl_reject>
	 46: AddReg dst: r3 src: r0
	 47: AddImm dst: r3 imm: 4
	 48: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 49: LdXMemW dst: r3 src: r3 off: -4 imm: 0
	 50: SwapBE dst: r3
	 51: RShImm dst: r3 imm: 12
	 52: AndImm dst: r3 imm: 1048575
	 53: JLTImm dst: r3 off: -1 imm: 1 <dsl_pred_in_next_2>
	 54: JLEImm dst: r3 off: -1 imm: 5 <dsl_pred_match_2>
dsl_pred_in_next_2:
	 55: JEqImm dst: r3 off: -1 imm: 100 <dsl_pred_match_2>
	 56: Ja off: -1 <dsl_reject>
dsl_pred_match_2:
	 57: MovReg dst: r3 src: r3
	 58: AddImm dst: r4 imm: 4
	 59: JLTImm dst: r4 off: -1 imm: 2 <dsl_chain_done_1>
	 60: MovReg dst: r3 src: r4
	 61: SubImm dst: r3 imm: 2
	 62: JGTImm dst: r3 off: -1 imm: 511 <dsl_chain_done_1>
	 63: MovReg dst: r5 src: r0
	 64: AddReg dst: r5 src: r3
	 65: AddImm dst: r5 imm: 1
	 66: JGTReg dst: r5 off: -1 src: r1 <dsl_chain_done_1>
	 67: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 68: AndImm dst: r5 imm: 1
	 69: JEqImm dst: r5 off: -1 imm: 1 <dsl_chain_done_1>
	 70: MovReg dst: r3 src: r0
	 71: AddReg dst: r3 src: r4
	 72: AddImm dst: r3 imm: 4
	 73: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 74: MovReg dst: r3 src: r4
	 75: JGTImm dst: r3 off: -1 imm: 508 <dsl_reject>
	 76: AddReg dst: r3 src: r0
	 77: AddImm dst: r3 imm: 4
	 78: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 79: LdXMemW dst: r3 src: r3 off: -4 imm: 0
	 80: SwapBE dst: r3
	 81: RShImm dst: r3 imm: 12
	 82: AndImm dst: r3 imm: 1048575
	 83: JLTImm dst: r3 off: -1 imm: 1 <dsl_pred_in_next_3>
	 84: JLEImm dst: r3 off: -1 imm: 5 <dsl_pred_match_3>
dsl_pred_in_next_3:
	 85: JEqImm dst: r3 off: -1 imm: 100 <dsl_pred_match_3>
	 86: Ja off: -1 <dsl_reject>
dsl_pred_match_3:
	 87: MovReg dst: r3 src: r3
	 88: AddImm dst: r4 imm: 4
	 89: JLTImm dst: r4 off: -1 imm: 2 <dsl_reject>
	 90: MovReg dst: r3 src: r4
	 91: SubImm dst: r3 imm: 2
	 92: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 93: MovReg dst: r5 src: r0
	 94: AddReg dst: r5 src: r3
	 95: AddImm dst: r5 imm: 1
	 96: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 97: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 98: AndImm dst: r5 imm: 1
	 99: JNEImm dst: r5 off: -1 imm: 1 <dsl_reject>
dsl_chain_done_1:
	100: MovReg dst: r3 src: r3
	101: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	102: MovImm dst: r3 imm: 0
	103: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	104: MovReg dst: r3 src: r0
	105: AddReg dst: r3 src: r4
	106: AddImm dst: r3 imm: 20
	107: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	108: AddImm dst: r4 imm: 20
	109: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	110: MovReg dst: r3 src: r4
	111: SubImm dst: r3 imm: 20
	112: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	113: MovReg dst: r5 src: r0
	114: AddReg dst: r5 src: r3
	115: AddImm dst: r5 imm: 1
	116: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	117: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	118: AndImm dst: r5 imm: 15
	119: LShImm dst: r5 imm: 2
	120: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	121: SubImm dst: r5 imm: 20
	122: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	123: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	124: MovReg dst: r5 src: r4
	125: SubImm dst: r5 imm: 20
	126: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	127: MovReg dst: r3 src: r0
	128: AddReg dst: r3 src: r5
	129: AddImm dst: r3 imm: 1
	130: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	131: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	132: RShImm dst: r3 imm: 4
	133: AndImm dst: r3 imm: 15
	134: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_2_0_case_1_skip>
	135: Ja off: -1 <dsl_pm_ipv4_2_0_walk>
dsl_pm_ipv4_2_0_case_1_skip:
	136: MovReg dst: r3 src: r3
	137: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_2_0_walk:
	138: MovReg dst: r3 src: r3
	139: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	140: MovReg dst: r3 src: r4
	141: SubImm dst: r3 imm: 20
	142: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	143: MovReg dst: r5 src: r0
	144: AddReg dst: r5 src: r3
	145: AddImm dst: r5 imm: 1
	146: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	147: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	148: AndImm dst: r5 imm: 15
	149: LShImm dst: r5 imm: 2
	150: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	151: SubImm dst: r5 imm: 20
	152: AddReg dst: r4 src: r5
	153: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	154: MovReg dst: r3 src: r0
	155: AddReg dst: r3 src: r4
	156: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	157: Ja off: -1 <dsl_pm_ipv4_2_0_done>
dsl_pm_ipv4_2_0_done:
	158: MovReg dst: r0 src: r0
	159: MovImm dst: r2 imm: 1
	160: Ja off: -1 <filter_result>
dsl_reject:
	161: MovImm dst: r2 imm: 0
== Callbacks
== Funcs
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame true
== Extractions
== Warnings
