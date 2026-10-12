# host: xdp_entry
# expr: eth/mpls[label in [1..5, 100]]+/ipv4
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
	 23: JLTImm dst: r3 off: -1 imm: 1 <dsl_pred_in_next_2>
	 24: JLEImm dst: r3 off: -1 imm: 5 <dsl_pred_match_2>
dsl_pred_in_next_2:
	 25: JEqImm dst: r3 off: -1 imm: 100 <dsl_pred_match_2>
	 26: Ja off: -1 <dsl_reject>
dsl_pred_match_2:
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
	 40: StXMemDW dst: rfp src: r4 off: -208 imm: 0
	 41: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 42: StXMemDW dst: rfp src: r0 off: -200 imm: 0
	 43: StXMemDW dst: rfp src: r1 off: -192 imm: 0
	 44: MovImm dst: r1 imm: 7
	 45: LdImmDW dst: r2 imm: -1 <dsl_chain_cb_1>
	 47: MovReg dst: r3 src: rfp
	 48: AddImm dst: r3 imm: -208
	 49: MovImm dst: r4 imm: 0
	 50: Call FnLoop
	 51: LdXMemDW dst: r4 src: rfp off: -208 imm: 0
	 52: LdXMemDW dst: r0 src: rfp off: -200 imm: 0
	 53: LdXMemDW dst: r1 src: rfp off: -192 imm: 0
	 54: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 55: JLTImm dst: r4 off: -1 imm: 2 <dsl_reject>
	 56: MovReg dst: r3 src: r4
	 57: SubImm dst: r3 imm: 2
	 58: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 59: MovReg dst: r5 src: r0
	 60: AddReg dst: r5 src: r3
	 61: AddImm dst: r5 imm: 1
	 62: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 63: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 64: AndImm dst: r5 imm: 1
	 65: JNEImm dst: r5 off: -1 imm: 1 <dsl_reject>
dsl_chain_done_1:
	 66: MovReg dst: r0 src: r0
	 67: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 68: MovImm dst: r3 imm: 0
	 69: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 70: MovReg dst: r3 src: r0
	 71: AddReg dst: r3 src: r4
	 72: AddImm dst: r3 imm: 20
	 73: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 74: AddImm dst: r4 imm: 20
	 75: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 76: MovReg dst: r3 src: r4
	 77: SubImm dst: r3 imm: 20
	 78: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 79: MovReg dst: r5 src: r0
	 80: AddReg dst: r5 src: r3
	 81: AddImm dst: r5 imm: 1
	 82: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 83: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 84: AndImm dst: r5 imm: 15
	 85: LShImm dst: r5 imm: 2
	 86: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 87: SubImm dst: r5 imm: 20
	 88: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 89: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 90: MovReg dst: r5 src: r4
	 91: SubImm dst: r5 imm: 20
	 92: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	 93: MovReg dst: r3 src: r0
	 94: AddReg dst: r3 src: r5
	 95: AddImm dst: r3 imm: 1
	 96: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 97: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 98: RShImm dst: r3 imm: 4
	 99: AndImm dst: r3 imm: 15
	100: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_2_0_case_1_skip>
	101: Ja off: -1 <dsl_pm_ipv4_2_0_walk>
dsl_pm_ipv4_2_0_case_1_skip:
	102: MovReg dst: r3 src: r3
	103: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_2_0_walk:
	104: MovReg dst: r3 src: r3
	105: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	106: MovReg dst: r3 src: r4
	107: SubImm dst: r3 imm: 20
	108: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	109: MovReg dst: r5 src: r0
	110: AddReg dst: r5 src: r3
	111: AddImm dst: r5 imm: 1
	112: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	113: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	114: AndImm dst: r5 imm: 15
	115: LShImm dst: r5 imm: 2
	116: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	117: SubImm dst: r5 imm: 20
	118: AddReg dst: r4 src: r5
	119: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	120: MovReg dst: r3 src: r0
	121: AddReg dst: r3 src: r4
	122: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	123: Ja off: -1 <dsl_pm_ipv4_2_0_done>
dsl_pm_ipv4_2_0_done:
	124: MovReg dst: r0 src: r0
	125: MovImm dst: r2 imm: 1
	126: Ja off: -1 <filter_result>
dsl_reject:
	127: MovImm dst: r2 imm: 0
== Callbacks
dsl_chain_cb_1:
	 0: LdXMemDW dst: r3 src: r2 off: 0 imm: 0
	 1: LdXMemDW dst: r4 src: r2 off: 8 imm: 0
	 2: LdXMemDW dst: r5 src: r2 off: 16 imm: 0
	 3: MovReg dst: r6 src: r2
	 4: JGTImm dst: r3 off: -1 imm: 512 <dsl_chain_cb_1_reject>
	 5: MovReg dst: r0 src: r4
	 6: AddReg dst: r0 src: r3
	 7: AddImm dst: r0 imm: 4
	 8: JGTReg dst: r0 off: -1 src: r5 <dsl_chain_cb_1_reject>
	 9: MovReg dst: r0 src: r4
	10: MovReg dst: r1 src: r5
	11: MovReg dst: r4 src: r3
	12: MovReg dst: r3 src: r4
	13: JGTImm dst: r3 off: -1 imm: 508 <dsl_chain_cb_1_reject>
	14: AddReg dst: r3 src: r0
	15: AddImm dst: r3 imm: 4
	16: JGTReg dst: r3 off: -1 src: r1 <dsl_chain_cb_1_reject>
	17: LdXMemW dst: r3 src: r3 off: -4 imm: 0
	18: SwapBE dst: r3
	19: RShImm dst: r3 imm: 12
	20: AndImm dst: r3 imm: 1048575
	21: JLTImm dst: r3 off: -1 imm: 1 <dsl_pred_in_next_1>
	22: JLEImm dst: r3 off: -1 imm: 5 <dsl_pred_match_1>
dsl_pred_in_next_1:
	23: JEqImm dst: r3 off: -1 imm: 100 <dsl_pred_match_1>
	24: Ja off: -1 <dsl_chain_cb_1_reject>
dsl_pred_match_1:
	25: MovReg dst: r3 src: r3
	26: MovReg dst: r2 src: r6
	27: LdXMemDW dst: r3 src: r2 off: 0 imm: 0
	28: LdXMemDW dst: r4 src: r2 off: 8 imm: 0
	29: LdXMemDW dst: r5 src: r2 off: 16 imm: 0
	30: AddImm dst: r3 imm: 4
	31: StXMemDW dst: r2 src: r3 off: 0 imm: 0
	32: JLTImm dst: r3 off: -1 imm: 2 <dsl_chain_cb_1_break>
	33: MovReg dst: r1 src: r3
	34: SubImm dst: r1 imm: 2
	35: JGTImm dst: r1 off: -1 imm: 511 <dsl_chain_cb_1_break>
	36: MovReg dst: r0 src: r4
	37: AddReg dst: r0 src: r1
	38: AddImm dst: r0 imm: 1
	39: JGTReg dst: r0 off: -1 src: r5 <dsl_chain_cb_1_break>
	40: LdXMemB dst: r0 src: r0 off: -1 imm: 0
	41: AndImm dst: r0 imm: 1
	42: JEqImm dst: r0 off: -1 imm: 1 <dsl_chain_cb_1_break>
	43: MovImm dst: r0 imm: 0
	44: Exit
dsl_chain_cb_1_reject:
	45: MovImm dst: r0 imm: -1
	46: MovReg dst: r2 src: r6
	47: StXMemDW dst: r2 src: r0 off: 0 imm: 0
dsl_chain_cb_1_break:
	48: MovImm dst: r0 imm: 1
	49: Exit
== Funcs
127: dsl_chain_cb_1
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame true
== Extractions
== Warnings
