# host: tc_entry
# expr: eth/ipv4/tcp where tcp.options.MSS.value == 1460
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
	 68: MovImm dst: r3 imm: -1
	 69: StXMemDW dst: rfp src: r3 off: -240 imm: 0
	 70: MovImm dst: r3 imm: 0
	 71: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 72: MovReg dst: r3 src: r0
	 73: AddReg dst: r3 src: r4
	 74: AddImm dst: r3 imm: 20
	 75: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 76: AddImm dst: r4 imm: 20
	 77: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 78: MovReg dst: r3 src: r4
	 79: SubImm dst: r3 imm: 8
	 80: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 81: MovReg dst: r5 src: r0
	 82: AddReg dst: r5 src: r3
	 83: AddImm dst: r5 imm: 1
	 84: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 85: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 86: AndImm dst: r5 imm: 240
	 87: RShImm dst: r5 imm: 4
	 88: LShImm dst: r5 imm: 2
	 89: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 90: SubImm dst: r5 imm: 20
	 91: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 92: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 93: MovReg dst: r5 src: r4
	 94: SubImm dst: r5 imm: 8
	 95: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	 96: MovReg dst: r3 src: r0
	 97: AddReg dst: r3 src: r5
	 98: AddImm dst: r3 imm: 1
	 99: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	100: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	101: RShImm dst: r3 imm: 4
	102: AndImm dst: r3 imm: 15
	103: JNEImm dst: r3 off: -1 imm: 5 <dsl_pm_tcp_2_0_case_1_skip>
	104: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_case_1_skip:
	105: MovReg dst: r3 src: r3
	106: Ja off: -1 <dsl_pm_tcp_2_0_parse_options>
dsl_pm_tcp_2_0_parse_options:
	107: MovReg dst: r3 src: r3
	108: LdXMemDW dst: r3 src: rfp off: -216 imm: 0
	109: JGTImm dst: r3 off: -1 imm: 512 <dsl_reject>
	110: AddReg dst: r3 src: r4
	111: JGTImm dst: r3 off: -1 imm: 512 <dsl_reject>
	112: MovReg dst: r5 src: r0
	113: AddReg dst: r5 src: r3
	114: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	115: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	116: StXMemDW dst: rfp src: r4 off: -208 imm: 0
	117: StXMemDW dst: rfp src: r0 off: -200 imm: 0
	118: StXMemDW dst: rfp src: r1 off: -192 imm: 0
	119: MovImm dst: r1 imm: 41
	120: LdImmDW dst: r2 imm: -1 <dsl_pm_tcp_2_0_parse_options_cb>
	122: MovReg dst: r3 src: rfp
	123: AddImm dst: r3 imm: -208
	124: MovImm dst: r4 imm: 0
	125: Call FnLoop
	126: LdXMemDW dst: r4 src: rfp off: -208 imm: 0
	127: LdXMemDW dst: r0 src: rfp off: -200 imm: 0
	128: LdXMemDW dst: r1 src: rfp off: -192 imm: 0
	129: JGTImm dst: r4 off: -1 imm: 512 <dsl_pm_tcp_2_0_malformed_1>
	130: LdXMemDW dst: r4 src: rfp off: -216 imm: 0
	131: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_malformed_1:
	132: LdXMemDW dst: r4 src: rfp off: -184 imm: 0
	133: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	134: AddImm dst: r4 imm: 20
	135: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	136: MovImm dst: r3 imm: -1
	137: StXMemDW dst: rfp src: r3 off: -240 imm: 0
	138: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	139: MovReg dst: r3 src: r4
	140: SubImm dst: r3 imm: 8
	141: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	142: MovReg dst: r5 src: r0
	143: AddReg dst: r5 src: r3
	144: AddImm dst: r5 imm: 1
	145: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	146: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	147: AndImm dst: r5 imm: 240
	148: RShImm dst: r5 imm: 4
	149: LShImm dst: r5 imm: 2
	150: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	151: SubImm dst: r5 imm: 20
	152: AddReg dst: r4 src: r5
	153: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	154: MovReg dst: r3 src: r0
	155: AddReg dst: r3 src: r4
	156: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	157: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_done:
	158: MovReg dst: r0 src: r0
	159: LdXMemDW dst: r3 src: rfp off: -240 imm: 0
	160: JEqImm dst: r3 off: -1 imm: -1 <dsl_reject>
	161: MovReg dst: r5 src: r3
	162: AddImm dst: r5 imm: 2
	163: JGTImm dst: r5 off: -1 imm: 510 <dsl_reject>
	164: MovReg dst: r3 src: r0
	165: AddReg dst: r3 src: r5
	166: AddImm dst: r3 imm: 2
	167: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	168: LdXMemH dst: r3 src: r3 off: -2 imm: 0
	169: SwapBE dst: r3
	170: StXMemDW dst: rfp src: r3 off: -56 imm: 0
	171: MovImm dst: r3 imm: 1460
	172: LdXMemDW dst: r5 src: rfp off: -56 imm: 0
	173: JNEReg dst: r5 off: -1 src: r3 <dsl_reject>
	174: MovImm dst: r2 imm: 1
	175: Ja off: -1 <filter_result>
dsl_reject:
	176: MovImm dst: r2 imm: 0
== Callbacks
dsl_pm_tcp_2_0_parse_options_cb:
	  0: LdXMemDW dst: r3 src: r2 off: 0 imm: 0
	  1: LdXMemDW dst: r4 src: r2 off: 8 imm: 0
	  2: LdXMemDW dst: r5 src: r2 off: 16 imm: 0
	  3: MovReg dst: r6 src: r5
	  4: JGTImm dst: r3 off: -1 imm: 512 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	  5: LdXMemDW dst: r1 src: r2 off: -8 imm: 0
	  6: JGTImm dst: r1 off: -1 imm: 512 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	  7: JGTReg dst: r3 off: -1 src: r1 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	  8: JEqReg dst: r3 off: -1 src: r1 <dsl_pm_tcp_2_0_parse_options_cb_break>
	  9: AddReg dst: r1 src: r4
	 10: MovReg dst: r5 src: r1
	 11: MovReg dst: r0 src: r4
	 12: AddImm dst: r0 imm: 1
	 13: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	 14: JGTReg dst: r0 off: -1 src: r6 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	 15: LdXMemB dst: r0 src: r4 off: 0 imm: 0
	 16: XorReg dst: r3 src: r0
	 17: XorReg dst: r3 src: r0
	 18: JGTImm dst: r3 off: -1 imm: 511 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	 19: JGTImm dst: r3 off: -1 imm: 511 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	 20: MovReg dst: r1 src: r4
	 21: AddReg dst: r1 src: r3
	 22: AddImm dst: r1 imm: 1
	 23: JGTReg dst: r1 off: -1 src: r5 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	 24: JGTReg dst: r1 off: -1 src: r6 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	 25: LdXMemB dst: r1 src: r1 off: -1 imm: 0
	 26: JNEImm dst: r1 off: -1 imm: 2 <dsl_pm_tcp_2_0_pre_skip_2>
	 27: StXMemDW dst: r2 src: r3 off: -32 imm: 0
dsl_pm_tcp_2_0_pre_skip_2:
	 28: MovReg dst: r3 src: r3
	 29: JGTImm dst: r3 off: -1 imm: 511 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	 30: MovReg dst: r0 src: r4
	 31: AddReg dst: r0 src: r3
	 32: AddImm dst: r0 imm: 1
	 33: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	 34: JGTReg dst: r0 off: -1 src: r6 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	 35: LdXMemB dst: r0 src: r0 off: -1 imm: 0
	 36: StXMemDW dst: rfp src: r0 off: -64 imm: 0
	 37: LdXMemDW dst: r0 src: rfp off: -64 imm: 0
	 38: JNEImm dst: r0 off: -1 imm: 0 <dsl_pm_tcp_2_0_tlvcb_5_skip>
	 39: Ja off: -1 <dsl_pm_tcp_2_0_parse_options_cb_break>
dsl_pm_tcp_2_0_tlvcb_5_skip:
	 40: MovReg dst: r3 src: r3
	 41: LdXMemDW dst: r0 src: rfp off: -64 imm: 0
	 42: JNEImm dst: r0 off: -1 imm: 1 <dsl_pm_tcp_2_0_tlvcb_6_skip>
	 43: MovReg dst: r0 src: r4
	 44: AddReg dst: r0 src: r3
	 45: AddImm dst: r0 imm: 1
	 46: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	 47: JGTReg dst: r0 off: -1 src: r6 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	 48: AddImm dst: r3 imm: 1
	 49: StXMemDW dst: r2 src: r3 off: 0 imm: 0
	 50: Ja off: -1 <dsl_pm_tcp_2_0_parse_options_cb_continue>
dsl_pm_tcp_2_0_tlvcb_6_skip:
	 51: MovReg dst: r3 src: r3
	 52: LdXMemDW dst: r0 src: rfp off: -64 imm: 0
	 53: JNEImm dst: r0 off: -1 imm: 2 <dsl_pm_tcp_2_0_tlvcb_7_skip>
	 54: MovImm dst: r7 imm: 4
	 55: Ja off: -1 <dsl_pm_tcp_2_0_default_4_length>
dsl_pm_tcp_2_0_tlvcb_7_skip:
	 56: MovReg dst: r3 src: r3
	 57: LdXMemDW dst: r0 src: rfp off: -64 imm: 0
	 58: JNEImm dst: r0 off: -1 imm: 3 <dsl_pm_tcp_2_0_tlvcb_8_skip>
	 59: MovImm dst: r7 imm: 3
	 60: Ja off: -1 <dsl_pm_tcp_2_0_default_4_length>
dsl_pm_tcp_2_0_tlvcb_8_skip:
	 61: MovReg dst: r3 src: r3
	 62: LdXMemDW dst: r0 src: rfp off: -64 imm: 0
	 63: JNEImm dst: r0 off: -1 imm: 4 <dsl_pm_tcp_2_0_tlvcb_9_skip>
	 64: MovImm dst: r7 imm: 2
	 65: Ja off: -1 <dsl_pm_tcp_2_0_default_4_length>
dsl_pm_tcp_2_0_tlvcb_9_skip:
	 66: MovReg dst: r3 src: r3
	 67: LdXMemDW dst: r0 src: rfp off: -64 imm: 0
	 68: JNEImm dst: r0 off: -1 imm: 5 <dsl_pm_tcp_2_0_tlvcb_10_skip>
	 69: Ja off: -1 <dsl_pm_tcp_2_0_default_4>
dsl_pm_tcp_2_0_tlvcb_10_skip:
	 70: MovReg dst: r3 src: r3
	 71: LdXMemDW dst: r0 src: rfp off: -64 imm: 0
	 72: JNEImm dst: r0 off: -1 imm: 8 <dsl_pm_tcp_2_0_tlvcb_11_skip>
	 73: MovImm dst: r7 imm: 10
	 74: Ja off: -1 <dsl_pm_tcp_2_0_default_4_length>
dsl_pm_tcp_2_0_tlvcb_11_skip:
	 75: MovReg dst: r3 src: r3
dsl_pm_tcp_2_0_default_4:
	 76: MovReg dst: r3 src: r3
	 77: MovImm dst: r7 imm: 0
dsl_pm_tcp_2_0_default_4_length:
	 78: MovReg dst: r3 src: r3
	 79: MovReg dst: r0 src: r3
	 80: AddImm dst: r0 imm: 1
	 81: JGTImm dst: r0 off: -1 imm: 511 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	 82: MovReg dst: r1 src: r4
	 83: AddReg dst: r1 src: r0
	 84: AddImm dst: r1 imm: 1
	 85: JGTReg dst: r1 off: -1 src: r5 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	 86: JGTReg dst: r1 off: -1 src: r6 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	 87: LdXMemB dst: r1 src: r1 off: -1 imm: 0
	 88: JEqImm dst: r7 off: -1 imm: 0 <dsl_pm_tcp_2_0_default_4_length_valid>
	 89: JNEReg dst: r1 off: -1 src: r7 <dsl_pm_tcp_2_0_parse_options_cb_reject>
dsl_pm_tcp_2_0_default_4_length_valid:
	 90: MovReg dst: r3 src: r3
	 91: JLTImm dst: r1 off: -1 imm: 2 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	 92: AddReg dst: r3 src: r1
	 93: JGTImm dst: r3 off: -1 imm: 512 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	 94: MovReg dst: r0 src: r4
	 95: AddReg dst: r0 src: r3
	 96: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	 97: JGTReg dst: r0 off: -1 src: r6 <dsl_pm_tcp_2_0_parse_options_cb_reject>
	 98: StXMemDW dst: r2 src: r3 off: 0 imm: 0
	 99: Ja off: -1 <dsl_pm_tcp_2_0_parse_options_cb_continue>
dsl_pm_tcp_2_0_parse_options_cb_continue:
	100: MovImm dst: r0 imm: 0
	101: Exit
dsl_pm_tcp_2_0_parse_options_cb_reject:
	102: MovImm dst: r0 imm: -1
	103: StXMemDW dst: r2 src: r0 off: 0 imm: 0
dsl_pm_tcp_2_0_parse_options_cb_break:
	104: MovImm dst: r0 imm: 1
	105: Exit
== Funcs
176: dsl_pm_tcp_2_0_parse_options_cb
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame false
== Extractions
== Warnings
