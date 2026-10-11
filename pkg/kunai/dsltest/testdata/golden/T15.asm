# host: tc_entry
# expr: eth/ipv4/tcp where any(ipv4.options.RR.addrs.addr == 192.168.0.0/16)
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
	 11: MovImm dst: r3 imm: -1
	 12: StXMemDW dst: rfp src: r3 off: -232 imm: 0
	 13: MovImm dst: r3 imm: 0
	 14: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 15: MovReg dst: r3 src: r0
	 16: AddReg dst: r3 src: r4
	 17: AddImm dst: r3 imm: 20
	 18: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 19: AddImm dst: r4 imm: 20
	 20: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 21: MovReg dst: r3 src: r4
	 22: SubImm dst: r3 imm: 20
	 23: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 24: MovReg dst: r5 src: r0
	 25: AddReg dst: r5 src: r3
	 26: AddImm dst: r5 imm: 1
	 27: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 28: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 29: AndImm dst: r5 imm: 15
	 30: LShImm dst: r5 imm: 2
	 31: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 32: SubImm dst: r5 imm: 20
	 33: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 34: MovReg dst: r3 src: r0
	 35: AddReg dst: r3 src: r4
	 36: LdXMemB dst: r3 src: r3 off: -20 imm: 0
	 37: RShImm dst: r3 imm: 4
	 38: AndImm dst: r3 imm: 15
	 39: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_1_0_case_1_skip>
	 40: Ja off: -1 <dsl_pm_ipv4_1_0_walk>
dsl_pm_ipv4_1_0_case_1_skip:
	 41: MovReg dst: r3 src: r3
	 42: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_1_0_walk:
	 43: MovReg dst: r3 src: r3
	 44: LdXMemDW dst: r3 src: rfp off: -216 imm: 0
	 45: JGTImm dst: r3 off: -1 imm: 512 <dsl_reject>
	 46: AddReg dst: r3 src: r4
	 47: JGTImm dst: r3 off: -1 imm: 512 <dsl_reject>
	 48: MovReg dst: r5 src: r0
	 49: AddReg dst: r5 src: r3
	 50: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 51: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 52: StXMemDW dst: rfp src: r4 off: -208 imm: 0
	 53: StXMemDW dst: rfp src: r0 off: -200 imm: 0
	 54: StXMemDW dst: rfp src: r1 off: -192 imm: 0
	 55: MovImm dst: r1 imm: 9
	 56: LdImmDW dst: r2 imm: -1 <dsl_pm_ipv4_1_0_walk_cb>
	 58: MovReg dst: r3 src: rfp
	 59: AddImm dst: r3 imm: -208
	 60: MovImm dst: r4 imm: 0
	 61: Call FnLoop
	 62: LdXMemDW dst: r4 src: rfp off: -208 imm: 0
	 63: LdXMemDW dst: r0 src: rfp off: -200 imm: 0
	 64: LdXMemDW dst: r1 src: rfp off: -192 imm: 0
	 65: JGTImm dst: r4 off: -1 imm: 512 <dsl_pm_ipv4_1_0_malformed_1>
	 66: LdXMemDW dst: r4 src: rfp off: -216 imm: 0
	 67: Ja off: -1 <dsl_pm_ipv4_1_0_done>
dsl_pm_ipv4_1_0_malformed_1:
	 68: LdXMemDW dst: r4 src: rfp off: -184 imm: 0
	 69: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 70: AddImm dst: r4 imm: 20
	 71: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 72: MovImm dst: r3 imm: -1
	 73: StXMemDW dst: rfp src: r3 off: -232 imm: 0
	 74: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 75: MovReg dst: r3 src: r4
	 76: SubImm dst: r3 imm: 20
	 77: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 78: MovReg dst: r5 src: r0
	 79: AddReg dst: r5 src: r3
	 80: AddImm dst: r5 imm: 1
	 81: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 82: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 83: AndImm dst: r5 imm: 15
	 84: LShImm dst: r5 imm: 2
	 85: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 86: SubImm dst: r5 imm: 20
	 87: AddReg dst: r4 src: r5
	 88: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 89: MovReg dst: r3 src: r0
	 90: AddReg dst: r3 src: r4
	 91: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 92: Ja off: -1 <dsl_pm_ipv4_1_0_done>
dsl_pm_ipv4_1_0_done:
	 93: MovReg dst: r0 src: r0
	 94: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	 95: AddReg dst: r3 src: r0
	 96: LdXMemB dst: r3 src: r3 off: 9 imm: 0
	 97: JNEImm dst: r3 off: -1 imm: 6 <dsl_reject>
	 98: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 99: MovImm dst: r3 imm: 0
	100: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	101: MovReg dst: r3 src: r0
	102: AddReg dst: r3 src: r4
	103: AddImm dst: r3 imm: 20
	104: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	105: AddImm dst: r4 imm: 20
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
	120: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	121: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	122: MovReg dst: r5 src: r4
	123: SubImm dst: r5 imm: 8
	124: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	125: MovReg dst: r3 src: r0
	126: AddReg dst: r3 src: r5
	127: AddImm dst: r3 imm: 1
	128: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	129: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	130: RShImm dst: r3 imm: 4
	131: AndImm dst: r3 imm: 15
	132: JNEImm dst: r3 off: -1 imm: 5 <dsl_pm_tcp_2_0_case_1_skip>
	133: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_case_1_skip:
	134: MovReg dst: r3 src: r3
	135: Ja off: -1 <dsl_pm_tcp_2_0_parse_options>
dsl_pm_tcp_2_0_parse_options:
	136: MovReg dst: r3 src: r3
	137: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	138: MovReg dst: r3 src: r4
	139: SubImm dst: r3 imm: 8
	140: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	141: MovReg dst: r5 src: r0
	142: AddReg dst: r5 src: r3
	143: AddImm dst: r5 imm: 1
	144: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	145: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	146: AndImm dst: r5 imm: 240
	147: RShImm dst: r5 imm: 4
	148: LShImm dst: r5 imm: 2
	149: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	150: SubImm dst: r5 imm: 20
	151: AddReg dst: r4 src: r5
	152: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	153: MovReg dst: r3 src: r0
	154: AddReg dst: r3 src: r4
	155: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	156: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_done:
	157: MovReg dst: r0 src: r0
	158: StXMemDW dst: rfp src: r0 off: -200 imm: 0
	159: StXMemDW dst: rfp src: r1 off: -192 imm: 0
	160: MovImm dst: r3 imm: 0
	161: StXMemDW dst: rfp src: r3 off: -208 imm: 0
	162: LdXMemDW dst: r3 src: rfp off: -232 imm: 0
	163: JEqImm dst: r3 off: -1 imm: -1 <dsl_auxwalk_skip_2>
	164: StXMemDW dst: rfp src: r3 off: -184 imm: 0
	165: MovImm dst: r1 imm: 9
	166: LdImmDW dst: r2 imm: -1 <dsl_auxwalk_cb_1>
	168: MovReg dst: r3 src: rfp
	169: AddImm dst: r3 imm: -208
	170: MovImm dst: r4 imm: 0
	171: Call FnLoop
dsl_auxwalk_skip_2:
	172: LdXMemDW dst: r0 src: rfp off: -200 imm: 0
	173: LdXMemDW dst: r1 src: rfp off: -192 imm: 0
	174: LdXMemDW dst: r3 src: rfp off: -208 imm: 0
	175: JEqImm dst: r3 off: -1 imm: 0 <dsl_reject>
	176: MovImm dst: r2 imm: 1
	177: Ja off: -1 <filter_result>
dsl_reject:
	178: MovImm dst: r2 imm: 0
== Callbacks
dsl_pm_ipv4_1_0_walk_cb:
	  0: LdXMemDW dst: r3 src: r2 off: 0 imm: 0
	  1: LdXMemDW dst: r4 src: r2 off: 8 imm: 0
	  2: LdXMemDW dst: r5 src: r2 off: 16 imm: 0
	  3: MovReg dst: r6 src: r5
	  4: JGTImm dst: r3 off: -1 imm: 512 <dsl_pm_ipv4_1_0_walk_cb_reject>
	  5: LdXMemDW dst: r1 src: r2 off: -8 imm: 0
	  6: JGTImm dst: r1 off: -1 imm: 512 <dsl_pm_ipv4_1_0_walk_cb_reject>
	  7: JGTReg dst: r3 off: -1 src: r1 <dsl_pm_ipv4_1_0_walk_cb_reject>
	  8: JEqReg dst: r3 off: -1 src: r1 <dsl_pm_ipv4_1_0_walk_cb_break>
	  9: AddReg dst: r1 src: r4
	 10: MovReg dst: r5 src: r1
	 11: MovReg dst: r0 src: r4
	 12: AddImm dst: r0 imm: 1
	 13: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 14: JGTReg dst: r0 off: -1 src: r6 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 15: LdXMemB dst: r0 src: r4 off: 0 imm: 0
	 16: XorReg dst: r3 src: r0
	 17: XorReg dst: r3 src: r0
	 18: JGTImm dst: r3 off: -1 imm: 511 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 19: JGTImm dst: r3 off: -1 imm: 511 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 20: MovReg dst: r1 src: r4
	 21: AddReg dst: r1 src: r3
	 22: AddImm dst: r1 imm: 1
	 23: JGTReg dst: r1 off: -1 src: r5 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 24: JGTReg dst: r1 off: -1 src: r6 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 25: LdXMemB dst: r1 src: r1 off: -1 imm: 0
	 26: JNEImm dst: r1 off: -1 imm: 7 <dsl_pm_ipv4_1_0_pre_skip_2>
	 27: StXMemDW dst: r2 src: r3 off: -24 imm: 0
dsl_pm_ipv4_1_0_pre_skip_2:
	 28: MovReg dst: r3 src: r3
	 29: JGTImm dst: r3 off: -1 imm: 511 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 30: MovReg dst: r0 src: r4
	 31: AddReg dst: r0 src: r3
	 32: AddImm dst: r0 imm: 1
	 33: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 34: JGTReg dst: r0 off: -1 src: r6 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 35: LdXMemB dst: r0 src: r0 off: -1 imm: 0
	 36: StXMemDW dst: rfp src: r0 off: -64 imm: 0
	 37: LdXMemDW dst: r0 src: rfp off: -64 imm: 0
	 38: JNEImm dst: r0 off: -1 imm: 0 <dsl_pm_ipv4_1_0_tlvcb_5_skip>
	 39: Ja off: -1 <dsl_pm_ipv4_1_0_walk_cb_break>
dsl_pm_ipv4_1_0_tlvcb_5_skip:
	 40: MovReg dst: r3 src: r3
	 41: LdXMemDW dst: r0 src: rfp off: -64 imm: 0
	 42: JNEImm dst: r0 off: -1 imm: 1 <dsl_pm_ipv4_1_0_tlvcb_6_skip>
	 43: MovReg dst: r0 src: r4
	 44: AddReg dst: r0 src: r3
	 45: AddImm dst: r0 imm: 1
	 46: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 47: JGTReg dst: r0 off: -1 src: r6 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 48: AddImm dst: r3 imm: 1
	 49: StXMemDW dst: r2 src: r3 off: 0 imm: 0
	 50: Ja off: -1 <dsl_pm_ipv4_1_0_walk_cb_continue>
dsl_pm_ipv4_1_0_tlvcb_6_skip:
	 51: MovReg dst: r3 src: r3
	 52: LdXMemDW dst: r0 src: rfp off: -64 imm: 0
	 53: JNEImm dst: r0 off: -1 imm: 7 <dsl_pm_ipv4_1_0_tlvcb_7_skip>
	 54: MovReg dst: r0 src: r3
	 55: AddImm dst: r0 imm: 1
	 56: JGTImm dst: r0 off: -1 imm: 511 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 57: MovReg dst: r1 src: r4
	 58: AddReg dst: r1 src: r0
	 59: AddImm dst: r1 imm: 1
	 60: JGTReg dst: r1 off: -1 src: r5 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 61: JGTReg dst: r1 off: -1 src: r6 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 62: LdXMemB dst: r1 src: r1 off: -1 imm: 0
	 63: JLTImm dst: r1 off: -1 imm: 2 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 64: MovReg dst: r0 src: r3
	 65: AddImm dst: r0 imm: 1
	 66: JGTImm dst: r0 off: -1 imm: 511 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 67: MovReg dst: r1 src: r4
	 68: AddReg dst: r1 src: r0
	 69: AddImm dst: r1 imm: 1
	 70: JGTReg dst: r1 off: -1 src: r5 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 71: JGTReg dst: r1 off: -1 src: r6 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 72: LdXMemB dst: r1 src: r1 off: -1 imm: 0
	 73: AndImm dst: r1 imm: 255
	 74: AddReg dst: r3 src: r1
	 75: JGTImm dst: r3 off: -1 imm: 512 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 76: MovReg dst: r0 src: r4
	 77: AddReg dst: r0 src: r3
	 78: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 79: JGTReg dst: r0 off: -1 src: r6 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 80: StXMemDW dst: r2 src: r3 off: 0 imm: 0
	 81: Ja off: -1 <dsl_pm_ipv4_1_0_walk_cb_continue>
dsl_pm_ipv4_1_0_tlvcb_7_skip:
	 82: MovReg dst: r3 src: r3
	 83: LdXMemDW dst: r0 src: rfp off: -64 imm: 0
	 84: JNEImm dst: r0 off: -1 imm: 148 <dsl_pm_ipv4_1_0_tlvcb_8_skip>
	 85: MovReg dst: r0 src: r4
	 86: AddReg dst: r0 src: r3
	 87: AddImm dst: r0 imm: 4
	 88: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 89: JGTReg dst: r0 off: -1 src: r6 <dsl_pm_ipv4_1_0_walk_cb_reject>
	 90: AddImm dst: r3 imm: 4
	 91: StXMemDW dst: r2 src: r3 off: 0 imm: 0
	 92: Ja off: -1 <dsl_pm_ipv4_1_0_walk_cb_continue>
dsl_pm_ipv4_1_0_tlvcb_8_skip:
	 93: MovReg dst: r3 src: r3
dsl_pm_ipv4_1_0_default_4:
	 94: MovReg dst: r3 src: r3
	 95: Ja off: -1 <dsl_pm_ipv4_1_0_walk_cb_reject>
dsl_pm_ipv4_1_0_walk_cb_continue:
	 96: MovImm dst: r0 imm: 0
	 97: Exit
dsl_pm_ipv4_1_0_walk_cb_reject:
	 98: MovImm dst: r0 imm: -1
	 99: StXMemDW dst: r2 src: r0 off: 0 imm: 0
dsl_pm_ipv4_1_0_walk_cb_break:
	100: MovImm dst: r0 imm: 1
	101: Exit
dsl_auxwalk_cb_1:
	102: LdXMemDW dst: r4 src: r2 off: 8 imm: 0
	103: LdXMemDW dst: r5 src: r2 off: 16 imm: 0
	104: LdXMemDW dst: r0 src: r2 off: 24 imm: 0
	105: AddImm dst: r0 imm: 1
	106: MovReg dst: r3 src: r0
	107: JGTImm dst: r3 off: -1 imm: 511 <dsl_auxwalk_cb_1_break>
	108: MovReg dst: r0 src: r4
	109: AddReg dst: r0 src: r3
	110: AddImm dst: r0 imm: 1
	111: JGTReg dst: r0 off: -1 src: r5 <dsl_auxwalk_cb_1_break>
	112: LdXMemB dst: r0 src: r0 off: -1 imm: 0
	113: JLTImm dst: r0 off: -1 imm: 3 <dsl_auxwalk_cb_1_break>
	114: SubImm dst: r0 imm: 3
	115: RShImm dst: r0 imm: 2
	116: JGEReg dst: r1 off: -1 src: r0 <dsl_auxwalk_cb_1_break>
	117: LdXMemDW dst: r0 src: r2 off: 24 imm: 0
	118: AddImm dst: r0 imm: 3
	119: MovReg dst: r3 src: r1
	120: JGEImm dst: r3 off: -1 imm: 9 <dsl_auxwalk_cb_1_mismatch>
	121: MulImm dst: r3 imm: 4
	122: AddReg dst: r3 src: r0
	123: JGTImm dst: r3 off: -1 imm: 508 <dsl_auxwalk_cb_1_mismatch>
	124: MovReg dst: r0 src: r4
	125: AddReg dst: r0 src: r3
	126: AddImm dst: r0 imm: 4
	127: JGTReg dst: r0 off: -1 src: r5 <dsl_auxwalk_cb_1_mismatch>
	128: LdXMemW dst: r0 src: r0 off: -4 imm: 0
	129: AndImm dst: r0 imm: 65535
	130: LdImmDW dst: r3 imm: 43200
	132: JNEReg dst: r0 off: -1 src: r3 <dsl_auxwalk_cb_1_mismatch>
	133: MovImm dst: r0 imm: 1
	134: StXMemDW dst: r2 src: r0 off: 0 imm: 0
	135: MovImm dst: r0 imm: 1
	136: Exit
dsl_auxwalk_cb_1_mismatch:
	137: MovImm dst: r0 imm: 0
	138: Exit
dsl_auxwalk_cb_1_break:
	139: MovImm dst: r0 imm: 1
	140: Exit
== Funcs
177: dsl_pm_ipv4_1_0_walk_cb
279: dsl_auxwalk_cb_1
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame false
== Extractions
== Warnings
