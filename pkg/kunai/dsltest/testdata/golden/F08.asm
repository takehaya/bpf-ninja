# host: xdp_entry
# expr: eth/ipv6/srv6 where any(srv6.segments.addr == fc00::1)
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
	  9: JNEImm dst: r3 off: -1 imm: 56710 <dsl_reject>
	 10: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 11: MovReg dst: r3 src: r4
	 12: AddImm dst: r3 imm: 6
	 13: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 14: AddReg dst: r3 src: r0
	 15: AddImm dst: r3 imm: 1
	 16: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 17: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 18: StXMemDW dst: rfp src: r3 off: -240 imm: 0
	 19: MovReg dst: r3 src: r0
	 20: AddReg dst: r3 src: r4
	 21: AddImm dst: r3 imm: 40
	 22: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 23: AddImm dst: r4 imm: 40
	 24: MovReg dst: r3 src: r0
	 25: AddReg dst: r3 src: r4
	 26: LdXMemB dst: r3 src: r3 off: -40 imm: 0
	 27: RShImm dst: r3 imm: 4
	 28: AndImm dst: r3 imm: 15
	 29: JNEImm dst: r3 off: -1 imm: 6 <dsl_pm_ipv6_1_0_case_1_skip>
	 30: MovReg dst: r3 src: r0
	 31: AddReg dst: r3 src: r4
	 32: LdXMemB dst: r3 src: r3 off: -34 imm: 0
	 33: JNEImm dst: r3 off: -1 imm: 0 <dsl_pm_ipv6_1_0_case_1_skip>
	 34: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext>
dsl_pm_ipv6_1_0_case_1_skip:
	 35: MovReg dst: r3 src: r3
	 36: MovReg dst: r3 src: r0
	 37: AddReg dst: r3 src: r4
	 38: LdXMemB dst: r3 src: r3 off: -40 imm: 0
	 39: RShImm dst: r3 imm: 4
	 40: AndImm dst: r3 imm: 15
	 41: JNEImm dst: r3 off: -1 imm: 6 <dsl_pm_ipv6_1_0_case_2_skip>
	 42: MovReg dst: r3 src: r0
	 43: AddReg dst: r3 src: r4
	 44: LdXMemB dst: r3 src: r3 off: -34 imm: 0
	 45: JNEImm dst: r3 off: -1 imm: 44 <dsl_pm_ipv6_1_0_case_2_skip>
	 46: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext>
dsl_pm_ipv6_1_0_case_2_skip:
	 47: MovReg dst: r3 src: r3
	 48: MovReg dst: r3 src: r0
	 49: AddReg dst: r3 src: r4
	 50: LdXMemB dst: r3 src: r3 off: -40 imm: 0
	 51: RShImm dst: r3 imm: 4
	 52: AndImm dst: r3 imm: 15
	 53: JNEImm dst: r3 off: -1 imm: 6 <dsl_pm_ipv6_1_0_case_3_skip>
	 54: MovReg dst: r3 src: r0
	 55: AddReg dst: r3 src: r4
	 56: LdXMemB dst: r3 src: r3 off: -34 imm: 0
	 57: JNEImm dst: r3 off: -1 imm: 60 <dsl_pm_ipv6_1_0_case_3_skip>
	 58: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext>
dsl_pm_ipv6_1_0_case_3_skip:
	 59: MovReg dst: r3 src: r3
	 60: MovReg dst: r3 src: r0
	 61: AddReg dst: r3 src: r4
	 62: LdXMemB dst: r3 src: r3 off: -40 imm: 0
	 63: RShImm dst: r3 imm: 4
	 64: AndImm dst: r3 imm: 15
	 65: JNEImm dst: r3 off: -1 imm: 6 <dsl_pm_ipv6_1_0_case_4_skip>
	 66: Ja off: -1 <dsl_pm_ipv6_1_0_done>
dsl_pm_ipv6_1_0_case_4_skip:
	 67: MovReg dst: r3 src: r3
	 68: Ja off: -1 <dsl_reject>
dsl_pm_ipv6_1_0_parse_ext:
	 69: MovReg dst: r3 src: r3
	 70: MovReg dst: r3 src: r0
	 71: AddReg dst: r3 src: r4
	 72: AddImm dst: r3 imm: 8
	 73: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 74: AddImm dst: r4 imm: 8
	 75: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 76: MovReg dst: r5 src: r4
	 77: SubImm dst: r5 imm: 8
	 78: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	 79: MovReg dst: r3 src: r0
	 80: AddReg dst: r3 src: r5
	 81: AddImm dst: r3 imm: 1
	 82: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 83: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 84: StXMemDW dst: rfp src: r3 off: -56 imm: 0
	 85: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 86: MovReg dst: r5 src: r4
	 87: SubImm dst: r5 imm: 8
	 88: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	 89: MovReg dst: r3 src: r0
	 90: AddReg dst: r3 src: r5
	 91: AddImm dst: r3 imm: 1
	 92: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 93: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 94: StXMemDW dst: rfp src: r3 off: -240 imm: 0
	 95: JLTImm dst: r4 off: -1 imm: 7 <dsl_reject>
	 96: MovReg dst: r3 src: r4
	 97: SubImm dst: r3 imm: 7
	 98: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 99: MovReg dst: r5 src: r0
	100: AddReg dst: r5 src: r3
	101: AddImm dst: r5 imm: 1
	102: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	103: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	104: AndImm dst: r5 imm: 255
	105: LShImm dst: r5 imm: 3
	106: AddReg dst: r4 src: r5
	107: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	108: MovReg dst: r3 src: r0
	109: AddReg dst: r3 src: r4
	110: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	111: LdXMemDW dst: r3 src: rfp off: -56 imm: 0
	112: JNEImm dst: r3 off: -1 imm: 0 <dsl_pm_ipv6_1_0_vcase_5_skip>
	113: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext_loop>
dsl_pm_ipv6_1_0_vcase_5_skip:
	114: MovReg dst: r3 src: r3
	115: LdXMemDW dst: r3 src: rfp off: -56 imm: 0
	116: JNEImm dst: r3 off: -1 imm: 44 <dsl_pm_ipv6_1_0_vcase_6_skip>
	117: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext_loop>
dsl_pm_ipv6_1_0_vcase_6_skip:
	118: MovReg dst: r3 src: r3
	119: LdXMemDW dst: r3 src: rfp off: -56 imm: 0
	120: JNEImm dst: r3 off: -1 imm: 60 <dsl_pm_ipv6_1_0_vcase_7_skip>
	121: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext_loop>
dsl_pm_ipv6_1_0_vcase_7_skip:
	122: MovReg dst: r3 src: r3
	123: Ja off: -1 <dsl_pm_ipv6_1_0_done>
dsl_pm_ipv6_1_0_parse_ext_loop:
	124: MovReg dst: r3 src: r3
	125: StXMemDW dst: rfp src: r4 off: -208 imm: 0
	126: StXMemDW dst: rfp src: r0 off: -200 imm: 0
	127: StXMemDW dst: rfp src: r1 off: -192 imm: 0
	128: MovImm dst: r1 imm: 4
	129: LdImmDW dst: r2 imm: -1 <dsl_pm_ipv6_1_0_parse_ext_cb>
	131: MovReg dst: r3 src: rfp
	132: AddImm dst: r3 imm: -208
	133: MovImm dst: r4 imm: 0
	134: Call FnLoop
	135: LdXMemDW dst: r4 src: rfp off: -208 imm: 0
	136: LdXMemDW dst: r0 src: rfp off: -200 imm: 0
	137: LdXMemDW dst: r1 src: rfp off: -192 imm: 0
	138: Ja off: -1 <dsl_pm_ipv6_1_0_done>
dsl_pm_ipv6_1_0_done:
	139: MovReg dst: r0 src: r0
	140: LdXMemDW dst: r3 src: rfp off: -240 imm: 0
	141: JNEImm dst: r3 off: -1 imm: 43 <dsl_reject>
	142: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	143: StXMemDW dst: rfp src: r4 off: -232 imm: 0
	144: MovImm dst: r3 imm: 0
	145: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	146: MovReg dst: r3 src: r0
	147: AddReg dst: r3 src: r4
	148: AddImm dst: r3 imm: 8
	149: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	150: AddImm dst: r4 imm: 8
	151: JLTImm dst: r4 off: -1 imm: 4 <dsl_reject>
	152: MovReg dst: r3 src: r4
	153: SubImm dst: r3 imm: 4
	154: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	155: MovReg dst: r5 src: r0
	156: AddReg dst: r5 src: r3
	157: AddImm dst: r5 imm: 1
	158: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	159: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	160: AndImm dst: r5 imm: 255
	161: AddImm dst: r5 imm: 1
	162: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	163: JLTImm dst: r4 off: -1 imm: 6 <dsl_reject>
	164: MovReg dst: r5 src: r4
	165: SubImm dst: r5 imm: 6
	166: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	167: MovReg dst: r3 src: r0
	168: AddReg dst: r3 src: r5
	169: AddImm dst: r3 imm: 1
	170: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	171: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	172: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_srv6_2_0_case_1_skip>
	173: Ja off: -1 <dsl_pm_srv6_2_0_walk>
dsl_pm_srv6_2_0_case_1_skip:
	174: MovReg dst: r3 src: r3
	175: Ja off: -1 <dsl_reject>
dsl_pm_srv6_2_0_walk:
	176: MovReg dst: r3 src: r3
	177: Ja off: -1 <dsl_pm_srv6_2_0_done>
dsl_pm_srv6_2_0_done:
	178: MovReg dst: r0 src: r0
	179: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	180: MovReg dst: r5 src: r3
	181: AddImm dst: r5 imm: 4
	182: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	183: MovReg dst: r2 src: r0
	184: AddReg dst: r2 src: r5
	185: AddImm dst: r2 imm: 1
	186: JGTReg dst: r2 off: -1 src: r1 <dsl_reject>
	187: LdXMemB dst: r2 src: r2 off: -1 imm: 0
	188: LShImm dst: r2 imm: 4
	189: AddImm dst: r2 imm: 16
	190: MovReg dst: r4 src: r3
	191: AddImm dst: r4 imm: 8
	192: AddReg dst: r4 src: r2
	193: MovReg dst: r5 src: r0
	194: AddReg dst: r5 src: r4
	195: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	196: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	197: StXMemDW dst: rfp src: r0 off: -200 imm: 0
	198: StXMemDW dst: rfp src: r1 off: -192 imm: 0
	199: MovImm dst: r3 imm: 0
	200: StXMemDW dst: rfp src: r3 off: -208 imm: 0
	201: LdXMemDW dst: r3 src: rfp off: -232 imm: 0
	202: StXMemDW dst: rfp src: r3 off: -184 imm: 0
	203: MovImm dst: r1 imm: 8
	204: LdImmDW dst: r2 imm: -1 <dsl_auxwalk_cb_1>
	206: MovReg dst: r3 src: rfp
	207: AddImm dst: r3 imm: -208
	208: MovImm dst: r4 imm: 0
	209: Call FnLoop
	210: LdXMemDW dst: r0 src: rfp off: -200 imm: 0
	211: LdXMemDW dst: r1 src: rfp off: -192 imm: 0
	212: LdXMemDW dst: r3 src: rfp off: -208 imm: 0
	213: JEqImm dst: r3 off: -1 imm: 0 <dsl_reject>
	214: MovImm dst: r2 imm: 1
	215: Ja off: -1 <filter_result>
dsl_reject:
	216: MovImm dst: r2 imm: 0
== Callbacks
dsl_pm_ipv6_1_0_parse_ext_cb:
	  0: LdXMemDW dst: r3 src: r2 off: 0 imm: 0
	  1: LdXMemDW dst: r4 src: r2 off: 8 imm: 0
	  2: LdXMemDW dst: r5 src: r2 off: 16 imm: 0
	  3: JGTImm dst: r3 off: -1 imm: 511 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	  4: MovReg dst: r0 src: r4
	  5: AddReg dst: r0 src: r3
	  6: AddImm dst: r0 imm: 8
	  7: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	  8: AddImm dst: r3 imm: 8
	  9: StXMemDW dst: r2 src: r3 off: 0 imm: 0
	 10: JLTImm dst: r3 off: -1 imm: 8 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 11: MovReg dst: r1 src: r3
	 12: SubImm dst: r1 imm: 8
	 13: JGTImm dst: r1 off: -1 imm: 511 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 14: MovReg dst: r0 src: r4
	 15: AddReg dst: r0 src: r1
	 16: AddImm dst: r0 imm: 1
	 17: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 18: LdXMemB dst: r0 src: r0 off: -1 imm: 0
	 19: StXMemDW dst: rfp src: r0 off: -56 imm: 0
	 20: JLTImm dst: r3 off: -1 imm: 8 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 21: MovReg dst: r1 src: r3
	 22: SubImm dst: r1 imm: 8
	 23: JGTImm dst: r1 off: -1 imm: 511 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 24: MovReg dst: r0 src: r4
	 25: AddReg dst: r0 src: r1
	 26: AddImm dst: r0 imm: 1
	 27: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 28: LdXMemB dst: r0 src: r0 off: -1 imm: 0
	 29: StXMemDW dst: r2 src: r0 off: -32 imm: 0
	 30: JLTImm dst: r3 off: -1 imm: 7 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 31: MovReg dst: r0 src: r3
	 32: SubImm dst: r0 imm: 7
	 33: JGTImm dst: r0 off: -1 imm: 511 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 34: MovReg dst: r1 src: r4
	 35: AddReg dst: r1 src: r0
	 36: AddImm dst: r1 imm: 1
	 37: JGTReg dst: r1 off: -1 src: r5 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 38: LdXMemB dst: r1 src: r1 off: -1 imm: 0
	 39: AndImm dst: r1 imm: 255
	 40: LShImm dst: r1 imm: 3
	 41: AddReg dst: r3 src: r1
	 42: JGTImm dst: r3 off: -1 imm: 512 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 43: MovReg dst: r0 src: r4
	 44: AddReg dst: r0 src: r3
	 45: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 46: StXMemDW dst: r2 src: r3 off: 0 imm: 0
	 47: LdXMemDW dst: r0 src: rfp off: -56 imm: 0
	 48: JNEImm dst: r0 off: -1 imm: 0 <dsl_pm_ipv6_1_0_vcb_case_8_skip>
	 49: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext_cb_continue>
dsl_pm_ipv6_1_0_vcb_case_8_skip:
	 50: MovReg dst: r3 src: r3
	 51: LdXMemDW dst: r0 src: rfp off: -56 imm: 0
	 52: JNEImm dst: r0 off: -1 imm: 44 <dsl_pm_ipv6_1_0_vcb_case_9_skip>
	 53: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext_cb_continue>
dsl_pm_ipv6_1_0_vcb_case_9_skip:
	 54: MovReg dst: r3 src: r3
	 55: LdXMemDW dst: r0 src: rfp off: -56 imm: 0
	 56: JNEImm dst: r0 off: -1 imm: 60 <dsl_pm_ipv6_1_0_vcb_case_10_skip>
	 57: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext_cb_continue>
dsl_pm_ipv6_1_0_vcb_case_10_skip:
	 58: MovReg dst: r3 src: r3
	 59: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
dsl_pm_ipv6_1_0_parse_ext_cb_continue:
	 60: MovImm dst: r0 imm: 0
	 61: Exit
dsl_pm_ipv6_1_0_parse_ext_cb_break:
	 62: MovImm dst: r0 imm: 1
	 63: Exit
dsl_auxwalk_cb_1:
	 64: LdXMemDW dst: r4 src: r2 off: 8 imm: 0
	 65: LdXMemDW dst: r5 src: r2 off: 16 imm: 0
	 66: LdXMemDW dst: r0 src: r2 off: 24 imm: 0
	 67: AddImm dst: r0 imm: 4
	 68: MovReg dst: r3 src: r0
	 69: JGTImm dst: r3 off: -1 imm: 511 <dsl_auxwalk_cb_1_break>
	 70: MovReg dst: r0 src: r4
	 71: AddReg dst: r0 src: r3
	 72: AddImm dst: r0 imm: 1
	 73: JGTReg dst: r0 off: -1 src: r5 <dsl_auxwalk_cb_1_break>
	 74: LdXMemB dst: r0 src: r0 off: -1 imm: 0
	 75: AddImm dst: r0 imm: 1
	 76: JGEReg dst: r1 off: -1 src: r0 <dsl_auxwalk_cb_1_break>
	 77: LdXMemDW dst: r0 src: r2 off: 24 imm: 0
	 78: AddImm dst: r0 imm: 8
	 79: MovReg dst: r3 src: r1
	 80: JGEImm dst: r3 off: -1 imm: 8 <dsl_auxwalk_cb_1_mismatch>
	 81: MulImm dst: r3 imm: 16
	 82: AddReg dst: r3 src: r0
	 83: JGTImm dst: r3 off: -1 imm: 504 <dsl_auxwalk_cb_1_mismatch>
	 84: MovReg dst: r0 src: r4
	 85: AddReg dst: r0 src: r3
	 86: AddImm dst: r0 imm: 8
	 87: JGTReg dst: r0 off: -1 src: r5 <dsl_auxwalk_cb_1_mismatch>
	 88: LdXMemDW dst: r0 src: r0 off: -8 imm: 0
	 89: LdImmDW dst: r3 imm: 252
	 91: JNEReg dst: r0 off: -1 src: r3 <dsl_auxwalk_cb_1_mismatch>
	 92: LdXMemDW dst: r0 src: r2 off: 24 imm: 0
	 93: AddImm dst: r0 imm: 16
	 94: MovReg dst: r3 src: r1
	 95: JGEImm dst: r3 off: -1 imm: 8 <dsl_auxwalk_cb_1_mismatch>
	 96: MulImm dst: r3 imm: 16
	 97: AddReg dst: r3 src: r0
	 98: JGTImm dst: r3 off: -1 imm: 504 <dsl_auxwalk_cb_1_mismatch>
	 99: MovReg dst: r0 src: r4
	100: AddReg dst: r0 src: r3
	101: AddImm dst: r0 imm: 8
	102: JGTReg dst: r0 off: -1 src: r5 <dsl_auxwalk_cb_1_mismatch>
	103: LdXMemDW dst: r0 src: r0 off: -8 imm: 0
	104: LdImmDW dst: r3 imm: 72057594037927936
	106: JNEReg dst: r0 off: -1 src: r3 <dsl_auxwalk_cb_1_mismatch>
	107: MovImm dst: r0 imm: 1
	108: StXMemDW dst: r2 src: r0 off: 0 imm: 0
	109: MovImm dst: r0 imm: 1
	110: Exit
dsl_auxwalk_cb_1_mismatch:
	111: MovImm dst: r0 imm: 0
	112: Exit
dsl_auxwalk_cb_1_break:
	113: MovImm dst: r0 imm: 1
	114: Exit
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame true
== Extractions
== Warnings
