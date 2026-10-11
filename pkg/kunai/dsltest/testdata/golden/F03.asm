# host: xdp_entry
# expr: eth/ipv6[src==2001:db8::/32]/tcp
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
	 18: StXMemDW dst: rfp src: r3 off: -232 imm: 0
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
	 94: StXMemDW dst: rfp src: r3 off: -232 imm: 0
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
	140: StXMemDW dst: rfp src: r4 off: -208 imm: 0
	141: LdXMemDW dst: r4 src: rfp off: -184 imm: 0
	142: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	143: MovReg dst: r3 src: r0
	144: AddReg dst: r3 src: r4
	145: AddImm dst: r3 imm: 40
	146: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	147: MovReg dst: r3 src: r4
	148: AddImm dst: r3 imm: 8
	149: JGTImm dst: r3 off: -1 imm: 504 <dsl_reject>
	150: AddReg dst: r3 src: r0
	151: AddImm dst: r3 imm: 8
	152: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	153: LdXMemDW dst: r3 src: r3 off: -8 imm: 0
	154: LdImmDW dst: r5 imm: 4294967295
	156: AndReg dst: r3 src: r5
	157: LdImmDW dst: r5 imm: 3087860000
	159: JNEReg dst: r3 off: -1 src: r5 <dsl_reject>
	160: LdXMemDW dst: r4 src: rfp off: -208 imm: 0
	161: LdXMemDW dst: r3 src: rfp off: -232 imm: 0
	162: JNEImm dst: r3 off: -1 imm: 6 <dsl_reject>
	163: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	164: MovImm dst: r3 imm: 0
	165: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	166: MovReg dst: r3 src: r0
	167: AddReg dst: r3 src: r4
	168: AddImm dst: r3 imm: 20
	169: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	170: AddImm dst: r4 imm: 20
	171: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	172: MovReg dst: r3 src: r4
	173: SubImm dst: r3 imm: 8
	174: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	175: MovReg dst: r5 src: r0
	176: AddReg dst: r5 src: r3
	177: AddImm dst: r5 imm: 1
	178: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	179: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	180: AndImm dst: r5 imm: 240
	181: RShImm dst: r5 imm: 4
	182: LShImm dst: r5 imm: 2
	183: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	184: SubImm dst: r5 imm: 20
	185: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	186: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	187: MovReg dst: r5 src: r4
	188: SubImm dst: r5 imm: 8
	189: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	190: MovReg dst: r3 src: r0
	191: AddReg dst: r3 src: r5
	192: AddImm dst: r3 imm: 1
	193: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	194: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	195: RShImm dst: r3 imm: 4
	196: AndImm dst: r3 imm: 15
	197: JNEImm dst: r3 off: -1 imm: 5 <dsl_pm_tcp_2_0_case_1_skip>
	198: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_case_1_skip:
	199: MovReg dst: r3 src: r3
	200: Ja off: -1 <dsl_pm_tcp_2_0_parse_options>
dsl_pm_tcp_2_0_parse_options:
	201: MovReg dst: r3 src: r3
	202: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	203: MovReg dst: r3 src: r4
	204: SubImm dst: r3 imm: 8
	205: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	206: MovReg dst: r5 src: r0
	207: AddReg dst: r5 src: r3
	208: AddImm dst: r5 imm: 1
	209: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	210: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	211: AndImm dst: r5 imm: 240
	212: RShImm dst: r5 imm: 4
	213: LShImm dst: r5 imm: 2
	214: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	215: SubImm dst: r5 imm: 20
	216: AddReg dst: r4 src: r5
	217: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	218: MovReg dst: r3 src: r0
	219: AddReg dst: r3 src: r4
	220: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	221: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_done:
	222: MovReg dst: r0 src: r0
	223: MovImm dst: r2 imm: 1
	224: Ja off: -1 <filter_result>
dsl_reject:
	225: MovImm dst: r2 imm: 0
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
	 29: StXMemDW dst: r2 src: r0 off: -24 imm: 0
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
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame true
== Extractions
== Warnings
