# host: tc_entry
# expr: eth/(ipv4|ipv6)/tcp
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
	  9: JNEImm dst: r3 off: -1 imm: 8 <dsl_alt_1_1>
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
	 62: MovImm dst: r3 imm: 0
	 63: StXMemDW dst: rfp src: r3 off: -232 imm: 0
	 64: Ja off: -1 <dsl_alt_end_1>
dsl_alt_1_1:
	 65: MovReg dst: r3 src: r0
	 66: AddReg dst: r3 src: r4
	 67: LdXMemH dst: r3 src: r3 off: -2 imm: 0
	 68: JNEImm dst: r3 off: -1 imm: 56710 <dsl_reject>
	 69: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 70: MovReg dst: r3 src: r4
	 71: AddImm dst: r3 imm: 6
	 72: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 73: AddReg dst: r3 src: r0
	 74: AddImm dst: r3 imm: 1
	 75: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 76: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 77: StXMemDW dst: rfp src: r3 off: -240 imm: 0
	 78: MovReg dst: r3 src: r0
	 79: AddReg dst: r3 src: r4
	 80: AddImm dst: r3 imm: 40
	 81: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 82: AddImm dst: r4 imm: 40
	 83: MovReg dst: r3 src: r0
	 84: AddReg dst: r3 src: r4
	 85: LdXMemB dst: r3 src: r3 off: -40 imm: 0
	 86: RShImm dst: r3 imm: 4
	 87: AndImm dst: r3 imm: 15
	 88: JNEImm dst: r3 off: -1 imm: 6 <dsl_pm_ipv6_1_0_case_1_skip>
	 89: MovReg dst: r3 src: r0
	 90: AddReg dst: r3 src: r4
	 91: LdXMemB dst: r3 src: r3 off: -34 imm: 0
	 92: JNEImm dst: r3 off: -1 imm: 0 <dsl_pm_ipv6_1_0_case_1_skip>
	 93: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext>
dsl_pm_ipv6_1_0_case_1_skip:
	 94: MovReg dst: r3 src: r3
	 95: MovReg dst: r3 src: r0
	 96: AddReg dst: r3 src: r4
	 97: LdXMemB dst: r3 src: r3 off: -40 imm: 0
	 98: RShImm dst: r3 imm: 4
	 99: AndImm dst: r3 imm: 15
	100: JNEImm dst: r3 off: -1 imm: 6 <dsl_pm_ipv6_1_0_case_2_skip>
	101: MovReg dst: r3 src: r0
	102: AddReg dst: r3 src: r4
	103: LdXMemB dst: r3 src: r3 off: -34 imm: 0
	104: JNEImm dst: r3 off: -1 imm: 44 <dsl_pm_ipv6_1_0_case_2_skip>
	105: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext>
dsl_pm_ipv6_1_0_case_2_skip:
	106: MovReg dst: r3 src: r3
	107: MovReg dst: r3 src: r0
	108: AddReg dst: r3 src: r4
	109: LdXMemB dst: r3 src: r3 off: -40 imm: 0
	110: RShImm dst: r3 imm: 4
	111: AndImm dst: r3 imm: 15
	112: JNEImm dst: r3 off: -1 imm: 6 <dsl_pm_ipv6_1_0_case_3_skip>
	113: MovReg dst: r3 src: r0
	114: AddReg dst: r3 src: r4
	115: LdXMemB dst: r3 src: r3 off: -34 imm: 0
	116: JNEImm dst: r3 off: -1 imm: 60 <dsl_pm_ipv6_1_0_case_3_skip>
	117: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext>
dsl_pm_ipv6_1_0_case_3_skip:
	118: MovReg dst: r3 src: r3
	119: MovReg dst: r3 src: r0
	120: AddReg dst: r3 src: r4
	121: LdXMemB dst: r3 src: r3 off: -40 imm: 0
	122: RShImm dst: r3 imm: 4
	123: AndImm dst: r3 imm: 15
	124: JNEImm dst: r3 off: -1 imm: 6 <dsl_pm_ipv6_1_0_case_4_skip>
	125: Ja off: -1 <dsl_pm_ipv6_1_0_done>
dsl_pm_ipv6_1_0_case_4_skip:
	126: MovReg dst: r3 src: r3
	127: Ja off: -1 <dsl_reject>
dsl_pm_ipv6_1_0_parse_ext:
	128: MovReg dst: r3 src: r3
	129: MovReg dst: r3 src: r0
	130: AddReg dst: r3 src: r4
	131: AddImm dst: r3 imm: 8
	132: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	133: AddImm dst: r4 imm: 8
	134: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	135: MovReg dst: r5 src: r4
	136: SubImm dst: r5 imm: 8
	137: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	138: MovReg dst: r3 src: r0
	139: AddReg dst: r3 src: r5
	140: AddImm dst: r3 imm: 1
	141: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	142: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	143: StXMemDW dst: rfp src: r3 off: -56 imm: 0
	144: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	145: MovReg dst: r5 src: r4
	146: SubImm dst: r5 imm: 8
	147: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	148: MovReg dst: r3 src: r0
	149: AddReg dst: r3 src: r5
	150: AddImm dst: r3 imm: 1
	151: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	152: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	153: StXMemDW dst: rfp src: r3 off: -240 imm: 0
	154: JLTImm dst: r4 off: -1 imm: 7 <dsl_reject>
	155: MovReg dst: r3 src: r4
	156: SubImm dst: r3 imm: 7
	157: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	158: MovReg dst: r5 src: r0
	159: AddReg dst: r5 src: r3
	160: AddImm dst: r5 imm: 1
	161: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	162: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	163: AndImm dst: r5 imm: 255
	164: LShImm dst: r5 imm: 3
	165: AddReg dst: r4 src: r5
	166: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	167: MovReg dst: r3 src: r0
	168: AddReg dst: r3 src: r4
	169: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	170: LdXMemDW dst: r3 src: rfp off: -56 imm: 0
	171: JNEImm dst: r3 off: -1 imm: 0 <dsl_pm_ipv6_1_0_vcase_5_skip>
	172: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext_loop>
dsl_pm_ipv6_1_0_vcase_5_skip:
	173: MovReg dst: r3 src: r3
	174: LdXMemDW dst: r3 src: rfp off: -56 imm: 0
	175: JNEImm dst: r3 off: -1 imm: 44 <dsl_pm_ipv6_1_0_vcase_6_skip>
	176: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext_loop>
dsl_pm_ipv6_1_0_vcase_6_skip:
	177: MovReg dst: r3 src: r3
	178: LdXMemDW dst: r3 src: rfp off: -56 imm: 0
	179: JNEImm dst: r3 off: -1 imm: 60 <dsl_pm_ipv6_1_0_vcase_7_skip>
	180: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext_loop>
dsl_pm_ipv6_1_0_vcase_7_skip:
	181: MovReg dst: r3 src: r3
	182: Ja off: -1 <dsl_pm_ipv6_1_0_done>
dsl_pm_ipv6_1_0_parse_ext_loop:
	183: MovReg dst: r3 src: r3
	184: StXMemDW dst: rfp src: r4 off: -208 imm: 0
	185: StXMemDW dst: rfp src: r0 off: -200 imm: 0
	186: StXMemDW dst: rfp src: r1 off: -192 imm: 0
	187: MovImm dst: r1 imm: 4
	188: LdImmDW dst: r2 imm: -1 <dsl_pm_ipv6_1_0_parse_ext_cb>
	190: MovReg dst: r3 src: rfp
	191: AddImm dst: r3 imm: -208
	192: MovImm dst: r4 imm: 0
	193: Call FnLoop
	194: LdXMemDW dst: r4 src: rfp off: -208 imm: 0
	195: LdXMemDW dst: r0 src: rfp off: -200 imm: 0
	196: LdXMemDW dst: r1 src: rfp off: -192 imm: 0
	197: Ja off: -1 <dsl_pm_ipv6_1_0_done>
dsl_pm_ipv6_1_0_done:
	198: MovReg dst: r0 src: r0
	199: MovImm dst: r3 imm: 1
	200: StXMemDW dst: rfp src: r3 off: -232 imm: 0
dsl_alt_end_1:
	201: MovReg dst: r0 src: r0
	202: LdXMemDW dst: r5 src: rfp off: -232 imm: 0
	203: JNEImm dst: r5 off: -1 imm: 0 <dsl_altdisp_skip_1>
	204: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	205: AddReg dst: r3 src: r0
	206: LdXMemB dst: r3 src: r3 off: 9 imm: 0
	207: JNEImm dst: r3 off: -1 imm: 6 <dsl_reject>
	208: Ja off: -1 <dsl_altdisp_done_1>
dsl_altdisp_skip_1:
	209: MovReg dst: r0 src: r0
	210: LdXMemDW dst: r3 src: rfp off: -240 imm: 0
	211: JNEImm dst: r3 off: -1 imm: 6 <dsl_reject>
dsl_altdisp_done_1:
	212: MovReg dst: r0 src: r0
	213: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	214: MovImm dst: r3 imm: 0
	215: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	216: MovReg dst: r3 src: r0
	217: AddReg dst: r3 src: r4
	218: AddImm dst: r3 imm: 20
	219: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	220: AddImm dst: r4 imm: 20
	221: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	222: MovReg dst: r3 src: r4
	223: SubImm dst: r3 imm: 8
	224: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	225: MovReg dst: r5 src: r0
	226: AddReg dst: r5 src: r3
	227: AddImm dst: r5 imm: 1
	228: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	229: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	230: AndImm dst: r5 imm: 240
	231: RShImm dst: r5 imm: 4
	232: LShImm dst: r5 imm: 2
	233: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	234: SubImm dst: r5 imm: 20
	235: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	236: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	237: MovReg dst: r5 src: r4
	238: SubImm dst: r5 imm: 8
	239: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	240: MovReg dst: r3 src: r0
	241: AddReg dst: r3 src: r5
	242: AddImm dst: r3 imm: 1
	243: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	244: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	245: RShImm dst: r3 imm: 4
	246: AndImm dst: r3 imm: 15
	247: JNEImm dst: r3 off: -1 imm: 5 <dsl_pm_tcp_2_0_case_1_skip>
	248: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_case_1_skip:
	249: MovReg dst: r3 src: r3
	250: Ja off: -1 <dsl_pm_tcp_2_0_parse_options>
dsl_pm_tcp_2_0_parse_options:
	251: MovReg dst: r3 src: r3
	252: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	253: MovReg dst: r3 src: r4
	254: SubImm dst: r3 imm: 8
	255: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	256: MovReg dst: r5 src: r0
	257: AddReg dst: r5 src: r3
	258: AddImm dst: r5 imm: 1
	259: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	260: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	261: AndImm dst: r5 imm: 240
	262: RShImm dst: r5 imm: 4
	263: LShImm dst: r5 imm: 2
	264: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	265: SubImm dst: r5 imm: 20
	266: AddReg dst: r4 src: r5
	267: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	268: MovReg dst: r3 src: r0
	269: AddReg dst: r3 src: r4
	270: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	271: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_done:
	272: MovReg dst: r0 src: r0
	273: MovImm dst: r2 imm: 1
	274: Ja off: -1 <filter_result>
dsl_reject:
	275: MovImm dst: r2 imm: 0
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
	  9: AndImm dst: r3 imm: 1023
	 10: StXMemDW dst: r2 src: r3 off: 0 imm: 0
	 11: JLTImm dst: r3 off: -1 imm: 8 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 12: MovReg dst: r1 src: r3
	 13: SubImm dst: r1 imm: 8
	 14: JGTImm dst: r1 off: -1 imm: 511 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 15: MovReg dst: r0 src: r4
	 16: AddReg dst: r0 src: r1
	 17: AddImm dst: r0 imm: 1
	 18: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 19: LdXMemB dst: r0 src: r0 off: -1 imm: 0
	 20: StXMemDW dst: rfp src: r0 off: -56 imm: 0
	 21: JLTImm dst: r3 off: -1 imm: 8 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 22: MovReg dst: r1 src: r3
	 23: SubImm dst: r1 imm: 8
	 24: JGTImm dst: r1 off: -1 imm: 511 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 25: MovReg dst: r0 src: r4
	 26: AddReg dst: r0 src: r1
	 27: AddImm dst: r0 imm: 1
	 28: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 29: LdXMemB dst: r0 src: r0 off: -1 imm: 0
	 30: StXMemDW dst: r2 src: r0 off: -32 imm: 0
	 31: JLTImm dst: r3 off: -1 imm: 7 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 32: MovReg dst: r0 src: r3
	 33: SubImm dst: r0 imm: 7
	 34: JGTImm dst: r0 off: -1 imm: 511 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 35: MovReg dst: r1 src: r4
	 36: AddReg dst: r1 src: r0
	 37: AddImm dst: r1 imm: 1
	 38: JGTReg dst: r1 off: -1 src: r5 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 39: LdXMemB dst: r1 src: r1 off: -1 imm: 0
	 40: AndImm dst: r1 imm: 255
	 41: LShImm dst: r1 imm: 3
	 42: AddReg dst: r3 src: r1
	 43: JGTImm dst: r3 off: -1 imm: 512 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 44: MovReg dst: r0 src: r4
	 45: AddReg dst: r0 src: r3
	 46: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
	 47: AndImm dst: r3 imm: 1023
	 48: StXMemDW dst: r2 src: r3 off: 0 imm: 0
	 49: LdXMemDW dst: r0 src: rfp off: -56 imm: 0
	 50: JNEImm dst: r0 off: -1 imm: 0 <dsl_pm_ipv6_1_0_vcb_case_8_skip>
	 51: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext_cb_continue>
dsl_pm_ipv6_1_0_vcb_case_8_skip:
	 52: MovReg dst: r3 src: r3
	 53: LdXMemDW dst: r0 src: rfp off: -56 imm: 0
	 54: JNEImm dst: r0 off: -1 imm: 44 <dsl_pm_ipv6_1_0_vcb_case_9_skip>
	 55: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext_cb_continue>
dsl_pm_ipv6_1_0_vcb_case_9_skip:
	 56: MovReg dst: r3 src: r3
	 57: LdXMemDW dst: r0 src: rfp off: -56 imm: 0
	 58: JNEImm dst: r0 off: -1 imm: 60 <dsl_pm_ipv6_1_0_vcb_case_10_skip>
	 59: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext_cb_continue>
dsl_pm_ipv6_1_0_vcb_case_10_skip:
	 60: MovReg dst: r3 src: r3
	 61: Ja off: -1 <dsl_pm_ipv6_1_0_parse_ext_cb_break>
dsl_pm_ipv6_1_0_parse_ext_cb_continue:
	 62: MovImm dst: r0 imm: 0
	 63: Exit
dsl_pm_ipv6_1_0_parse_ext_cb_break:
	 64: MovImm dst: r0 imm: 1
	 65: Exit
== Funcs
275: dsl_pm_ipv6_1_0_parse_ext_cb
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame false
== Extractions
== Warnings
