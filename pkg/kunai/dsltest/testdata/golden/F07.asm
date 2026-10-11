# host: xdp_entry
# expr: eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where inner.dst == 10.0.0.1
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
	 62: MovReg dst: r3 src: r0
	 63: AddReg dst: r3 src: r4
	 64: AddImm dst: r3 imm: 8
	 65: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 66: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	 67: AddReg dst: r3 src: r0
	 68: LdXMemB dst: r3 src: r3 off: 9 imm: 0
	 69: JNEImm dst: r3 off: -1 imm: 17 <dsl_reject>
	 70: AddImm dst: r4 imm: 8
	 71: JLTImm dst: r4 off: -1 imm: 6 <dsl_reject>
	 72: MovReg dst: r5 src: r4
	 73: SubImm dst: r5 imm: 6
	 74: JGTImm dst: r5 off: -1 imm: 510 <dsl_reject>
	 75: MovReg dst: r3 src: r0
	 76: AddReg dst: r3 src: r5
	 77: AddImm dst: r3 imm: 2
	 78: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 79: LdXMemH dst: r3 src: r3 off: -2 imm: 0
	 80: JNEImm dst: r3 off: -1 imm: 26632 <dsl_reject>
	 81: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 82: MovReg dst: r3 src: r0
	 83: AddReg dst: r3 src: r4
	 84: AddImm dst: r3 imm: 8
	 85: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 86: AddImm dst: r4 imm: 8
	 87: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 88: MovReg dst: r5 src: r4
	 89: SubImm dst: r5 imm: 8
	 90: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	 91: MovReg dst: r3 src: r0
	 92: AddReg dst: r3 src: r5
	 93: AddImm dst: r3 imm: 1
	 94: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 95: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 96: RShImm dst: r3 imm: 2
	 97: AndImm dst: r3 imm: 1
	 98: JNEImm dst: r3 off: -1 imm: 0 <dsl_pm_gtp_3_0_case_1_skip>
	 99: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	100: MovReg dst: r5 src: r4
	101: SubImm dst: r5 imm: 8
	102: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	103: MovReg dst: r3 src: r0
	104: AddReg dst: r3 src: r5
	105: AddImm dst: r3 imm: 1
	106: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	107: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	108: RShImm dst: r3 imm: 1
	109: AndImm dst: r3 imm: 1
	110: JNEImm dst: r3 off: -1 imm: 0 <dsl_pm_gtp_3_0_case_1_skip>
	111: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	112: MovReg dst: r5 src: r4
	113: SubImm dst: r5 imm: 8
	114: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	115: MovReg dst: r3 src: r0
	116: AddReg dst: r3 src: r5
	117: AddImm dst: r3 imm: 1
	118: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	119: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	120: AndImm dst: r3 imm: 1
	121: JNEImm dst: r3 off: -1 imm: 0 <dsl_pm_gtp_3_0_case_1_skip>
	122: Ja off: -1 <dsl_pm_gtp_3_0_done>
dsl_pm_gtp_3_0_case_1_skip:
	123: MovReg dst: r3 src: r3
	124: Ja off: -1 <dsl_pm_gtp_3_0_parse_opt>
dsl_pm_gtp_3_0_parse_opt:
	125: MovReg dst: r3 src: r3
	126: MovReg dst: r3 src: r0
	127: AddReg dst: r3 src: r4
	128: AddImm dst: r3 imm: 4
	129: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	130: AddImm dst: r4 imm: 4
	131: JLTImm dst: r4 off: -1 imm: 1 <dsl_reject>
	132: MovReg dst: r5 src: r4
	133: SubImm dst: r5 imm: 1
	134: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	135: MovReg dst: r3 src: r0
	136: AddReg dst: r3 src: r5
	137: AddImm dst: r3 imm: 1
	138: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	139: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	140: JNEImm dst: r3 off: -1 imm: 0 <dsl_pm_gtp_3_0_case_2_skip>
	141: Ja off: -1 <dsl_pm_gtp_3_0_done>
dsl_pm_gtp_3_0_case_2_skip:
	142: MovReg dst: r3 src: r3
	143: Ja off: -1 <dsl_pm_gtp_3_0_parse_ext>
dsl_pm_gtp_3_0_parse_ext:
	144: MovReg dst: r3 src: r3
	145: MovReg dst: r3 src: r0
	146: AddReg dst: r3 src: r4
	147: AddImm dst: r3 imm: 4
	148: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	149: AddImm dst: r4 imm: 4
	150: JLTImm dst: r4 off: -1 imm: 1 <dsl_reject>
	151: MovReg dst: r5 src: r4
	152: SubImm dst: r5 imm: 1
	153: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	154: MovReg dst: r3 src: r0
	155: AddReg dst: r3 src: r5
	156: AddImm dst: r3 imm: 1
	157: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	158: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	159: StXMemDW dst: rfp src: r3 off: -56 imm: 0
	160: JLTImm dst: r4 off: -1 imm: 4 <dsl_reject>
	161: MovReg dst: r3 src: r4
	162: SubImm dst: r3 imm: 4
	163: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	164: MovReg dst: r5 src: r0
	165: AddReg dst: r5 src: r3
	166: AddImm dst: r5 imm: 1
	167: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	168: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	169: AndImm dst: r5 imm: 255
	170: LShImm dst: r5 imm: 2
	171: JLTImm dst: r5 off: -1 imm: 4 <dsl_reject>
	172: SubImm dst: r5 imm: 4
	173: AddReg dst: r4 src: r5
	174: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	175: MovReg dst: r3 src: r0
	176: AddReg dst: r3 src: r4
	177: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	178: LdXMemDW dst: r3 src: rfp off: -56 imm: 0
	179: JNEImm dst: r3 off: -1 imm: 0 <dsl_pm_gtp_3_0_vcase_4_skip>
	180: Ja off: -1 <dsl_pm_gtp_3_0_done>
dsl_pm_gtp_3_0_vcase_4_skip:
	181: MovReg dst: r3 src: r3
	182: Ja off: -1 <dsl_pm_gtp_3_0_parse_ext_loop>
dsl_pm_gtp_3_0_parse_ext_loop:
	183: MovReg dst: r3 src: r3
	184: StXMemDW dst: rfp src: r4 off: -208 imm: 0
	185: StXMemDW dst: rfp src: r0 off: -200 imm: 0
	186: StXMemDW dst: rfp src: r1 off: -192 imm: 0
	187: MovImm dst: r1 imm: 8
	188: LdImmDW dst: r2 imm: -1 <dsl_pm_gtp_3_0_parse_ext_cb>
	190: MovReg dst: r3 src: rfp
	191: AddImm dst: r3 imm: -208
	192: MovImm dst: r4 imm: 0
	193: Call FnLoop
	194: LdXMemDW dst: r4 src: rfp off: -208 imm: 0
	195: LdXMemDW dst: r0 src: rfp off: -200 imm: 0
	196: LdXMemDW dst: r1 src: rfp off: -192 imm: 0
	197: Ja off: -1 <dsl_pm_gtp_3_0_done>
dsl_pm_gtp_3_0_done:
	198: MovReg dst: r0 src: r0
	199: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	200: StXMemDW dst: rfp src: r4 off: -232 imm: 0
	201: MovImm dst: r3 imm: 0
	202: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	203: MovReg dst: r3 src: r0
	204: AddReg dst: r3 src: r4
	205: AddImm dst: r3 imm: 20
	206: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	207: AddImm dst: r4 imm: 20
	208: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	209: MovReg dst: r3 src: r4
	210: SubImm dst: r3 imm: 20
	211: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	212: MovReg dst: r5 src: r0
	213: AddReg dst: r5 src: r3
	214: AddImm dst: r5 imm: 1
	215: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	216: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	217: AndImm dst: r5 imm: 15
	218: LShImm dst: r5 imm: 2
	219: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	220: SubImm dst: r5 imm: 20
	221: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	222: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	223: MovReg dst: r5 src: r4
	224: SubImm dst: r5 imm: 20
	225: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	226: MovReg dst: r3 src: r0
	227: AddReg dst: r3 src: r5
	228: AddImm dst: r3 imm: 1
	229: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	230: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	231: RShImm dst: r3 imm: 4
	232: AndImm dst: r3 imm: 15
	233: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_4_1_case_1_skip>
	234: Ja off: -1 <dsl_pm_ipv4_4_1_walk>
dsl_pm_ipv4_4_1_case_1_skip:
	235: MovReg dst: r3 src: r3
	236: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_4_1_walk:
	237: MovReg dst: r3 src: r3
	238: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	239: MovReg dst: r3 src: r4
	240: SubImm dst: r3 imm: 20
	241: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	242: MovReg dst: r5 src: r0
	243: AddReg dst: r5 src: r3
	244: AddImm dst: r5 imm: 1
	245: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	246: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	247: AndImm dst: r5 imm: 15
	248: LShImm dst: r5 imm: 2
	249: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	250: SubImm dst: r5 imm: 20
	251: AddReg dst: r4 src: r5
	252: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	253: MovReg dst: r3 src: r0
	254: AddReg dst: r3 src: r4
	255: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	256: Ja off: -1 <dsl_pm_ipv4_4_1_done>
dsl_pm_ipv4_4_1_done:
	257: MovReg dst: r0 src: r0
	258: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	259: MovReg dst: r5 src: r3
	260: AddImm dst: r5 imm: 9
	261: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	262: MovReg dst: r3 src: r0
	263: AddReg dst: r3 src: r5
	264: AddImm dst: r3 imm: 1
	265: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	266: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	267: JNEImm dst: r3 off: -1 imm: 6 <dsl_reject>
	268: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	269: MovImm dst: r3 imm: 0
	270: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	271: MovReg dst: r3 src: r0
	272: AddReg dst: r3 src: r4
	273: AddImm dst: r3 imm: 20
	274: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	275: AddImm dst: r4 imm: 20
	276: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	277: MovReg dst: r3 src: r4
	278: SubImm dst: r3 imm: 8
	279: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	280: MovReg dst: r5 src: r0
	281: AddReg dst: r5 src: r3
	282: AddImm dst: r5 imm: 1
	283: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	284: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	285: AndImm dst: r5 imm: 240
	286: RShImm dst: r5 imm: 4
	287: LShImm dst: r5 imm: 2
	288: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	289: SubImm dst: r5 imm: 20
	290: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	291: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	292: MovReg dst: r5 src: r4
	293: SubImm dst: r5 imm: 8
	294: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	295: MovReg dst: r3 src: r0
	296: AddReg dst: r3 src: r5
	297: AddImm dst: r3 imm: 1
	298: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	299: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	300: RShImm dst: r3 imm: 4
	301: AndImm dst: r3 imm: 15
	302: JNEImm dst: r3 off: -1 imm: 5 <dsl_pm_tcp_5_0_case_1_skip>
	303: Ja off: -1 <dsl_pm_tcp_5_0_done>
dsl_pm_tcp_5_0_case_1_skip:
	304: MovReg dst: r3 src: r3
	305: Ja off: -1 <dsl_pm_tcp_5_0_parse_options>
dsl_pm_tcp_5_0_parse_options:
	306: MovReg dst: r3 src: r3
	307: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	308: MovReg dst: r3 src: r4
	309: SubImm dst: r3 imm: 8
	310: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	311: MovReg dst: r5 src: r0
	312: AddReg dst: r5 src: r3
	313: AddImm dst: r5 imm: 1
	314: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	315: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	316: AndImm dst: r5 imm: 240
	317: RShImm dst: r5 imm: 4
	318: LShImm dst: r5 imm: 2
	319: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	320: SubImm dst: r5 imm: 20
	321: AddReg dst: r4 src: r5
	322: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	323: MovReg dst: r3 src: r0
	324: AddReg dst: r3 src: r4
	325: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	326: Ja off: -1 <dsl_pm_tcp_5_0_done>
dsl_pm_tcp_5_0_done:
	327: MovReg dst: r0 src: r0
	328: LdXMemDW dst: r3 src: rfp off: -232 imm: 0
	329: AddImm dst: r3 imm: 16
	330: JGTImm dst: r3 off: -1 imm: 508 <dsl_reject>
	331: AddReg dst: r3 src: r0
	332: AddImm dst: r3 imm: 4
	333: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	334: LdXMemW dst: r3 src: r3 off: -4 imm: 0
	335: LdImmDW dst: r5 imm: 16777226
	337: JNEReg dst: r3 off: -1 src: r5 <dsl_reject>
	338: MovImm dst: r2 imm: 1
	339: Ja off: -1 <filter_result>
dsl_reject:
	340: MovImm dst: r2 imm: 0
== Callbacks
dsl_pm_gtp_3_0_parse_ext_cb:
	 0: LdXMemDW dst: r3 src: r2 off: 0 imm: 0
	 1: LdXMemDW dst: r4 src: r2 off: 8 imm: 0
	 2: LdXMemDW dst: r5 src: r2 off: 16 imm: 0
	 3: JGTImm dst: r3 off: -1 imm: 511 <dsl_pm_gtp_3_0_parse_ext_cb_break>
	 4: MovReg dst: r0 src: r4
	 5: AddReg dst: r0 src: r3
	 6: AddImm dst: r0 imm: 4
	 7: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_gtp_3_0_parse_ext_cb_break>
	 8: AddImm dst: r3 imm: 4
	 9: StXMemDW dst: r2 src: r3 off: 0 imm: 0
	10: JLTImm dst: r3 off: -1 imm: 1 <dsl_pm_gtp_3_0_parse_ext_cb_break>
	11: MovReg dst: r1 src: r3
	12: SubImm dst: r1 imm: 1
	13: JGTImm dst: r1 off: -1 imm: 511 <dsl_pm_gtp_3_0_parse_ext_cb_break>
	14: MovReg dst: r0 src: r4
	15: AddReg dst: r0 src: r1
	16: AddImm dst: r0 imm: 1
	17: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_gtp_3_0_parse_ext_cb_break>
	18: LdXMemB dst: r0 src: r0 off: -1 imm: 0
	19: StXMemDW dst: rfp src: r0 off: -56 imm: 0
	20: JLTImm dst: r3 off: -1 imm: 4 <dsl_pm_gtp_3_0_parse_ext_cb_break>
	21: MovReg dst: r0 src: r3
	22: SubImm dst: r0 imm: 4
	23: JGTImm dst: r0 off: -1 imm: 511 <dsl_pm_gtp_3_0_parse_ext_cb_break>
	24: MovReg dst: r1 src: r4
	25: AddReg dst: r1 src: r0
	26: AddImm dst: r1 imm: 1
	27: JGTReg dst: r1 off: -1 src: r5 <dsl_pm_gtp_3_0_parse_ext_cb_break>
	28: LdXMemB dst: r1 src: r1 off: -1 imm: 0
	29: AndImm dst: r1 imm: 255
	30: LShImm dst: r1 imm: 2
	31: JLTImm dst: r1 off: -1 imm: 4 <dsl_pm_gtp_3_0_parse_ext_cb_break>
	32: SubImm dst: r1 imm: 4
	33: AddReg dst: r3 src: r1
	34: JGTImm dst: r3 off: -1 imm: 512 <dsl_pm_gtp_3_0_parse_ext_cb_break>
	35: MovReg dst: r0 src: r4
	36: AddReg dst: r0 src: r3
	37: JGTReg dst: r0 off: -1 src: r5 <dsl_pm_gtp_3_0_parse_ext_cb_break>
	38: StXMemDW dst: r2 src: r3 off: 0 imm: 0
	39: LdXMemDW dst: r0 src: rfp off: -56 imm: 0
	40: JNEImm dst: r0 off: -1 imm: 0 <dsl_pm_gtp_3_0_vcb_case_6_skip>
	41: Ja off: -1 <dsl_pm_gtp_3_0_parse_ext_cb_break>
dsl_pm_gtp_3_0_vcb_case_6_skip:
	42: MovReg dst: r3 src: r3
	43: Ja off: -1 <dsl_pm_gtp_3_0_parse_ext_cb_continue>
dsl_pm_gtp_3_0_parse_ext_cb_continue:
	44: MovImm dst: r0 imm: 0
	45: Exit
dsl_pm_gtp_3_0_parse_ext_cb_break:
	46: MovImm dst: r0 imm: 1
	47: Exit
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame true
== Extractions
== Warnings
