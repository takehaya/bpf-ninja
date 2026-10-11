# host: xdp_entry
# expr: eth/ipv4@outer/udp/geneve/eth/ipv4@inner/tcp where inner.dst == 10.0.0.1
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
	 80: JNEImm dst: r3 off: -1 imm: 49431 <dsl_reject>
	 81: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 82: MovImm dst: r3 imm: 0
	 83: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 84: MovReg dst: r3 src: r0
	 85: AddReg dst: r3 src: r4
	 86: AddImm dst: r3 imm: 8
	 87: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 88: AddImm dst: r4 imm: 8
	 89: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 90: MovReg dst: r3 src: r4
	 91: SubImm dst: r3 imm: 8
	 92: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 93: MovReg dst: r5 src: r0
	 94: AddReg dst: r5 src: r3
	 95: AddImm dst: r5 imm: 1
	 96: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 97: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 98: AndImm dst: r5 imm: 63
	 99: LShImm dst: r5 imm: 2
	100: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	101: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	102: MovReg dst: r5 src: r4
	103: SubImm dst: r5 imm: 8
	104: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	105: MovReg dst: r3 src: r0
	106: AddReg dst: r3 src: r5
	107: AddImm dst: r3 imm: 1
	108: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	109: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	110: RShImm dst: r3 imm: 6
	111: AndImm dst: r3 imm: 3
	112: JNEImm dst: r3 off: -1 imm: 0 <dsl_pm_geneve_3_0_case_1_skip>
	113: Ja off: -1 <dsl_pm_geneve_3_0_walk>
dsl_pm_geneve_3_0_case_1_skip:
	114: MovReg dst: r3 src: r3
	115: Ja off: -1 <dsl_reject>
dsl_pm_geneve_3_0_walk:
	116: MovReg dst: r3 src: r3
	117: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	118: MovReg dst: r3 src: r4
	119: SubImm dst: r3 imm: 8
	120: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	121: MovReg dst: r5 src: r0
	122: AddReg dst: r5 src: r3
	123: AddImm dst: r5 imm: 1
	124: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	125: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	126: AndImm dst: r5 imm: 63
	127: LShImm dst: r5 imm: 2
	128: AddReg dst: r4 src: r5
	129: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	130: MovReg dst: r3 src: r0
	131: AddReg dst: r3 src: r4
	132: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	133: Ja off: -1 <dsl_pm_geneve_3_0_done>
dsl_pm_geneve_3_0_done:
	134: MovReg dst: r0 src: r0
	135: MovReg dst: r3 src: r0
	136: AddReg dst: r3 src: r4
	137: AddImm dst: r3 imm: 14
	138: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	139: AddImm dst: r4 imm: 14
	140: JLTImm dst: r4 off: -1 imm: 2 <dsl_reject>
	141: MovReg dst: r5 src: r4
	142: SubImm dst: r5 imm: 2
	143: JGTImm dst: r5 off: -1 imm: 510 <dsl_reject>
	144: MovReg dst: r3 src: r0
	145: AddReg dst: r3 src: r5
	146: AddImm dst: r3 imm: 2
	147: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	148: LdXMemH dst: r3 src: r3 off: -2 imm: 0
	149: JNEImm dst: r3 off: -1 imm: 8 <dsl_reject>
	150: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	151: StXMemDW dst: rfp src: r4 off: -232 imm: 0
	152: MovImm dst: r3 imm: 0
	153: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	154: MovReg dst: r3 src: r0
	155: AddReg dst: r3 src: r4
	156: AddImm dst: r3 imm: 20
	157: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	158: AddImm dst: r4 imm: 20
	159: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	160: MovReg dst: r3 src: r4
	161: SubImm dst: r3 imm: 20
	162: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	163: MovReg dst: r5 src: r0
	164: AddReg dst: r5 src: r3
	165: AddImm dst: r5 imm: 1
	166: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	167: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	168: AndImm dst: r5 imm: 15
	169: LShImm dst: r5 imm: 2
	170: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	171: SubImm dst: r5 imm: 20
	172: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	173: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	174: MovReg dst: r5 src: r4
	175: SubImm dst: r5 imm: 20
	176: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	177: MovReg dst: r3 src: r0
	178: AddReg dst: r3 src: r5
	179: AddImm dst: r3 imm: 1
	180: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	181: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	182: RShImm dst: r3 imm: 4
	183: AndImm dst: r3 imm: 15
	184: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_5_1_case_1_skip>
	185: Ja off: -1 <dsl_pm_ipv4_5_1_walk>
dsl_pm_ipv4_5_1_case_1_skip:
	186: MovReg dst: r3 src: r3
	187: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_5_1_walk:
	188: MovReg dst: r3 src: r3
	189: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	190: MovReg dst: r3 src: r4
	191: SubImm dst: r3 imm: 20
	192: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	193: MovReg dst: r5 src: r0
	194: AddReg dst: r5 src: r3
	195: AddImm dst: r5 imm: 1
	196: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	197: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	198: AndImm dst: r5 imm: 15
	199: LShImm dst: r5 imm: 2
	200: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	201: SubImm dst: r5 imm: 20
	202: AddReg dst: r4 src: r5
	203: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	204: MovReg dst: r3 src: r0
	205: AddReg dst: r3 src: r4
	206: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	207: Ja off: -1 <dsl_pm_ipv4_5_1_done>
dsl_pm_ipv4_5_1_done:
	208: MovReg dst: r0 src: r0
	209: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	210: MovReg dst: r5 src: r3
	211: AddImm dst: r5 imm: 9
	212: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	213: MovReg dst: r3 src: r0
	214: AddReg dst: r3 src: r5
	215: AddImm dst: r3 imm: 1
	216: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	217: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	218: JNEImm dst: r3 off: -1 imm: 6 <dsl_reject>
	219: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	220: MovImm dst: r3 imm: 0
	221: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	222: MovReg dst: r3 src: r0
	223: AddReg dst: r3 src: r4
	224: AddImm dst: r3 imm: 20
	225: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	226: AddImm dst: r4 imm: 20
	227: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	228: MovReg dst: r3 src: r4
	229: SubImm dst: r3 imm: 8
	230: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	231: MovReg dst: r5 src: r0
	232: AddReg dst: r5 src: r3
	233: AddImm dst: r5 imm: 1
	234: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	235: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	236: AndImm dst: r5 imm: 240
	237: RShImm dst: r5 imm: 4
	238: LShImm dst: r5 imm: 2
	239: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	240: SubImm dst: r5 imm: 20
	241: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	242: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	243: MovReg dst: r5 src: r4
	244: SubImm dst: r5 imm: 8
	245: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	246: MovReg dst: r3 src: r0
	247: AddReg dst: r3 src: r5
	248: AddImm dst: r3 imm: 1
	249: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	250: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	251: RShImm dst: r3 imm: 4
	252: AndImm dst: r3 imm: 15
	253: JNEImm dst: r3 off: -1 imm: 5 <dsl_pm_tcp_6_0_case_1_skip>
	254: Ja off: -1 <dsl_pm_tcp_6_0_done>
dsl_pm_tcp_6_0_case_1_skip:
	255: MovReg dst: r3 src: r3
	256: Ja off: -1 <dsl_pm_tcp_6_0_parse_options>
dsl_pm_tcp_6_0_parse_options:
	257: MovReg dst: r3 src: r3
	258: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	259: MovReg dst: r3 src: r4
	260: SubImm dst: r3 imm: 8
	261: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	262: MovReg dst: r5 src: r0
	263: AddReg dst: r5 src: r3
	264: AddImm dst: r5 imm: 1
	265: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	266: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	267: AndImm dst: r5 imm: 240
	268: RShImm dst: r5 imm: 4
	269: LShImm dst: r5 imm: 2
	270: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	271: SubImm dst: r5 imm: 20
	272: AddReg dst: r4 src: r5
	273: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	274: MovReg dst: r3 src: r0
	275: AddReg dst: r3 src: r4
	276: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	277: Ja off: -1 <dsl_pm_tcp_6_0_done>
dsl_pm_tcp_6_0_done:
	278: MovReg dst: r0 src: r0
	279: LdXMemDW dst: r3 src: rfp off: -232 imm: 0
	280: AddImm dst: r3 imm: 16
	281: JGTImm dst: r3 off: -1 imm: 508 <dsl_reject>
	282: AddReg dst: r3 src: r0
	283: AddImm dst: r3 imm: 4
	284: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	285: LdXMemW dst: r3 src: r3 off: -4 imm: 0
	286: LdImmDW dst: r5 imm: 16777226
	288: JNEReg dst: r3 off: -1 src: r5 <dsl_reject>
	289: MovImm dst: r2 imm: 1
	290: Ja off: -1 <filter_result>
dsl_reject:
	291: MovImm dst: r2 imm: 0
== Callbacks
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame true
== Extractions
== Warnings
