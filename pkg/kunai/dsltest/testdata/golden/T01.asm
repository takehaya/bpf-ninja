# host: tc_entry
# expr: eth/ipv4+/tcp
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
	  65: JNEImm dst: r3 off: -1 imm: 4 <dsl_chain_done_1>
	  66: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	  67: MovImm dst: r3 imm: 0
	  68: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	  69: MovReg dst: r3 src: r0
	  70: AddReg dst: r3 src: r4
	  71: AddImm dst: r3 imm: 20
	  72: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	  73: AddImm dst: r4 imm: 20
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
	  87: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	  88: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	  89: MovReg dst: r5 src: r4
	  90: SubImm dst: r5 imm: 20
	  91: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	  92: MovReg dst: r3 src: r0
	  93: AddReg dst: r3 src: r5
	  94: AddImm dst: r3 imm: 1
	  95: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	  96: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	  97: RShImm dst: r3 imm: 4
	  98: AndImm dst: r3 imm: 15
	  99: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_1_0_i1_case_1_skip>
	 100: Ja off: -1 <dsl_pm_ipv4_1_0_i1_walk>
dsl_pm_ipv4_1_0_i1_case_1_skip:
	 101: MovReg dst: r3 src: r3
	 102: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_1_0_i1_walk:
	 103: MovReg dst: r3 src: r3
	 104: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 105: MovReg dst: r3 src: r4
	 106: SubImm dst: r3 imm: 20
	 107: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 108: MovReg dst: r5 src: r0
	 109: AddReg dst: r5 src: r3
	 110: AddImm dst: r5 imm: 1
	 111: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 112: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 113: AndImm dst: r5 imm: 15
	 114: LShImm dst: r5 imm: 2
	 115: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 116: SubImm dst: r5 imm: 20
	 117: AddReg dst: r4 src: r5
	 118: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 119: MovReg dst: r3 src: r0
	 120: AddReg dst: r3 src: r4
	 121: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 122: Ja off: -1 <dsl_pm_ipv4_1_0_i1_done>
dsl_pm_ipv4_1_0_i1_done:
	 123: MovReg dst: r0 src: r0
	 124: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	 125: MovReg dst: r5 src: r3
	 126: AddImm dst: r5 imm: 9
	 127: JGTImm dst: r5 off: -1 imm: 511 <dsl_chain_done_1>
	 128: MovReg dst: r3 src: r0
	 129: AddReg dst: r3 src: r5
	 130: AddImm dst: r3 imm: 1
	 131: JGTReg dst: r3 off: -1 src: r1 <dsl_chain_done_1>
	 132: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 133: JNEImm dst: r3 off: -1 imm: 4 <dsl_chain_done_1>
	 134: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 135: MovImm dst: r3 imm: 0
	 136: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 137: MovReg dst: r3 src: r0
	 138: AddReg dst: r3 src: r4
	 139: AddImm dst: r3 imm: 20
	 140: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 141: AddImm dst: r4 imm: 20
	 142: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 143: MovReg dst: r3 src: r4
	 144: SubImm dst: r3 imm: 20
	 145: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 146: MovReg dst: r5 src: r0
	 147: AddReg dst: r5 src: r3
	 148: AddImm dst: r5 imm: 1
	 149: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 150: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 151: AndImm dst: r5 imm: 15
	 152: LShImm dst: r5 imm: 2
	 153: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 154: SubImm dst: r5 imm: 20
	 155: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 156: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 157: MovReg dst: r5 src: r4
	 158: SubImm dst: r5 imm: 20
	 159: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	 160: MovReg dst: r3 src: r0
	 161: AddReg dst: r3 src: r5
	 162: AddImm dst: r3 imm: 1
	 163: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 164: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 165: RShImm dst: r3 imm: 4
	 166: AndImm dst: r3 imm: 15
	 167: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_1_0_i2_case_1_skip>
	 168: Ja off: -1 <dsl_pm_ipv4_1_0_i2_walk>
dsl_pm_ipv4_1_0_i2_case_1_skip:
	 169: MovReg dst: r3 src: r3
	 170: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_1_0_i2_walk:
	 171: MovReg dst: r3 src: r3
	 172: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 173: MovReg dst: r3 src: r4
	 174: SubImm dst: r3 imm: 20
	 175: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 176: MovReg dst: r5 src: r0
	 177: AddReg dst: r5 src: r3
	 178: AddImm dst: r5 imm: 1
	 179: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 180: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 181: AndImm dst: r5 imm: 15
	 182: LShImm dst: r5 imm: 2
	 183: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 184: SubImm dst: r5 imm: 20
	 185: AddReg dst: r4 src: r5
	 186: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 187: MovReg dst: r3 src: r0
	 188: AddReg dst: r3 src: r4
	 189: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 190: Ja off: -1 <dsl_pm_ipv4_1_0_i2_done>
dsl_pm_ipv4_1_0_i2_done:
	 191: MovReg dst: r0 src: r0
	 192: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	 193: MovReg dst: r5 src: r3
	 194: AddImm dst: r5 imm: 9
	 195: JGTImm dst: r5 off: -1 imm: 511 <dsl_chain_done_1>
	 196: MovReg dst: r3 src: r0
	 197: AddReg dst: r3 src: r5
	 198: AddImm dst: r3 imm: 1
	 199: JGTReg dst: r3 off: -1 src: r1 <dsl_chain_done_1>
	 200: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 201: JNEImm dst: r3 off: -1 imm: 4 <dsl_chain_done_1>
	 202: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 203: MovImm dst: r3 imm: 0
	 204: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 205: MovReg dst: r3 src: r0
	 206: AddReg dst: r3 src: r4
	 207: AddImm dst: r3 imm: 20
	 208: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 209: AddImm dst: r4 imm: 20
	 210: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 211: MovReg dst: r3 src: r4
	 212: SubImm dst: r3 imm: 20
	 213: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 214: MovReg dst: r5 src: r0
	 215: AddReg dst: r5 src: r3
	 216: AddImm dst: r5 imm: 1
	 217: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 218: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 219: AndImm dst: r5 imm: 15
	 220: LShImm dst: r5 imm: 2
	 221: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 222: SubImm dst: r5 imm: 20
	 223: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 224: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 225: MovReg dst: r5 src: r4
	 226: SubImm dst: r5 imm: 20
	 227: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	 228: MovReg dst: r3 src: r0
	 229: AddReg dst: r3 src: r5
	 230: AddImm dst: r3 imm: 1
	 231: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 232: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 233: RShImm dst: r3 imm: 4
	 234: AndImm dst: r3 imm: 15
	 235: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_1_0_i3_case_1_skip>
	 236: Ja off: -1 <dsl_pm_ipv4_1_0_i3_walk>
dsl_pm_ipv4_1_0_i3_case_1_skip:
	 237: MovReg dst: r3 src: r3
	 238: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_1_0_i3_walk:
	 239: MovReg dst: r3 src: r3
	 240: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 241: MovReg dst: r3 src: r4
	 242: SubImm dst: r3 imm: 20
	 243: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 244: MovReg dst: r5 src: r0
	 245: AddReg dst: r5 src: r3
	 246: AddImm dst: r5 imm: 1
	 247: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 248: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 249: AndImm dst: r5 imm: 15
	 250: LShImm dst: r5 imm: 2
	 251: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 252: SubImm dst: r5 imm: 20
	 253: AddReg dst: r4 src: r5
	 254: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 255: MovReg dst: r3 src: r0
	 256: AddReg dst: r3 src: r4
	 257: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 258: Ja off: -1 <dsl_pm_ipv4_1_0_i3_done>
dsl_pm_ipv4_1_0_i3_done:
	 259: MovReg dst: r0 src: r0
	 260: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	 261: MovReg dst: r5 src: r3
	 262: AddImm dst: r5 imm: 9
	 263: JGTImm dst: r5 off: -1 imm: 511 <dsl_chain_done_1>
	 264: MovReg dst: r3 src: r0
	 265: AddReg dst: r3 src: r5
	 266: AddImm dst: r3 imm: 1
	 267: JGTReg dst: r3 off: -1 src: r1 <dsl_chain_done_1>
	 268: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 269: JNEImm dst: r3 off: -1 imm: 4 <dsl_chain_done_1>
	 270: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 271: MovImm dst: r3 imm: 0
	 272: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 273: MovReg dst: r3 src: r0
	 274: AddReg dst: r3 src: r4
	 275: AddImm dst: r3 imm: 20
	 276: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 277: AddImm dst: r4 imm: 20
	 278: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 279: MovReg dst: r3 src: r4
	 280: SubImm dst: r3 imm: 20
	 281: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 282: MovReg dst: r5 src: r0
	 283: AddReg dst: r5 src: r3
	 284: AddImm dst: r5 imm: 1
	 285: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 286: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 287: AndImm dst: r5 imm: 15
	 288: LShImm dst: r5 imm: 2
	 289: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 290: SubImm dst: r5 imm: 20
	 291: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 292: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 293: MovReg dst: r5 src: r4
	 294: SubImm dst: r5 imm: 20
	 295: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	 296: MovReg dst: r3 src: r0
	 297: AddReg dst: r3 src: r5
	 298: AddImm dst: r3 imm: 1
	 299: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 300: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 301: RShImm dst: r3 imm: 4
	 302: AndImm dst: r3 imm: 15
	 303: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_1_0_i4_case_1_skip>
	 304: Ja off: -1 <dsl_pm_ipv4_1_0_i4_walk>
dsl_pm_ipv4_1_0_i4_case_1_skip:
	 305: MovReg dst: r3 src: r3
	 306: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_1_0_i4_walk:
	 307: MovReg dst: r3 src: r3
	 308: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 309: MovReg dst: r3 src: r4
	 310: SubImm dst: r3 imm: 20
	 311: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 312: MovReg dst: r5 src: r0
	 313: AddReg dst: r5 src: r3
	 314: AddImm dst: r5 imm: 1
	 315: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 316: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 317: AndImm dst: r5 imm: 15
	 318: LShImm dst: r5 imm: 2
	 319: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 320: SubImm dst: r5 imm: 20
	 321: AddReg dst: r4 src: r5
	 322: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 323: MovReg dst: r3 src: r0
	 324: AddReg dst: r3 src: r4
	 325: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 326: Ja off: -1 <dsl_pm_ipv4_1_0_i4_done>
dsl_pm_ipv4_1_0_i4_done:
	 327: MovReg dst: r0 src: r0
	 328: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	 329: MovReg dst: r5 src: r3
	 330: AddImm dst: r5 imm: 9
	 331: JGTImm dst: r5 off: -1 imm: 511 <dsl_chain_done_1>
	 332: MovReg dst: r3 src: r0
	 333: AddReg dst: r3 src: r5
	 334: AddImm dst: r3 imm: 1
	 335: JGTReg dst: r3 off: -1 src: r1 <dsl_chain_done_1>
	 336: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 337: JNEImm dst: r3 off: -1 imm: 4 <dsl_chain_done_1>
	 338: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 339: MovImm dst: r3 imm: 0
	 340: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 341: MovReg dst: r3 src: r0
	 342: AddReg dst: r3 src: r4
	 343: AddImm dst: r3 imm: 20
	 344: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 345: AddImm dst: r4 imm: 20
	 346: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 347: MovReg dst: r3 src: r4
	 348: SubImm dst: r3 imm: 20
	 349: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 350: MovReg dst: r5 src: r0
	 351: AddReg dst: r5 src: r3
	 352: AddImm dst: r5 imm: 1
	 353: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 354: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 355: AndImm dst: r5 imm: 15
	 356: LShImm dst: r5 imm: 2
	 357: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 358: SubImm dst: r5 imm: 20
	 359: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 360: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 361: MovReg dst: r5 src: r4
	 362: SubImm dst: r5 imm: 20
	 363: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	 364: MovReg dst: r3 src: r0
	 365: AddReg dst: r3 src: r5
	 366: AddImm dst: r3 imm: 1
	 367: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 368: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 369: RShImm dst: r3 imm: 4
	 370: AndImm dst: r3 imm: 15
	 371: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_1_0_i5_case_1_skip>
	 372: Ja off: -1 <dsl_pm_ipv4_1_0_i5_walk>
dsl_pm_ipv4_1_0_i5_case_1_skip:
	 373: MovReg dst: r3 src: r3
	 374: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_1_0_i5_walk:
	 375: MovReg dst: r3 src: r3
	 376: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 377: MovReg dst: r3 src: r4
	 378: SubImm dst: r3 imm: 20
	 379: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 380: MovReg dst: r5 src: r0
	 381: AddReg dst: r5 src: r3
	 382: AddImm dst: r5 imm: 1
	 383: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 384: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 385: AndImm dst: r5 imm: 15
	 386: LShImm dst: r5 imm: 2
	 387: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 388: SubImm dst: r5 imm: 20
	 389: AddReg dst: r4 src: r5
	 390: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 391: MovReg dst: r3 src: r0
	 392: AddReg dst: r3 src: r4
	 393: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 394: Ja off: -1 <dsl_pm_ipv4_1_0_i5_done>
dsl_pm_ipv4_1_0_i5_done:
	 395: MovReg dst: r0 src: r0
	 396: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	 397: MovReg dst: r5 src: r3
	 398: AddImm dst: r5 imm: 9
	 399: JGTImm dst: r5 off: -1 imm: 511 <dsl_chain_done_1>
	 400: MovReg dst: r3 src: r0
	 401: AddReg dst: r3 src: r5
	 402: AddImm dst: r3 imm: 1
	 403: JGTReg dst: r3 off: -1 src: r1 <dsl_chain_done_1>
	 404: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 405: JNEImm dst: r3 off: -1 imm: 4 <dsl_chain_done_1>
	 406: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 407: MovImm dst: r3 imm: 0
	 408: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 409: MovReg dst: r3 src: r0
	 410: AddReg dst: r3 src: r4
	 411: AddImm dst: r3 imm: 20
	 412: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 413: AddImm dst: r4 imm: 20
	 414: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 415: MovReg dst: r3 src: r4
	 416: SubImm dst: r3 imm: 20
	 417: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 418: MovReg dst: r5 src: r0
	 419: AddReg dst: r5 src: r3
	 420: AddImm dst: r5 imm: 1
	 421: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 422: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 423: AndImm dst: r5 imm: 15
	 424: LShImm dst: r5 imm: 2
	 425: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 426: SubImm dst: r5 imm: 20
	 427: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 428: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 429: MovReg dst: r5 src: r4
	 430: SubImm dst: r5 imm: 20
	 431: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	 432: MovReg dst: r3 src: r0
	 433: AddReg dst: r3 src: r5
	 434: AddImm dst: r3 imm: 1
	 435: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 436: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 437: RShImm dst: r3 imm: 4
	 438: AndImm dst: r3 imm: 15
	 439: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_1_0_i6_case_1_skip>
	 440: Ja off: -1 <dsl_pm_ipv4_1_0_i6_walk>
dsl_pm_ipv4_1_0_i6_case_1_skip:
	 441: MovReg dst: r3 src: r3
	 442: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_1_0_i6_walk:
	 443: MovReg dst: r3 src: r3
	 444: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 445: MovReg dst: r3 src: r4
	 446: SubImm dst: r3 imm: 20
	 447: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 448: MovReg dst: r5 src: r0
	 449: AddReg dst: r5 src: r3
	 450: AddImm dst: r5 imm: 1
	 451: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 452: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 453: AndImm dst: r5 imm: 15
	 454: LShImm dst: r5 imm: 2
	 455: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 456: SubImm dst: r5 imm: 20
	 457: AddReg dst: r4 src: r5
	 458: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 459: MovReg dst: r3 src: r0
	 460: AddReg dst: r3 src: r4
	 461: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 462: Ja off: -1 <dsl_pm_ipv4_1_0_i6_done>
dsl_pm_ipv4_1_0_i6_done:
	 463: MovReg dst: r0 src: r0
	 464: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	 465: MovReg dst: r5 src: r3
	 466: AddImm dst: r5 imm: 9
	 467: JGTImm dst: r5 off: -1 imm: 511 <dsl_chain_done_1>
	 468: MovReg dst: r3 src: r0
	 469: AddReg dst: r3 src: r5
	 470: AddImm dst: r3 imm: 1
	 471: JGTReg dst: r3 off: -1 src: r1 <dsl_chain_done_1>
	 472: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 473: JNEImm dst: r3 off: -1 imm: 4 <dsl_chain_done_1>
	 474: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 475: MovImm dst: r3 imm: 0
	 476: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 477: MovReg dst: r3 src: r0
	 478: AddReg dst: r3 src: r4
	 479: AddImm dst: r3 imm: 20
	 480: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 481: AddImm dst: r4 imm: 20
	 482: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 483: MovReg dst: r3 src: r4
	 484: SubImm dst: r3 imm: 20
	 485: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 486: MovReg dst: r5 src: r0
	 487: AddReg dst: r5 src: r3
	 488: AddImm dst: r5 imm: 1
	 489: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 490: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 491: AndImm dst: r5 imm: 15
	 492: LShImm dst: r5 imm: 2
	 493: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 494: SubImm dst: r5 imm: 20
	 495: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 496: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 497: MovReg dst: r5 src: r4
	 498: SubImm dst: r5 imm: 20
	 499: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	 500: MovReg dst: r3 src: r0
	 501: AddReg dst: r3 src: r5
	 502: AddImm dst: r3 imm: 1
	 503: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 504: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 505: RShImm dst: r3 imm: 4
	 506: AndImm dst: r3 imm: 15
	 507: JNEImm dst: r3 off: -1 imm: 4 <dsl_pm_ipv4_1_0_i7_case_1_skip>
	 508: Ja off: -1 <dsl_pm_ipv4_1_0_i7_walk>
dsl_pm_ipv4_1_0_i7_case_1_skip:
	 509: MovReg dst: r3 src: r3
	 510: Ja off: -1 <dsl_reject>
dsl_pm_ipv4_1_0_i7_walk:
	 511: MovReg dst: r3 src: r3
	 512: JLTImm dst: r4 off: -1 imm: 20 <dsl_reject>
	 513: MovReg dst: r3 src: r4
	 514: SubImm dst: r3 imm: 20
	 515: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 516: MovReg dst: r5 src: r0
	 517: AddReg dst: r5 src: r3
	 518: AddImm dst: r5 imm: 1
	 519: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 520: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 521: AndImm dst: r5 imm: 15
	 522: LShImm dst: r5 imm: 2
	 523: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 524: SubImm dst: r5 imm: 20
	 525: AddReg dst: r4 src: r5
	 526: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 527: MovReg dst: r3 src: r0
	 528: AddReg dst: r3 src: r4
	 529: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 530: Ja off: -1 <dsl_pm_ipv4_1_0_i7_done>
dsl_pm_ipv4_1_0_i7_done:
	 531: MovReg dst: r0 src: r0
dsl_chain_done_1:
	 532: MovReg dst: r0 src: r0
	 533: LdXMemDW dst: r3 src: rfp off: -184 imm: 0
	 534: MovReg dst: r5 src: r3
	 535: AddImm dst: r5 imm: 9
	 536: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	 537: MovReg dst: r3 src: r0
	 538: AddReg dst: r3 src: r5
	 539: AddImm dst: r3 imm: 1
	 540: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 541: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 542: JNEImm dst: r3 off: -1 imm: 6 <dsl_reject>
	 543: StXMemDW dst: rfp src: r4 off: -184 imm: 0
	 544: MovImm dst: r3 imm: 0
	 545: StXMemDW dst: rfp src: r3 off: -216 imm: 0
	 546: MovReg dst: r3 src: r0
	 547: AddReg dst: r3 src: r4
	 548: AddImm dst: r3 imm: 20
	 549: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 550: AddImm dst: r4 imm: 20
	 551: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 552: MovReg dst: r3 src: r4
	 553: SubImm dst: r3 imm: 8
	 554: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 555: MovReg dst: r5 src: r0
	 556: AddReg dst: r5 src: r3
	 557: AddImm dst: r5 imm: 1
	 558: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 559: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 560: AndImm dst: r5 imm: 240
	 561: RShImm dst: r5 imm: 4
	 562: LShImm dst: r5 imm: 2
	 563: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 564: SubImm dst: r5 imm: 20
	 565: StXMemDW dst: rfp src: r5 off: -216 imm: 0
	 566: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 567: MovReg dst: r5 src: r4
	 568: SubImm dst: r5 imm: 8
	 569: JGTImm dst: r5 off: -1 imm: 511 <dsl_reject>
	 570: MovReg dst: r3 src: r0
	 571: AddReg dst: r3 src: r5
	 572: AddImm dst: r3 imm: 1
	 573: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 574: LdXMemB dst: r3 src: r3 off: -1 imm: 0
	 575: RShImm dst: r3 imm: 4
	 576: AndImm dst: r3 imm: 15
	 577: JNEImm dst: r3 off: -1 imm: 5 <dsl_pm_tcp_2_0_case_1_skip>
	 578: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_case_1_skip:
	 579: MovReg dst: r3 src: r3
	 580: Ja off: -1 <dsl_pm_tcp_2_0_parse_options>
dsl_pm_tcp_2_0_parse_options:
	 581: MovReg dst: r3 src: r3
	 582: JLTImm dst: r4 off: -1 imm: 8 <dsl_reject>
	 583: MovReg dst: r3 src: r4
	 584: SubImm dst: r3 imm: 8
	 585: JGTImm dst: r3 off: -1 imm: 511 <dsl_reject>
	 586: MovReg dst: r5 src: r0
	 587: AddReg dst: r5 src: r3
	 588: AddImm dst: r5 imm: 1
	 589: JGTReg dst: r5 off: -1 src: r1 <dsl_reject>
	 590: LdXMemB dst: r5 src: r5 off: -1 imm: 0
	 591: AndImm dst: r5 imm: 240
	 592: RShImm dst: r5 imm: 4
	 593: LShImm dst: r5 imm: 2
	 594: JLTImm dst: r5 off: -1 imm: 20 <dsl_reject>
	 595: SubImm dst: r5 imm: 20
	 596: AddReg dst: r4 src: r5
	 597: JGTImm dst: r4 off: -1 imm: 512 <dsl_reject>
	 598: MovReg dst: r3 src: r0
	 599: AddReg dst: r3 src: r4
	 600: JGTReg dst: r3 off: -1 src: r1 <dsl_reject>
	 601: Ja off: -1 <dsl_pm_tcp_2_0_done>
dsl_pm_tcp_2_0_done:
	 602: MovReg dst: r0 src: r0
	 603: MovImm dst: r2 imm: 1
	 604: Ja off: -1 <filter_result>
dsl_reject:
	 605: MovImm dst: r2 imm: 0
== Callbacks
== Capture MaxCapLen=0 FilterMinPrefix=0
== WireFrame false
== Extractions
== Warnings
