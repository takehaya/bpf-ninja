package injectcheck

// Helper argument counts from the Linux UAPI prototypes in bpf_helper_defs.h.
// Unknown IDs conservatively use all five arguments. These ABI facts are
// independent of the transformer's site classification and liveness claims.
func helperReads(id int64) uint16 {
	switch id {
	case 5, 7, 8, 14, 15, 35, 42, 80, 118, 125, 158, 160, 186, 208:
		return 0x0
	case 17, 19, 24, 34, 41, 46, 47, 77, 79, 86, 93, 94, 95, 96, 97, 98, 109, 117, 122, 123, 128, 136, 137, 138, 139, 140, 151, 154, 162, 168, 172, 173, 174, 175, 178, 185, 187, 188, 196:
		return 0x2
	case 1, 3, 16, 22, 23, 32, 37, 39, 40, 44, 48, 54, 58, 59, 61, 62, 65, 81, 83, 88, 89, 108, 116, 129, 132, 133, 134, 135, 146, 153, 155, 157, 159, 170, 184, 194, 199, 200, 206, 207, 211:
		return 0x6
	case 4, 12, 13, 18, 27, 29, 30, 31, 33, 36, 38, 43, 45, 51, 56, 64, 75, 87, 92, 102, 103, 104, 112, 113, 114, 115, 124, 127, 131, 144, 147, 148, 161, 166, 169, 171, 176, 182, 183, 192, 193, 195, 203, 204, 205:
		return 0xe
	case 2, 20, 21, 26, 50, 52, 53, 55, 60, 63, 67, 69, 70, 71, 72, 73, 74, 76, 78, 82, 90, 91, 101, 105, 106, 107, 119, 120, 130, 141, 142, 143, 145, 150, 152, 156, 164, 167, 177, 179, 181, 189, 190, 197, 198, 209, 210:
		return 0x1e
	default:
		return 0x3e
	}
}
