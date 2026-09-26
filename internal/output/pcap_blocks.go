package output

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// validatePcapBlocks verifies framing before publishing a merge. NgReader can
// return io.EOF for both a clean end and a truncated packet/trailer, so its EOF
// alone is not evidence that all input packets were read. This bounded-memory
// pass also checks the duplicate length at each block's end.
func validatePcapBlocks(src io.Reader) error {
	r := bufio.NewReaderSize(src, 64<<10)
	var order binary.ByteOrder
	var header [12]byte
	var trailer [4]byte
	for {
		_, err := io.ReadFull(r, header[:8])
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		used := uint32(8)
		if binary.LittleEndian.Uint32(header[:4]) == 0x0a0d0d0a {
			if _, err := io.ReadFull(r, header[8:]); err != nil {
				return err
			}
			used = 12
			switch binary.LittleEndian.Uint32(header[8:]) {
			case 0x1a2b3c4d:
				order = binary.LittleEndian
			case 0x4d3c2b1a:
				order = binary.BigEndian
			default:
				return fmt.Errorf("invalid pcap-ng byte-order magic")
			}
		}
		if order == nil {
			return fmt.Errorf("pcap-ng input has no section header")
		}
		n := order.Uint32(header[4:8])
		if n < used+4 || n%4 != 0 {
			return fmt.Errorf("invalid pcap-ng block length %d", n)
		}
		if _, err := io.CopyN(io.Discard, r, int64(n-used-4)); err != nil {
			return fmt.Errorf("truncated pcap-ng block: %w", err)
		}
		if _, err := io.ReadFull(r, trailer[:]); err != nil {
			return fmt.Errorf("truncated pcap-ng trailer: %w", err)
		}
		if order.Uint32(trailer[:]) != n {
			return fmt.Errorf("pcap-ng block lengths disagree")
		}
	}
}
