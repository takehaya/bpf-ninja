#!/usr/bin/env python3
"""Check final pcap-ng packets independently of the Go capture/merge writers."""
import argparse
from pathlib import Path
import struct
import sys


def read_exact(stream, length):
    data = stream.read(length)
    if len(data) != length:
        raise ValueError("truncated pcap-ng block")
    return data


def options(data, endian):
    offset = 0
    result = {}
    while offset < len(data):
        if offset + 4 > len(data):
            raise ValueError("truncated option")
        kind, size = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        if kind == 0:
            if size != 0:
                raise ValueError("invalid end option")
            break
        if offset + size > len(data):
            raise ValueError("truncated option value")
        result[kind] = data[offset:offset+size]
        offset += (size+3) & ~3
    return result


def packets(path):
    endian, interfaces = None, []
    with open(path, "rb") as stream:
        while True:
            header = stream.read(8)
            if not header:
                return
            if len(header) != 8:
                raise ValueError("truncated block header")
            if header[:4] == b"\x0a\x0d\x0d\x0a":
                magic = read_exact(stream, 4)
                if magic == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif magic == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    raise ValueError("invalid byte-order magic")
                interfaces = []
            else:
                magic = b""
            if endian is None:
                raise ValueError("missing section header")
            kind, size = struct.unpack(endian + "II", header)
            if size < 12 + len(magic) or size % 4 or size > 64 * 1024 * 1024:
                raise ValueError(f"invalid block length {size}")
            body = magic + read_exact(stream, size - 12 - len(magic))
            if struct.unpack(endian + "I", read_exact(stream, 4))[0] != size:
                raise ValueError("block trailer length mismatch")
            if kind == 1:
                if len(body) < 8:
                    raise ValueError("short interface block")
                linktype, _, snaplen = struct.unpack_from(endian + "HHI", body)
                opts = options(body[8:], endian)
                interfaces.append((linktype, snaplen, opts.get(2, b"").decode("utf-8")))
            elif kind == 6:
                if len(body) < 20:
                    raise ValueError("short enhanced packet block")
                iface, _, _, caplen, original = struct.unpack_from(endian + "IIIII", body)
                if iface >= len(interfaces):
                    raise ValueError("packet refers to missing interface")
                if caplen > original or 20 + ((caplen + 3) & ~3) > len(body):
                    raise ValueError("invalid packet lengths")
                linktype, snaplen, name = interfaces[iface]
                if snaplen and caplen > snaplen:
                    raise ValueError("packet exceeds interface snaplen")
                opts = options(body[20+((caplen+3) & ~3):], endian)
                packet_id = opts.get(5, b"\0"*8)
                if len(packet_id) != 8:
                    raise ValueError("invalid packet ID option length")
                yield {"caplen": caplen, "linktype": linktype, "interface": name,
                       "data": body[20:20+caplen], "packet_id": struct.unpack(endian+"Q", packet_id)[0]}
            elif kind not in {0x0a0d0d0a, 5}:
                raise ValueError(f"unexpected block type {kind}")


def check(path, minimum=1, count=None, caplen=None, linktype=1, interface=None):
    total = 0
    for packet in packets(path):
        total += 1
        if packet["linktype"] != linktype:
            raise ValueError(f"packet {total}: linktype {packet['linktype']}, expected {linktype}")
        if caplen is not None and packet["caplen"] != caplen:
            raise ValueError(f"packet {total}: caplen {packet['caplen']}, expected {caplen}")
        if interface is not None and packet["interface"] != interface:
            raise ValueError(f"packet {total}: interface {packet['interface']!r}, expected {interface!r}")
    if total < minimum or (count is not None and total != count):
        raise ValueError(f"packet count {total}, expected count={count}, minimum={minimum}")
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--min-count", type=int, default=1)
    parser.add_argument("--count", type=int)
    parser.add_argument("--caplen", type=int)
    parser.add_argument("--linktype", type=int, default=1)
    parser.add_argument("--interface")
    args = parser.parse_args()
    try:
        count = check(args.path, args.min_count, args.count, args.caplen, args.linktype, args.interface)
    except (OSError, ValueError, struct.error) as error:
        print(f"pcap assertion failed: {args.path}: {error}", file=sys.stderr)
        return 1
    print(f"pcap verified: {args.path}: {count} packets", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
