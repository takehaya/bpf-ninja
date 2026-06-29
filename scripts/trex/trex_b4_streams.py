#!/usr/bin/env python3
"""TRex stream driver for the B4 filter-only XDP drop bench (§5.5).

Usage: trex_b4_streams.py <stream> <duration_sec>
  stream: udp64 | tcp443 | gtpu | srv6
  duration_sec: integer

Streams (continuous, mult=100%):
  udp64   64B Ether/IPv4/UDP dport 9          — floor / accept_all cells
  tcp443  64B Ether/IPv4/TCP dport 443        — F1 match path (kunai & cbpfc)
  gtpu    90B Ether/IPv4/UDP:2152/GTP-U/IPv4(dst 10.0.0.1)/TCP
                                              — F7 match path (full chain walk)
  srv6   130B Ether/IPv6/SRH(3 segs, fc00::1 last)/TCP
                                              — F8 match path (walks all 3 segments)

Flow spread: NO STLScVmRaw randomization. TRex's VM path re-parses the
packet to pick its header/payload split point, fails on the SRH
(routing type 4), and silently truncates the frame to the parsed 54B
prefix. Instead every stream type emits N_FLOWS static streams with
distinct source addresses, which spreads RSS on the DUT identically
across all cells. GTP-U header and SRH are raw bytes (no scapy
contrib); all packets go in via pkt_buffer.

Output: single JSON line with opackets / avg_tx_mpps.
"""
import sys, time, json, struct, socket
sys.path.insert(0, "/opt/trex/v3.08/scripts/automation/trex_control_plane/interactive")
from trex.stl.api import *

SRC_MAC = "40:a6:b7:82:cd:d8"
DST_MAC = "40:a6:b7:95:a2:d0"
DST_IP  = "10.99.0.1"

N_FLOWS = 32
TOTAL_PPS = 200e6


def ip6(a):
    return socket.inet_pton(socket.AF_INET6, a)


def gtpu_bytes(inner, teid=0x1234):
    # GTPv1-U fixed 8B header: flags 0x30 (v1, PT=1), type 0xFF (G-PDU),
    # length = payload bytes after the 8B header, then TEID.
    return struct.pack("!BBHI", 0x30, 0xFF, len(inner), teid) + inner


def srh_bytes(segs, nh=6):
    # RFC 8754 SRH: nh, hdr_ext_len (8B units excl. first 8), routing
    # type 4, segments_left, last_entry, flags, tag, then 16B segments.
    body = b"".join(segs)
    return struct.pack("!BBBBBBH", nh, len(body) // 8, 4, len(segs) - 1,
                       len(segs) - 1, 0, 0) + body


def geneve_bytes(inner_eth, vni=0x000064, opt_words=1):
    # RFC 8926 Geneve fixed 8B header: ver(2)/opt_len(6, in 4B units),
    # O/C/rsvd flags, protocol type 0x6558 (Trans Ether Bridging),
    # 24b VNI + 8b reserved, then opt_len*4 option bytes, then the
    # inner Ethernet frame. opt_words>0 exercises the option-skip
    # advance (same path the §5.3 opt_len>0 correctness case covers).
    optlen = opt_words & 0x3F
    hdr = struct.pack("!BBH", (0 << 6) | optlen, 0x00, 0x6558)
    hdr += struct.pack("!I", (vni << 8) & 0xFFFFFFFF)  # 24b VNI + 8b rsvd
    return hdr + (b"\x00\x00\x00\x00" * opt_words) + inner_eth


def frame(i, label):
    src4 = "10.%d.0.2" % (8 + i)
    if label == "udp64":
        return bytes(Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src4, dst=DST_IP)
                     / UDP(sport=12345 + i, dport=9) / ("X" * 18))
    if label == "tcp443":
        return bytes(Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src4, dst=DST_IP)
                     / TCP(sport=12345 + i, dport=443, flags="S"))
    if label == "gtpu":
        inner = bytes(IP(src="192.168.0.1", dst="10.0.0.1")
                      / TCP(sport=1024, dport=80, flags="S"))
        return bytes(Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src4, dst=DST_IP)
                     / UDP(sport=2152 + i, dport=2152)) + gtpu_bytes(inner)
    if label == "srv6":
        # fc00::1 in the LAST scanned slot so any() walks all 3 segments.
        srh = srh_bytes([ip6("fc00::3"), ip6("fc00::2"), ip6("fc00::1")])
        tcp = bytes(TCP(sport=1024, dport=80, flags="S"))
        hdr = bytes(Ether(src=SRC_MAC, dst=DST_MAC)
                    / IPv6(src="2001:db8::%x:2" % i, dst="2001:db8::1",
                           nh=43, plen=len(srh) + len(tcp)))
        return hdr + srh + tcp
    if label == "geneve":
        # F9: eth/ipv4@outer/udp/geneve/eth/ipv4@inner/tcp where inner.dst == 10.0.0.1
        inner = bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                      / IP(src="192.168.0.1", dst="10.0.0.1")
                      / TCP(sport=1024, dport=80, flags="S"))
        return bytes(Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src4, dst=DST_IP)
                     / UDP(sport=20000 + i, dport=6081)) + geneve_bytes(inner)
    if label == "tcpmss":
        # F10: eth/ipv4/tcp where tcp.options.MSS.value == 1460
        return bytes(Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src4, dst=DST_IP)
                     / TCP(sport=12345 + i, dport=443, flags="S",
                           options=[("MSS", 1460)]))
    if label == "tcp80":
        # F2: eth/ipv4[src==10.0.0.0/8]/tcp where tcp.dport == 80 (src4 in 10/8)
        return bytes(Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src4, dst=DST_IP)
                     / TCP(sport=12345 + i, dport=80, flags="S"))
    if label == "ipv6tcp":
        # F3: eth/ipv6[src==2001:db8::/32]/tcp
        return bytes(Ether(src=SRC_MAC, dst=DST_MAC)
                     / IPv6(src="2001:db8::%x:2" % i, dst="2001:db8::1")
                     / TCP(sport=12345 + i, dport=80, flags="S"))
    if label == "vlan":
        # F4: eth/vlan[tci==100]/ipv4/tcp where tcp.dport == 80
        return bytes(Ether(src=SRC_MAC, dst=DST_MAC) / Dot1Q(vlan=100)
                     / IP(src=src4, dst=DST_IP)
                     / TCP(sport=12345 + i, dport=80, flags="S"))
    if label == "qinq":
        # F5: eth/qinq/vlan/ipv4/tcp where tcp.dport == 80
        # eth.ethertype 0x88A8 -> qinq (S-tag); qinq.ethertype 0x8100 -> vlan (C-tag)
        return bytes(Ether(src=SRC_MAC, dst=DST_MAC, type=0x88a8)
                     / Dot1Q(vlan=200, type=0x8100) / Dot1Q(vlan=100)
                     / IP(src=src4, dst=DST_IP)
                     / TCP(sport=12345 + i, dport=80, flags="S"))
    if label == "icmp":
        # F6: eth/ipv4/icmp where icmp.type == 8 (echo request)
        return bytes(Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src4, dst=DST_IP)
                     / ICMP(type=8))
    raise ValueError("unknown stream: %s" % label)


def build_streams(label):
    return [
        STLStream(packet=STLPktBuilder(pkt_buffer=frame(i, label)),
                  mode=STLTXCont(pps=TOTAL_PPS / N_FLOWS))
        for i in range(N_FLOWS)
    ]


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    label = sys.argv[1].lower()
    duration = int(sys.argv[2])

    c = STLClient(server="127.0.0.1")
    c.connect()
    c.acquire(ports=[0], force=True)
    c.reset(ports=[0])
    c.add_streams(build_streams(label), ports=[0])
    c.clear_stats()
    c.start(ports=[0], mult="100%")
    time.sleep(duration)
    c.stop(ports=[0])
    s = c.get_stats()[0]

    opackets = s.get("opackets", 0)
    print(json.dumps({
        "stream":      label,
        "opackets":    opackets,
        "oerrors":     s.get("oerrors", 0),
        "avg_tx_mpps": round(opackets / duration / 1e6, 3),
        "tx_bps_Gbps": round(s.get("tx_bps", 0) / 1e9, 3),
    }))
    c.release(ports=[0])
    c.disconnect()


if __name__ == "__main__":
    main()
