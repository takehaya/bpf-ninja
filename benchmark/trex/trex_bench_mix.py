#!/usr/bin/env python3
"""TRex v3.08 bench probe — 50:50 TCP/443 + TCP/80 mix.

For axis-2 match-rate sweep: combined with an xdp-ninja filter
`tcp port 443`, exactly half the offered packets match. Pair with
`tcp port 80` for the other half, `udp` for 0% match, or no filter
for 100% match.

Usage: trex_bench_mix.py <duration_sec>
Output: single JSON line with TX/RX stats (avg over duration).
"""
import sys, time, json
sys.path.insert(0, "/opt/trex/v3.08/scripts/automation/trex_control_plane/interactive")
from trex.stl.api import *

SRC_MAC = "40:a6:b7:82:cd:d8"
DST_MAC = "40:a6:b7:95:a2:d0"
SRC_IP  = "10.99.0.2"
DST_IP  = "10.99.0.1"


def build_streams():
    # Randomize src IP + src port across the 64-bucket RSS landing.
    def vm():
        return STLScVmRaw([
            STLVmFlowVar(name="sip", min_value=0x08000001, max_value=0x08FFFFFF, size=4, op="random"),
            STLVmWrFlowVar(fv_name="sip", pkt_offset=26),
            STLVmFlowVar(name="sp", min_value=1024, max_value=60000, size=2, op="random"),
            STLVmWrFlowVar(fv_name="sp", pkt_offset=34),
            STLVmFixIpv4(offset="IP"),
        ])

    base = Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=SRC_IP, dst=DST_IP)
    pkt_443 = base / TCP(sport=12345, dport=443, flags="S") / ("X" * 6)
    pkt_80  = base / TCP(sport=12345, dport=80,  flags="S") / ("X" * 6)
    # 64B total = 14 (eth) + 20 (ip) + 20 (tcp) + 6 (payload) + 4 (CRC excluded by TRex)
    return [
        STLStream(packet=STLPktBuilder(pkt=pkt_443, vm=vm()),
                  mode=STLTXCont(pps=100e6)),
        STLStream(packet=STLPktBuilder(pkt=pkt_80,  vm=vm()),
                  mode=STLTXCont(pps=100e6)),
    ]


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    duration = int(sys.argv[1])

    c = STLClient(server="127.0.0.1")
    c.connect()
    c.acquire(ports=[0], force=True)
    c.reset(ports=[0])
    c.add_streams(build_streams(), ports=[0])
    c.clear_stats()
    c.start(ports=[0], mult="100%")
    time.sleep(duration)
    c.stop(ports=[0])
    s = c.get_stats()[0]

    opackets = s.get("opackets", 0)
    ipackets = s.get("ipackets", 0)
    print(json.dumps({
        "tx_pps":      round(s.get("tx_pps", 0), 0),
        "rx_pps":      round(s.get("rx_pps", 0), 0),
        "opackets":    opackets,
        "ipackets":    ipackets,
        "oerrors":     s.get("oerrors", 0),
        "ierrors":     s.get("ierrors", 0),
        "avg_tx_mpps": round(opackets / duration / 1e6, 3),
        "avg_rx_mpps": round(ipackets / duration / 1e6, 3),
    }))
    c.release(ports=[0])
    c.disconnect()


if __name__ == "__main__":
    main()
