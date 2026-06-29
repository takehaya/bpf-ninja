#!/usr/bin/env python3
"""TRex v3.08 hardware-mode bench probe with TX + RX stats.

Usage: trex_bench.py <packet_size> <duration_sec>
  packet_size: 64 | imix | 1500
  duration_sec: integer

Output: single JSON line with tx/rx stats. Sends on port 0; RX side
captures the same port — useful when DUT runs a tx_reflect XDP program
that bounces packets back.
"""
import sys, time, json
sys.path.insert(0, "/opt/trex/v3.08/scripts/automation/trex_control_plane/interactive")
from trex.stl.api import *

SRC_MAC = "40:a6:b7:82:cd:d8"
DST_MAC = "40:a6:b7:95:a2:d0"
SRC_IP  = "10.99.0.2"
DST_IP  = "10.99.0.1"


def build_streams(pkt_label: str):
    vm = STLScVmRaw([
        STLVmFlowVar(name="sip", min_value=0x08000001, max_value=0x08FFFFFF, size=4, op="random"),
        STLVmWrFlowVar(fv_name="sip", pkt_offset=26),
        STLVmFlowVar(name="sp", min_value=1024, max_value=60000, size=2, op="random"),
        STLVmWrFlowVar(fv_name="sp", pkt_offset=34),
        STLVmFixIpv4(offset="IP"),
    ])
    base = Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=SRC_IP, dst=DST_IP) / UDP(sport=12345, dport=9)

    if pkt_label == "64":
        pkt = base / ("X" * 18)
        return [STLStream(packet=STLPktBuilder(pkt=pkt, vm=vm), mode=STLTXCont(pps=200e6))]
    if pkt_label == "1500":
        pkt = base / ("X" * 1458)
        return [STLStream(packet=STLPktBuilder(pkt=pkt, vm=vm), mode=STLTXCont(pps=200e6))]
    if pkt_label == "imix":
        return [
            STLStream(packet=STLPktBuilder(pkt=base / ("X" * 18), vm=vm),
                      mode=STLTXCont(pps=200e6 * 7 / 12)),
            STLStream(packet=STLPktBuilder(pkt=base / ("X" * 552), vm=vm),
                      mode=STLTXCont(pps=200e6 * 4 / 12)),
            STLStream(packet=STLPktBuilder(pkt=base / ("X" * 1458), vm=vm),
                      mode=STLTXCont(pps=200e6 * 1 / 12)),
        ]
    raise ValueError(f"unknown packet size: {pkt_label}")


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    pkt_label = sys.argv[1].lower()
    duration = int(sys.argv[2])

    c = STLClient(server="127.0.0.1")
    c.connect()
    c.acquire(ports=[0], force=True)
    c.reset(ports=[0])
    c.add_streams(build_streams(pkt_label), ports=[0])
    c.clear_stats()
    c.start(ports=[0], mult="100%")
    time.sleep(duration)
    c.stop(ports=[0])
    s = c.get_stats()[0]

    opackets = s.get("opackets", 0)
    ipackets = s.get("ipackets", 0)
    print(json.dumps({
        "tx_pps":      round(s.get("tx_pps", 0), 0),
        "tx_bps_Gbps": round(s.get("tx_bps", 0) / 1e9, 3),
        "opackets":    opackets,
        "oerrors":     s.get("oerrors", 0),
        "rx_pps":      round(s.get("rx_pps", 0), 0),
        "rx_bps_Gbps": round(s.get("rx_bps", 0) / 1e9, 3),
        "ipackets":    ipackets,
        "ierrors":     s.get("ierrors", 0),
        # Average rates over full duration (cleaner than the last
        # snapshot's tx_pps / rx_pps which fluctuate).
        "avg_tx_mpps": round(opackets / duration / 1e6, 3),
        "avg_rx_mpps": round(ipackets / duration / 1e6, 3),
    }))
    c.release(ports=[0])
    c.disconnect()


if __name__ == "__main__":
    main()
