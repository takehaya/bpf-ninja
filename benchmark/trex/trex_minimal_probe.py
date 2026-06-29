"""Minimal trex probe — start at 1 Mpps to see if hardware TX works at all.
If this works, we incrementally raise. If not, hardware-mode TX is broken on
our single-port config."""
import sys, time, json
sys.path.insert(0, "/opt/trex/v3.06/automation/trex_control_plane/interactive")
from trex.stl.api import *

c = STLClient(server="127.0.0.1")
c.connect()
c.acquire(ports=[0], force=True)
c.reset(ports=[0])

pkt = (Ether(src="40:a6:b7:82:cd:d8", dst="40:a6:b7:95:a2:d0")/
       IP(src="10.99.0.2", dst="10.99.0.1")/
       TCP(sport=12345, dport=443, flags="S")/("X"*22))

# Try low rate first
streams = [STLStream(packet=STLPktBuilder(pkt=pkt), mode=STLTXCont(pps=1e6))]
c.add_streams(streams, ports=[0])
c.clear_stats()
c.start(ports=[0], mult="100%")
time.sleep(3)
c.stop(ports=[0])
s = c.get_stats()[0]
print(json.dumps({
    "requested_pps": 1e6,
    "tx_pps": s.get("tx_pps", 0),
    "opackets": s.get("opackets", 0),
    "oerrors": s.get("oerrors", 0),
}))
c.release(ports=[0])
c.disconnect()
