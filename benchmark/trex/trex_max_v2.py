"""Fixed: no wait_on_traffic, just sleep + stats."""
import sys, time, json
sys.path.insert(0, "/tmp/trex-core/scripts/automation/trex_control_plane/interactive")
from trex.stl.api import *

c = STLClient(server="127.0.0.1")
c.connect()
c.acquire(ports=[0], force=True)
c.reset(ports=[0])

vm = STLScVmRaw([
    STLVmFlowVar(name="sp", min_value=1024, max_value=60000, size=2, op="random"),
    STLVmWrFlowVar(fv_name="sp", pkt_offset=34),
])
pkt = (Ether(src="40:a6:b7:82:cd:d8", dst="40:a6:b7:95:a2:d0")/
       IP(src="10.99.0.2", dst="10.99.0.1")/
       UDP(sport=12345, dport=9)/("X"*18))

streams = [STLStream(packet=STLPktBuilder(pkt=pkt, vm=vm), mode=STLTXCont(pps=200e6))]
c.add_streams(streams, ports=[0])
c.clear_stats()
c.start(ports=[0], mult="100%")
time.sleep(5)
c.stop(ports=[0])
s = c.get_stats()[0]
print(json.dumps({
    "tx_pps": s.get("tx_pps", 0),
    "tx_bps_Gbps": round(s.get("tx_bps", 0) / 1e9, 3),
    "opackets": s.get("opackets", 0),
    "oerrors": s.get("oerrors", 0),
}, indent=2))
c.release(ports=[0])
c.disconnect()
