"""B3 macrobench T-Rex multi-source driver v2.
Variant of /tmp/trex_b3_run.py that uses explicit time.sleep + c.stop()
(trex's `duration` arg is unreliable in software mode — observed 30s
specified, ~156s actual).

Spreads TCP src port over 1024..65535 random so DUT NIC RSS (4-tuple
hash) hits multiple RX queues. Used to exercise per-CPU sharded
ringbuf in xdp-ninja vs single AF_PACKET socket in tcpdump.

Run from the Generator host (ssh ocxma-trex):
  scp scripts/trex/trex_b3_multi_v2.py ocxma-trex:/tmp/
  ssh ocxma-trex 'python3 /tmp/trex_b3_multi_v2.py 100 30'

Usage: python3 trex_b3_multi_v2.py <match_pct> <duration_s>
"""
import sys, time, json
sys.path.insert(0, "/opt/trex/v3.06/automation/trex_control_plane/interactive")
from trex.stl.api import *

match_pct = int(sys.argv[1]) if len(sys.argv) > 1 else 100
duration_s = int(sys.argv[2]) if len(sys.argv) > 2 else 30
target_mpps = 22

c = STLClient(server="127.0.0.1")
result = {"match_pct": match_pct, "duration_s": duration_s, "mode": "multi-source"}
try:
    c.connect()
    c.acquire(ports=[0], force=True)
    c.reset(ports=[0])

    vm = STLScVmRaw([
        STLVmFlowVar(name="srcp", min_value=1024, max_value=65535,
                     size=2, op="random"),
        STLVmWrFlowVar(fv_name="srcp", pkt_offset=34),
    ])

    pkt_a = (Ether(src="40:a6:b7:82:cd:d8", dst="40:a6:b7:95:a2:d0")/
             IP(src="10.99.0.2", dst="10.99.0.1")/
             TCP(sport=12345, dport=443, flags="S")/("X"*22))
    pkt_b = (Ether(src="40:a6:b7:82:cd:d8", dst="40:a6:b7:95:a2:d0")/
             IP(src="10.99.0.2", dst="10.99.0.1")/
             TCP(sport=12345, dport=80, flags="S")/("X"*22))

    if match_pct == 100:
        streams = [STLStream(packet=STLPktBuilder(pkt=pkt_a, vm=vm),
                             mode=STLTXCont(pps=target_mpps*1e6))]
    else:
        match_pps = target_mpps * 1e6 * match_pct / 100.0
        nomatch_pps = target_mpps * 1e6 * (100 - match_pct) / 100.0
        streams = [
            STLStream(packet=STLPktBuilder(pkt=pkt_a, vm=vm),
                      mode=STLTXCont(pps=match_pps)),
            STLStream(packet=STLPktBuilder(pkt=pkt_b, vm=vm),
                      mode=STLTXCont(pps=nomatch_pps)),
        ]
    c.add_streams(streams, ports=[0])
    c.clear_stats()
    c.start(ports=[0], mult="100%")
    t0 = time.time()
    time.sleep(duration_s)
    c.stop(ports=[0])
    elapsed = time.time() - t0
    s = c.get_stats()[0]
    result["opackets"] = s.get("opackets", 0)
    result["oerrors"] = s.get("oerrors", 0)
    result["tx_pps"] = s.get("tx_pps", 0)
    result["tx_bps"] = s.get("tx_bps", 0)
    result["elapsed_s"] = elapsed
    result["status"] = "ok"
except Exception as e:
    result["status"] = "err"
    result["err"] = str(e)
finally:
    try: c.release(ports=[0])
    except: pass
    try: c.disconnect()
    except: pass
print(json.dumps(result))
