import Kunai.Vectors.AuxHeaders

/-!
# Protocol vectors: PFCP, SCTP, ARP, NSH, ERSPAN, IGMP

Presence, field comparisons, and truncation for each protocol added to the
bundled vocabulary after the first seventeen (DECISIONS.md D-040 onwards).
-/
namespace Kunai
open Pkt

set_option maxRecDepth 16384

/-- A field path written out part by part (`pfcp.sess.seid`). -/
def fp (parts : List String) : FieldPath := FieldPath.ofParts parts
def fa (parts : List String) : Arith := .field (fp parts)

-- PFCP (D-040) ---------------------------------------------------------------

/-- PFCP common header, version 1; `s` selects the session form. -/
def pfcpHdr (s : Nat) (msgType : Nat) (mp : Nat := 0) (length : Nat := 12) : Packet :=
  [UInt8.ofNat (0x20 + mp * 2 + s), UInt8.ofNat msgType] ++ be 2 length
def pfcpNode (seq : Nat) : Packet := be 3 seq ++ [0]
def pfcpSess (seid seq : Nat) (prio : Nat := 0) : Packet := be 8 seid ++ be 3 seq ++ [UInt8.ofNat (prio * 16)]
def pfcpPkt (pfcp : Packet) (dport : Nat := 8805) : Packet :=
  eth 0x0800 ++ ipv4 17 ++ udp 8805 dport ++ pfcp
/-- Heartbeat Request (type 1), node form. -/
def pfcpHeartbeat : Packet := pfcpPkt (pfcpHdr 0 1 (length := 4) ++ pfcpNode 7)
/-- Session Establishment Request (type 50), session form, priority 3. -/
def pfcpEstab : Packet := pfcpPkt (pfcpHdr 1 50 (mp := 1) ++ pfcpSess 0x1122334455667788 9 (prio := 3))
def pfcpL : List Layer := [P "eth", P "ipv4", P "udp", P "pfcp"]
def pfcpW (w : Where) : Filter := { layers := pfcpL, cond := some w }
def pfcpSeid := fa ["pfcp", "sess", "seid"]

vector pfcpNodePresent := {
  id := "pfcp-node", ast := { layers := pfcpL }, packet := pfcpHeartbeat, expected := .accept [] }
vector pfcpSessPresent := {
  id := "pfcp-sess", ast := { layers := pfcpL }, packet := pfcpEstab, expected := .accept [] }
vector pfcpIPv6 := {
  id := "pfcp-ipv6", ast := { layers := [P "eth", P "ipv6", P "udp", P "pfcp"] },
  packet := eth 0x86DD ++ ipv6 17 ++ udp 8805 8805 ++ pfcpHdr 0 1 (length := 4) ++ pfcpNode 7, expected := .accept [] }
vector pfcpPortMiss := {
  id := "pfcp-port-miss", ast := { layers := pfcpL }, packet := pfcpPkt (pfcpHdr 0 1 ++ pfcpNode 7) (dport := 8806),
  expected := .reject, note := "udp.dport 8806 is not KUNAI_PFCP_UDP_DPORT" }
vector pfcpMsgType := {
  id := "pfcp-pred-msg-type", ast := { layers := [P "eth", P "ipv4", P "udp", .proto { name := "pfcp", preds := [.cmp (f "msg_type") .eq (.int 50)] }] },
  packet := pfcpEstab, expected := .accept [] }
vector pfcpMsgTypeMiss := {
  id := "pfcp-pred-msg-type-miss", ast := { layers := [P "eth", P "ipv4", P "udp", .proto { name := "pfcp", preds := [.cmp (f "msg_type") .eq (.int 50)] }] },
  packet := pfcpHeartbeat, expected := .reject }
vector pfcpFlags := {
  id := "pfcp-where-flags", ast := pfcpW (.and (cmp (fa ["pfcp", "version"]) .eq (k 1)) (.and (cmp (fa ["pfcp", "s"]) .eq (k 1)) (cmp (fa ["pfcp", "mp"]) .eq (k 1)))),
  packet := pfcpEstab, expected := .accept [] }
vector pfcpSeidHit := {
  id := "pfcp-sess-seid", ast := pfcpW (cmp pfcpSeid .eq (k 0x1122334455667788)), packet := pfcpEstab, expected := .accept [],
  note := "a 64-bit aux field" }
vector pfcpSeidMiss := {
  id := "pfcp-sess-seid-miss", ast := pfcpW (cmp pfcpSeid .eq (k 0x1122334455667789)), packet := pfcpEstab, expected := .reject }
vector pfcpSeidAbsent := {
  id := "pfcp-sess-seid-absent", ast := pfcpW (cmp pfcpSeid .ne (k 0)), packet := pfcpHeartbeat, expected := .reject,
  note := "D-003/D-027: s = 0, the session tail is not extracted and every comparison on it is false" }
vector pfcpSeidAbsentNot := {
  id := "pfcp-sess-seid-absent-not", ast := pfcpW (.not (cmp pfcpSeid .eq (k 0))), packet := pfcpHeartbeat, expected := .accept [] }
vector pfcpSessExists := {
  id := "pfcp-sess-exists", ast := pfcpW (.fieldExists (fp ["pfcp", "sess"])), packet := pfcpEstab, expected := .accept [] }
vector pfcpSessExistsAbsent := {
  id := "pfcp-sess-exists-absent", ast := pfcpW (.fieldExists (fp ["pfcp", "sess"])), packet := pfcpHeartbeat, expected := .reject }
vector pfcpNodeExistsAbsent := {
  id := "pfcp-node-exists-absent", ast := pfcpW (.fieldExists (fp ["pfcp", "node"])), packet := pfcpEstab, expected := .reject,
  note := "the two tails exclude each other" }
vector pfcpPriority := {
  id := "pfcp-sess-priority", ast := pfcpW (cmp (fa ["pfcp", "sess", "priority"]) .eq (k 3)), packet := pfcpEstab, expected := .accept [],
  note := "a 4-bit aux field" }
vector pfcpBracketSeid := {
  id := "pfcp-pred-sess-seid", ast := { layers := [P "eth", P "ipv4", P "udp", .proto { name := "pfcp", preds := [.cmp (fp ["sess", "seid"]) .eq (.int 0x1122334455667788)] }] },
  packet := pfcpEstab, expected := .accept [] }
vector pfcpBracketSeidAbsent := {
  id := "pfcp-pred-sess-seid-absent", ast := { layers := [P "eth", P "ipv4", P "udp", .proto { name := "pfcp", preds := [.cmp (fp ["sess", "seid"]) .ne (.int 0)] }] },
  packet := pfcpHeartbeat, expected := .reject, note := "a bracket on an absent aux is false (D-003)" }
vector pfcpNodeSeq := {
  id := "pfcp-node-seq", ast := pfcpW (cmp (fa ["pfcp", "node", "seq"]) .eq (k 7)), packet := pfcpHeartbeat, expected := .accept [],
  goStatus := .notImplemented, note := "D-040: Go reads no 3-byte aux field" }
vector pfcpSessSeq := {
  id := "pfcp-sess-seq", ast := pfcpW (cmp (fa ["pfcp", "sess", "seq"]) .eq (k 9)), packet := pfcpEstab, expected := .accept [],
  goStatus := .notImplemented, note := "D-040: Go reads no 3-byte aux field" }
vector pfcpTruncCommon := {
  id := "pfcp-truncated-common", ast := { layers := pfcpL }, packet := pfcpHeartbeat.take 45, expected := .reject,
  note := "3 of the 4 common bytes" }
vector pfcpNodeExact := {
  id := "pfcp-node-exact-fit", ast := { layers := pfcpL }, packet := pfcpHeartbeat, expected := .accept [],
  note := "the packet ends with the node tail" }
vector pfcpTruncNode := {
  id := "pfcp-truncated-node", ast := { layers := pfcpL }, packet := pfcpHeartbeat.take 49, expected := .reject,
  note := "the node tail is cut: s = 0 commits to it" }
vector pfcpTruncSess := {
  id := "pfcp-truncated-sess", ast := { layers := pfcpL }, packet := pfcpEstab.take 54, expected := .reject,
  note := "s = 1 needs 12 tail bytes, 8 present (enough for the node form)" }

def pfcpVectors : List Vector := [
  pfcpNodePresent, pfcpSessPresent, pfcpIPv6, pfcpPortMiss, pfcpMsgType, pfcpMsgTypeMiss, pfcpFlags,
  pfcpSeidHit, pfcpSeidMiss, pfcpSeidAbsent, pfcpSeidAbsentNot, pfcpSessExists, pfcpSessExistsAbsent, pfcpNodeExistsAbsent,
  pfcpPriority, pfcpBracketSeid, pfcpBracketSeidAbsent, pfcpNodeSeq, pfcpSessSeq,
  pfcpTruncCommon, pfcpNodeExact, pfcpTruncNode, pfcpTruncSess]

-- SCTP (D-041) ---------------------------------------------------------------

def sctpHdr (sport dport : Nat) (vtag : Nat := 0) : Packet := be 2 sport ++ be 2 dport ++ be 4 vtag ++ be 4 0
def sctpChunk (type : Nat) (length : Nat) (flags : Nat := 0) : Packet := [UInt8.ofNat type, UInt8.ofNat flags] ++ be 2 length
/-- INIT (type 1, 20 bytes) from 5000 to the NGAP port 38412, verification tag 0. -/
def sctpInit : Packet := sctpHdr 5000 38412 ++ sctpChunk 1 20 ++ be 4 0x01020304 ++ be 4 65536 ++ be 2 10 ++ be 2 10 ++ be 4 1
/-- DATA (type 0, flags B|E) on an established association. -/
def sctpData : Packet := sctpHdr 5000 38412 (vtag := 0xdeadbeef) ++ sctpChunk 0 20 (flags := 3) ++ be 4 1 ++ be 2 0 ++ be 2 0 ++ be 4 60 ++ payload 4
def sctpPkt (sctp : Packet) : Packet := eth 0x0800 ++ ipv4 132 ++ sctp
def sctpL : List Layer := [P "eth", P "ipv4", P "sctp"]
def sctpW (w : Where) : Filter := { layers := sctpL, cond := some w }
def sctpPred (p : Predicate) : Filter := { layers := [P "eth", P "ipv4", .proto { name := "sctp", preds := [p] }] }
def sctpChunkType := fa ["sctp", "chunk", "type"]

vector sctpInitPresent := {
  id := "sctp-init", ast := { layers := sctpL }, packet := sctpPkt sctpInit, expected := .accept [] }
vector sctpIPv6 := {
  id := "sctp-ipv6", ast := { layers := [P "eth", P "ipv6", P "sctp"] }, packet := eth 0x86DD ++ ipv6 132 ++ sctpData, expected := .accept [] }
vector sctpSrv6 := {
  id := "sctp-srv6", ast := { layers := [P "eth", P "ipv6", P "srv6", P "sctp"] },
  packet := eth 0x86DD ++ ipv6 43 ++ srv6Hdr 132 0 ++ be 16 0xfc000000000000000000000000000003 ++ sctpData, expected := .accept [],
  note := "KUNAI_SCTP_SRV6_NEXT_HEADER" }
vector sctpProtoMiss := {
  id := "sctp-proto-miss", ast := { layers := sctpL }, packet := eth 0x0800 ++ ipv4 17 ++ sctpInit, expected := .reject,
  note := "ipv4.protocol 17 is udp" }
vector sctpNotTcp := {
  id := "sctp-not-tcp", ast := { layers := chain3 }, packet := sctpPkt sctpInit, expected := .reject }
vector sctpDport := {
  id := "sctp-pred-dport", ast := sctpPred (.cmp (f "dport") .eq (.int 38412)), packet := sctpPkt sctpInit, expected := .accept [] }
vector sctpDportMiss := {
  id := "sctp-pred-dport-miss", ast := sctpPred (.cmp (f "dport") .eq (.int 36412)), packet := sctpPkt sctpInit, expected := .reject }
vector sctpVtag := {
  id := "sctp-where-vtag", ast := sctpW (cmp (fa ["sctp", "vtag"]) .eq (k 0xdeadbeef)), packet := sctpPkt sctpData, expected := .accept [] }
vector sctpVtagMiss := {
  id := "sctp-where-vtag-miss", ast := sctpW (cmp (fa ["sctp", "vtag"]) .eq (k 0xdeadbeef)), packet := sctpPkt sctpInit, expected := .reject,
  note := "INIT carries verification tag 0" }
vector sctpChunkInit := {
  id := "sctp-chunk-type", ast := sctpW (cmp sctpChunkType .eq (k 1)), packet := sctpPkt sctpInit, expected := .accept [] }
vector sctpChunkInitMiss := {
  id := "sctp-chunk-type-miss", ast := sctpW (cmp sctpChunkType .eq (k 1)), packet := sctpPkt sctpData, expected := .reject }
vector sctpChunkFlags := {
  id := "sctp-chunk-flags-length", ast := sctpW (.and (cmp (fa ["sctp", "chunk", "flags"]) .eq (k 3)) (cmp (fa ["sctp", "chunk", "length"]) .ge (k 20))),
  packet := sctpPkt sctpData, expected := .accept [] }
vector sctpChunkBracket := {
  id := "sctp-pred-chunk-type", ast := sctpPred (.cmp (fp ["chunk", "type"]) .eq (.int 0)), packet := sctpPkt sctpData, expected := .accept [] }
vector sctpChunkBracketMiss := {
  id := "sctp-pred-chunk-type-miss", ast := sctpPred (.cmp (fp ["chunk", "type"]) .eq (.int 0)), packet := sctpPkt sctpInit, expected := .reject }
vector sctpChunkExists := {
  id := "sctp-chunk-exists", ast := sctpW (.fieldExists (fp ["sctp", "chunk"])), packet := sctpPkt sctpInit, expected := .accept [],
  note := "the first chunk header is extracted unconditionally" }
vector sctpTruncCommon := {
  id := "sctp-truncated-common", ast := { layers := sctpL }, packet := (sctpPkt sctpInit).take 40, expected := .reject,
  note := "6 of the 12 common-header bytes" }
vector sctpNoChunk := {
  id := "sctp-no-chunk", ast := { layers := sctpL }, packet := (sctpPkt sctpInit).take 46, expected := .reject,
  note := "D-041: the common header alone is not an SCTP packet" }
vector sctpTruncChunk := {
  id := "sctp-truncated-chunk", ast := { layers := sctpL }, packet := (sctpPkt sctpInit).take 48, expected := .reject }
vector sctpChunkExact := {
  id := "sctp-chunk-exact-fit", ast := sctpW (cmp sctpChunkType .eq (k 1)), packet := (sctpPkt sctpInit).take 50, expected := .accept [],
  note := "the chunk value is not read" }

def sctpVectors : List Vector := [
  sctpInitPresent, sctpIPv6, sctpSrv6, sctpProtoMiss, sctpNotTcp, sctpDport, sctpDportMiss, sctpVtag, sctpVtagMiss,
  sctpChunkInit, sctpChunkInitMiss, sctpChunkFlags, sctpChunkBracket, sctpChunkBracketMiss, sctpChunkExists,
  sctpTruncCommon, sctpNoChunk, sctpTruncChunk, sctpChunkExact]

-- ARP (D-042) ----------------------------------------------------------------

/-- ARP for IPv4; a request by default (who has 10.0.0.2, tell 10.0.0.1). -/
def arpHdr (oper : Nat := 1) (htype : Nat := 1) (ptype : Nat := 0x0800) (hlen : Nat := 6) (plen : Nat := 4)
    (sha : Nat := 0x66778899aabb) (spa : Nat := 0x0a000001) (tha : Nat := 0) (tpa : Nat := 0x0a000002) : Packet :=
  be 2 htype ++ be 2 ptype ++ be 1 hlen ++ be 1 plen ++ be 2 oper ++ be 6 sha ++ be 4 spa ++ be 6 tha ++ be 4 tpa
/-- Broadcast frame padded to the 60-byte Ethernet minimum. -/
def arpPkt (arp : Packet := arpHdr) : Packet := eth 0x0806 (dst := 0xffffffffffff) ++ arp ++ List.replicate 18 0
def arpL : List Layer := [P "eth", P "arp"]
def arpW (w : Where) : Filter := { layers := arpL, cond := some w }
def arpPred (p : Predicate) : Filter := { layers := [P "eth", .proto { name := "arp", preds := [p] }] }

vector arpRequest := {
  id := "arp-request", ast := { layers := arpL }, packet := arpPkt, expected := .accept [] }
vector arpVlan := {
  id := "arp-vlan", ast := { layers := [P "eth", P "vlan", P "arp"] },
  packet := eth 0x8100 ++ vlan 100 0x0806 ++ arpHdr, expected := .accept [] }
vector arpQinq := {
  id := "arp-qinq", ast := { layers := [P "eth", P "qinq", P "vlan", P "arp"] },
  packet := eth 0x88A8 ++ vlan 200 0x8100 ++ vlan 100 0x0806 ++ arpHdr, expected := .accept [] }
vector arpOptVlanAbsent := {
  id := "arp-opt-vlan-absent", ast := { layers := [P "eth", Pq "vlan" .opt, P "arp"] }, packet := arpPkt, expected := .accept [] }
vector arpOptVlanPresent := {
  id := "arp-opt-vlan-present", ast := { layers := [P "eth", Pq "vlan" .opt, P "arp"] },
  packet := eth 0x8100 ++ vlan 100 0x0806 ++ arpHdr, expected := .accept [] }
vector arpAlt := {
  id := "arp-alt-second", ast := { layers := [P "eth", .alt [{ name := "ipv4" }, { name := "arp" }]] }, packet := arpPkt, expected := .accept [] }
vector arpEthertypeMiss := {
  id := "arp-ethertype-miss", ast := { layers := arpL }, packet := eth 0x0800 ++ arpHdr,
  expected := .reject, note := "a valid ARP header behind eth.ethertype 0x0800 isolates the dispatch check" }
vector arpNotIPv4 := {
  id := "arp-not-ipv4", ast := { layers := chain3 }, packet := arpPkt, expected := .reject }
vector arpOper := {
  id := "arp-pred-oper", ast := arpPred (.cmp (f "oper") .eq (.int 1)), packet := arpPkt, expected := .accept [] }
vector arpOperMiss := {
  id := "arp-pred-oper-miss", ast := arpPred (.cmp (f "oper") .eq (.int 2)), packet := arpPkt, expected := .reject }
vector arpTpaBracket := {
  id := "arp-pred-tpa", ast := arpPred (.cmp (f "tpa") .eq (.ipv4 0x0a000002)), packet := arpPkt, expected := .accept [] }
vector arpSpa := {
  id := "arp-where-spa", ast := arpW (.litCmp (ff "arp" "spa") .eq (.ipv4 0x0a000001)), packet := arpPkt, expected := .accept [] }
vector arpTpaCidr := {
  id := "arp-where-tpa-cidr", ast := arpW (.litCmp (ff "arp" "tpa") .eq (.cidr4 0x0a000000 24)), packet := arpPkt, expected := .accept [] }
vector arpTpaCidrMiss := {
  id := "arp-where-tpa-cidr-miss", ast := arpW (.litCmp (ff "arp" "tpa") .eq (.cidr4 0xc0a80000 16)), packet := arpPkt, expected := .reject }
vector arpSha := {
  id := "arp-where-sha", ast := arpW (.litCmp (ff "arp" "sha") .eq (.mac 0x66778899aabb)), packet := arpPkt, expected := .accept [] }
vector arpThaInt := {
  id := "arp-where-tha-int", ast := arpW (cmp (fld "arp" "tha") .eq (k 0)), packet := arpPkt, expected := .accept [],
  goStatus := .notImplemented, note := "D-042: Go compares no 6-byte field with an integer (a MAC literal works)" }
vector arpReply := {
  id := "arp-where-reply", ast := arpW (.and (cmp (fld "arp" "oper") .eq (k 2)) (.litCmp (ff "arp" "tha") .eq (.mac 0x66778899aabb))),
  packet := arpPkt (arpHdr (oper := 2) (sha := 0x020000000001) (spa := 0x0a000002) (tha := 0x66778899aabb) (tpa := 0x0a000001)),
  expected := .accept [] }
vector arpPtype := {
  id := "arp-pred-ptype", ast := arpPred (.cmp (f "ptype") .eq (.int 0x0800)), packet := arpPkt, expected := .accept [] }
vector arpPtypeOther := {
  id := "arp-pred-ptype-other", ast := arpPred (.cmp (f "ptype") .eq (.int 0x0800)), packet := arpPkt (arpHdr (ptype := 0x0801)),
  expected := .reject, note := "D-042: ptype is not validated, so arp is present and the predicate fails" }
vector arpPtypeOtherChain := {
  id := "arp-ptype-not-validated", ast := { layers := arpL }, packet := arpPkt (arpHdr (ptype := 0x0801)), expected := .accept [],
  note := "D-042: the layout does not depend on ptype" }
vector arpHtypeIeee := {
  id := "arp-htype-ieee802", ast := { layers := arpL }, packet := arpPkt (arpHdr (htype := 6)), expected := .accept [],
  note := "D-042: htype is not validated" }
vector arpHlenBad := {
  id := "arp-hlen-reject", ast := { layers := arpL }, packet := arpPkt (arpHdr (hlen := 8)), expected := .reject,
  note := "D-042/D-017: hlen 6 is required; the ethertype named arp, so this is broken, not absent" }
vector arpPlenBad := {
  id := "arp-plen-reject", ast := { layers := arpL }, packet := arpPkt (arpHdr (plen := 16)), expected := .reject }
vector arpOptBroken := {
  id := "arp-opt-broken", ast := { layers := [P "eth", Pq "arp" .opt] }, packet := arpPkt (arpHdr (hlen := 8)), expected := .reject,
  note := "D-017 (c): the parent constant names arp, a failed self-validation rejects instead of skipping" }
vector arpUnderMpls := {
  id := "arp-under-mpls-selfvalidating", ast := { layers := [P "eth", P "mpls", P "arp"] },
  packet := eth 0x8847 ++ mpls 5 1 ++ arpHdr, expected := .accept [],
  note := "D-042: the hlen/plen check makes arp self-validating, so like ipv4 it may follow a parent without an edge" }
vector arpUnderMplsBroken := {
  id := "arp-under-mpls-selfvalidating-miss", ast := { layers := [P "eth", P "mpls", P "arp"] },
  packet := mpls1, expected := .reject, note := "the ipv4 header after the label is not hlen 6 / plen 4" }
vector arpExact := {
  id := "arp-exact-fit", ast := { layers := arpL }, packet := eth 0x0806 ++ arpHdr, expected := .accept [] }
vector arpTrunc := {
  id := "arp-truncated", ast := { layers := arpL }, packet := (eth 0x0806 ++ arpHdr).take 41, expected := .reject,
  note := "27 of 28 bytes" }
vector arpTruncBeforeLens := {
  id := "arp-truncated-before-lengths", ast := { layers := arpL }, packet := (eth 0x0806 ++ arpHdr).take 18, expected := .reject }

def arpVectors : List Vector := [
  arpRequest, arpVlan, arpQinq, arpOptVlanAbsent, arpOptVlanPresent, arpAlt, arpEthertypeMiss, arpNotIPv4,
  arpOper, arpOperMiss, arpTpaBracket, arpSpa, arpTpaCidr, arpTpaCidrMiss, arpSha, arpThaInt, arpReply,
  arpPtype, arpPtypeOther, arpPtypeOtherChain, arpHtypeIeee, arpHlenBad, arpPlenBad, arpOptBroken,
  arpUnderMpls, arpUnderMplsBroken, arpExact, arpTrunc, arpTruncBeforeLens]

-- NSH (D-043) ----------------------------------------------------------------

/-- NSH base + service path header; `length` in 4-byte words. -/
def nshHdr (mdType nextProto length : Nat) (spi : Nat := 100) (si : Nat := 255) (ttl : Nat := 63) : Packet :=
  [UInt8.ofNat (ttl / 4), UInt8.ofNat ((ttl % 4) * 64 + length), UInt8.ofNat mdType, UInt8.ofNat nextProto] ++ be 3 spi ++ [UInt8.ofNat si]
def nshMd1 (nextProto : Nat) : Packet := nshHdr 1 nextProto 6 ++ be 4 1 ++ be 4 2 ++ be 4 3 ++ be 4 4
/-- MD type 2 with one 4-byte TLV (class 0, type 1, length 4). -/
def nshMd2 (nextProto : Nat) (length : Nat := 4) : Packet := nshHdr 2 nextProto length ++ be 2 0 ++ [1, 4] ++ be 4 0xcafe
def nshInner : Packet := ipv4 6 ++ tcp 12345 80 ++ payload 5
def nshPkt (nsh : Packet) (inner : Packet := nshInner) : Packet := eth 0x894F ++ nsh ++ inner
def nshL : List Layer := [P "eth", P "nsh", P "ipv4", P "tcp"]
def nshW (w : Where) : Filter := { layers := nshL, cond := some w }
def nshPred (p : Predicate) : Filter := { layers := [P "eth", .proto { name := "nsh", preds := [p] }, P "ipv4", P "tcp"] }
def nshCtx1 := fa ["nsh", "md1", "ctx1"]

vector nshMd1Chain := {
  id := "nsh-md1", ast := nshW (cmp dport .eq (k 80)), packet := nshPkt (nshMd1 1), expected := .accept [] }
vector nshMd2Chain := {
  id := "nsh-md2", ast := nshW (cmp dport .eq (k 80)), packet := nshPkt (nshMd2 1), expected := .accept [],
  note := "length 4 skips the 8 bytes of TLVs" }
vector nshMd2Empty := {
  id := "nsh-md2-no-context", ast := { layers := nshL }, packet := nshPkt (nshHdr 2 1 2), expected := .accept [] }
vector nshTerminal := {
  id := "nsh-terminal", ast := { layers := [P "eth", P "nsh"] }, packet := nshPkt (nshMd1 1), expected := .accept [] }
vector nshIPv6 := {
  id := "nsh-ipv6", ast := { layers := [P "eth", P "nsh", P "ipv6", P "tcp"] },
  packet := nshPkt (nshMd1 2) (ipv6 6 ++ tcp 12345 80 ++ payload 5), expected := .accept [] }
vector nshEth := {
  id := "nsh-eth", ast := { layers := [P "eth", P "nsh", P "eth", P "ipv4", P "tcp"] },
  packet := nshPkt (nshMd2 3) (eth 0x0800 ++ nshInner), expected := .accept [] }
vector nshMpls := {
  id := "nsh-mpls", ast := { layers := [P "eth", P "nsh", P "mpls", P "ipv4", P "tcp"] },
  packet := nshPkt (nshMd1 5) (mpls 16 1 ++ nshInner), expected := .accept [] }
vector nshNextProtoMiss := {
  id := "nsh-next-proto-miss", ast := { layers := [P "eth", P "nsh", P "ipv6", P "tcp"] },
  packet := nshPkt (nshMd1 1) (ipv6 6 ++ tcp 12345 80 ++ payload 5), expected := .reject,
  note := "a valid IPv6 payload behind next_proto 1 isolates the dispatch check" }
vector nshVlan := {
  id := "nsh-vlan", ast := { layers := [P "eth", P "vlan", P "nsh", P "ipv4", P "tcp"] },
  packet := eth 0x8100 ++ vlan 100 0x894F ++ nshMd1 1 ++ nshInner, expected := .accept [] }
vector nshGre := {
  id := "nsh-gre", ast := { layers := [P "eth", P "ipv4", P "gre", P "nsh", P "ipv4", P "tcp"] },
  packet := eth 0x0800 ++ ipv4 47 ++ be 2 0 ++ be 2 0x894F ++ nshMd1 1 ++ nshInner, expected := .accept [] }
vector nshOptAbsent := {
  id := "nsh-opt-absent", ast := { layers := [P "eth", Pq "nsh" .opt, P "ipv4", P "tcp"] }, expected := .accept [] }
vector nshOptPresent := {
  id := "nsh-opt-present", ast := { layers := [P "eth", Pq "nsh" .opt, P "ipv4", P "tcp"] }, packet := nshPkt (nshMd2 1), expected := .accept [] }
vector nshMdTypeBad := {
  id := "nsh-md-type-reject", ast := { layers := nshL }, packet := nshPkt (nshHdr 0 1 2), expected := .reject,
  note := "D-043: MD types other than 1 and 2 reject" }
vector nshMdTypeExperimental := {
  id := "nsh-md-type-15-reject", ast := { layers := nshL }, packet := nshPkt (nshHdr 15 1 2), expected := .reject }
vector nshMd2LengthShort := {
  id := "nsh-md2-length-below-2", ast := { layers := nshL }, packet := nshPkt (nshHdr 2 1 1), expected := .reject,
  note := "length counts the 8-byte base and service path headers" }
vector nshMd2LengthWrong := {
  id := "nsh-md2-length-short-of-tlvs", ast := { layers := nshL }, packet := nshPkt (nshMd2 1 (length := 3)), expected := .reject,
  note := "the cursor lands inside the TLV and the ipv4 self-validation fails" }
vector nshMd2LengthOverrun := {
  id := "nsh-md2-length-past-end", ast := { layers := [P "eth", P "nsh"] }, packet := nshPkt (nshMd2 1 (length := 63)), expected := .reject,
  note := "252 declared bytes do not fit" }
vector nshSi := {
  id := "nsh-pred-si", ast := nshPred (.cmp (f "si") .eq (.int 255)), packet := nshPkt (nshMd1 1), expected := .accept [] }
vector nshSiMiss := {
  id := "nsh-pred-si-miss", ast := nshPred (.cmp (f "si") .eq (.int 254)), packet := nshPkt (nshMd1 1), expected := .reject }
vector nshTtl := {
  id := "nsh-where-ttl", ast := nshW (.and (cmp (fld "nsh" "ttl") .eq (k 63)) (cmp (fld "nsh" "length") .eq (k 6))),
  packet := nshPkt (nshMd1 1), expected := .accept [], note := "ttl straddles bytes 0 and 1" }
vector nshCtx := {
  id := "nsh-md1-ctx", ast := nshW (cmp nshCtx1 .eq (k 1)), packet := nshPkt (nshMd1 1), expected := .accept [] }
vector nshCtxMiss := {
  id := "nsh-md1-ctx-miss", ast := nshW (cmp nshCtx1 .eq (k 2)), packet := nshPkt (nshMd1 1), expected := .reject }
vector nshCtxAbsent := {
  id := "nsh-md1-ctx-absent", ast := nshW (cmp nshCtx1 .ne (k 0)), packet := nshPkt (nshMd2 1), expected := .reject,
  note := "D-003/D-027: MD type 2 has no md1" }
vector nshCtxAbsentNot := {
  id := "nsh-md1-ctx-absent-not", ast := nshW (.not (cmp nshCtx1 .eq (k 1))), packet := nshPkt (nshMd2 1), expected := .accept [] }
vector nshCtxBracket := {
  id := "nsh-pred-md1-ctx", ast := nshPred (.cmp (fp ["md1", "ctx2"]) .eq (.int 2)), packet := nshPkt (nshMd1 1), expected := .accept [] }
vector nshMd1ExistsAbsent := {
  id := "nsh-md1-exists-absent", ast := nshW (.fieldExists (fp ["nsh", "md1"])), packet := nshPkt (nshMd2 1), expected := .reject }
vector nshSpi := {
  id := "nsh-where-spi", ast := nshW (cmp (fld "nsh" "spi") .eq (k 100)), packet := nshPkt (nshMd1 1), expected := .accept [],
  goStatus := .notImplemented, note := "D-043: Go reads no 3-byte field in a comparison (as vxlan.vni)" }
vector nshTruncBase := {
  id := "nsh-truncated-base", ast := { layers := [P "eth", P "nsh"] }, packet := (nshPkt (nshMd1 1)).take 19, expected := .reject }
vector nshTruncMd1 := {
  id := "nsh-truncated-md1", ast := { layers := [P "eth", P "nsh"] }, packet := (nshPkt (nshMd1 1)).take 32, expected := .reject,
  note := "10 of the 16 context bytes" }
vector nshMd1Exact := {
  id := "nsh-md1-exact-fit", ast := { layers := [P "eth", P "nsh"] }, packet := (nshPkt (nshMd1 1)).take 38, expected := .accept [] }
vector nshTruncMd2 := {
  id := "nsh-truncated-md2", ast := { layers := [P "eth", P "nsh"] }, packet := (nshPkt (nshMd2 1)).take 27, expected := .reject,
  note := "5 of the 8 TLV bytes" }

def nshVectors : List Vector := [
  nshMd1Chain, nshMd2Chain, nshMd2Empty, nshTerminal, nshIPv6, nshEth, nshMpls, nshNextProtoMiss, nshVlan, nshGre,
  nshOptAbsent, nshOptPresent, nshMdTypeBad, nshMdTypeExperimental, nshMd2LengthShort, nshMd2LengthWrong, nshMd2LengthOverrun,
  nshSi, nshSiMiss, nshTtl, nshCtx, nshCtxMiss, nshCtxAbsent, nshCtxAbsentNot, nshCtxBracket, nshMd1ExistsAbsent, nshSpi,
  nshTruncBase, nshTruncMd1, nshMd1Exact, nshTruncMd2]

-- ERSPAN (D-044) -------------------------------------------------------------

/-- GRE with the sequence-number bit set, as ERSPAN II and III send it. -/
def greSeq (protoType : Nat) (seq : Nat := 1) : Packet := be 2 0x1000 ++ be 2 protoType ++ be 4 seq
def erspanHdr (version : Nat) (sessionId : Nat := 100) (vlanId : Nat := 10) (t : Nat := 0) (cos : Nat := 0) (en : Nat := 0) : Packet :=
  be 2 (version * 4096 + vlanId) ++ be 2 (cos * 8192 + en * 2048 + t * 1024 + sessionId)
def erspanV2 (index : Nat := 7) : Packet := be 4 index
def erspanV3 (ts : Nat := 0x01020304) (sgt : Nat := 50) (hwId : Nat := 3) (o : Nat := 0) : Packet :=
  be 4 ts ++ be 2 sgt ++ be 2 (hwId * 16 + o)
def erspanInner : Packet := eth 0x0800 ++ ipv4 6 ++ tcp 12345 80 ++ payload 5
def erspanPkt (protoType : Nat) (erspan : Packet) (inner : Packet := erspanInner) : Packet :=
  eth 0x0800 ++ ipv4 47 ++ greSeq protoType ++ erspan ++ inner
def erspan2Pkt : Packet := erspanPkt 0x88BE (erspanHdr 1 ++ erspanV2)
def erspan3Pkt : Packet := erspanPkt 0x22EB (erspanHdr 2 ++ erspanV3)
def erspanL : List Layer := [P "eth", P "ipv4", P "gre", P "erspan", P "eth", P "ipv4", P "tcp"]
def erspanW (w : Where) : Filter := { layers := erspanL, cond := some w }
def erspanPred (p : Predicate) : Filter :=
  { layers := [P "eth", P "ipv4", P "gre", .proto { name := "erspan", preds := [p] }, P "eth", P "ipv4", P "tcp"] }
def erspanTs := fa ["erspan", "v3", "timestamp"]
def erspanTermL : List Layer := [P "eth", P "ipv4", P "gre", P "erspan"]

vector erspan2Chain := {
  id := "erspan2", ast := erspanW (cmp dport .eq (k 80)), packet := erspan2Pkt, expected := .accept [] }
vector erspan3Chain := {
  id := "erspan3", ast := erspanW (cmp dport .eq (k 80)), packet := erspan3Pkt, expected := .accept [],
  note := "KUNAI_ERSPAN_GRE_PROTOCOL_TYPE_ALT_TYPE3" }
vector erspan3Platform := {
  id := "erspan3-platform-subheader", ast := erspanW (cmp dport .eq (k 80)),
  packet := erspanPkt 0x22EB (erspanHdr 2 ++ erspanV3 (o := 1) ++ be 8 0x0102030405060708), expected := .accept [],
  note := "D-044: O = 1 skips the 8-byte platform-specific subheader" }
vector erspan3PlatformMissing := {
  id := "erspan3-platform-subheader-missing", ast := { layers := erspanL },
  packet := erspanPkt 0x22EB (erspanHdr 2 ++ erspanV3 (o := 1)), expected := .reject,
  note := "the inner frame is read 8 bytes late: its ethertype lands on the ipv4 flags" }
vector erspanIPv6 := {
  id := "erspan-ipv6-outer", ast := { layers := [P "eth", P "ipv6", P "gre", P "erspan", P "eth", P "ipv4", P "tcp"] },
  packet := eth 0x86DD ++ ipv6 47 ++ greSeq 0x88BE ++ erspanHdr 1 ++ erspanV2 ++ erspanInner, expected := .accept [] }
vector erspanInnerVlan := {
  id := "erspan-inner-vlan", ast := { layers := [P "eth", P "ipv4", P "gre", P "erspan", P "eth", P "vlan", P "ipv4", P "tcp"] },
  packet := erspanPkt 0x88BE (erspanHdr 1 ++ erspanV2) (eth 0x8100 ++ vlan 10 0x0800 ++ ipv4 6 ++ tcp 12345 80), expected := .accept [] }
vector erspanGreMiss := {
  id := "erspan-gre-type-miss", ast := { layers := erspanTermL }, packet := erspanPkt 0x6558 (erspanHdr 1 ++ erspanV2), expected := .reject,
  note := "0x6558 is transparent Ethernet bridging" }
vector erspanVersion0 := {
  id := "erspan-version-0-reject", ast := { layers := erspanTermL }, packet := erspanPkt 0x88BE (erspanHdr 0 ++ erspanV2), expected := .reject }
vector erspanVersion3 := {
  id := "erspan-version-3-reject", ast := { layers := erspanTermL }, packet := erspanPkt 0x22EB (erspanHdr 3 ++ erspanV3), expected := .reject }
vector erspanVersionCross := {
  id := "erspan-version-over-gre-type", ast := erspanW (cmp erspanTs .eq (k 0x01020304)),
  packet := erspanPkt 0x88BE (erspanHdr 2 ++ erspanV3), expected := .accept [],
  note := "D-044: the version, not the GRE protocol type, picks the layout" }
vector erspanSession := {
  id := "erspan-pred-session", ast := erspanPred (.cmp (f "session_id") .eq (.int 100)), packet := erspan3Pkt, expected := .accept [] }
vector erspanSessionMiss := {
  id := "erspan-pred-session-miss", ast := erspanPred (.cmp (f "session_id") .eq (.int 101)), packet := erspan2Pkt, expected := .reject }
vector erspanVlanT := {
  id := "erspan-where-vlan-t", ast := erspanW (.and (cmp (fld "erspan" "vlan") .eq (k 10)) (cmp (fld "erspan" "t") .eq (k 1))),
  packet := erspanPkt 0x88BE (erspanHdr 1 (t := 1) ++ erspanV2), expected := .accept [] }
vector erspanCos := {
  id := "erspan-where-cos-en", ast := erspanW (.and (cmp (fld "erspan" "cos") .eq (k 5)) (cmp (fld "erspan" "en") .eq (k 3))),
  packet := erspanPkt 0x88BE (erspanHdr 1 (cos := 5) (en := 3) ++ erspanV2), expected := .accept [] }
vector erspanTsHit := {
  id := "erspan3-timestamp", ast := erspanW (cmp erspanTs .eq (k 0x01020304)), packet := erspan3Pkt, expected := .accept [] }
vector erspanTsAbsent := {
  id := "erspan3-timestamp-absent", ast := erspanW (cmp erspanTs .ne (k 0)), packet := erspan2Pkt, expected := .reject,
  note := "D-003/D-027: type II has no v3" }
vector erspanTsAbsentNot := {
  id := "erspan3-timestamp-absent-not", ast := erspanW (.not (cmp erspanTs .eq (k 0))), packet := erspan2Pkt, expected := .accept [] }
vector erspanSgt := {
  id := "erspan3-sgt-hw-id", ast := erspanW (.and (cmp (fa ["erspan", "v3", "sgt"]) .eq (k 50)) (cmp (fa ["erspan", "v3", "hw_id"]) .eq (k 3))),
  packet := erspan3Pkt, expected := .accept [] }
vector erspanOBracket := {
  id := "erspan3-pred-o", ast := erspanPred (.cmp (fp ["v3", "o"]) .eq (.int 1)),
  packet := erspanPkt 0x22EB (erspanHdr 2 ++ erspanV3 (o := 1) ++ be 8 0), expected := .accept [] }
vector erspanOBracketMiss := {
  id := "erspan3-pred-o-miss", ast := erspanPred (.cmp (fp ["v3", "o"]) .eq (.int 1)), packet := erspan3Pkt, expected := .reject }
vector erspanV2Exists := {
  id := "erspan2-exists", ast := erspanW (.fieldExists (fp ["erspan", "v2"])), packet := erspan2Pkt, expected := .accept [] }
vector erspanV3ExistsAbsent := {
  id := "erspan3-exists-absent", ast := erspanW (.fieldExists (fp ["erspan", "v3"])), packet := erspan2Pkt, expected := .reject }
vector erspanIndex := {
  id := "erspan2-index", ast := erspanW (cmp (fa ["erspan", "v2", "index"]) .eq (k 7)), packet := erspan2Pkt, expected := .accept [],
  goStatus := .notImplemented, note := "D-044: Go reads the 20-bit index through a 4-byte window past the 4-byte entry" }
vector erspanTruncBase := {
  id := "erspan-truncated-base", ast := { layers := erspanTermL }, packet := erspan2Pkt.take 44, expected := .reject }
vector erspan2Exact := {
  id := "erspan2-exact-fit", ast := { layers := erspanTermL }, packet := erspan2Pkt.take 50, expected := .accept [] }
vector erspan2Trunc := {
  id := "erspan2-truncated", ast := { layers := erspanTermL }, packet := erspan2Pkt.take 48, expected := .reject }
vector erspan3Trunc := {
  id := "erspan3-truncated", ast := { layers := erspanTermL }, packet := erspan3Pkt.take 52, expected := .reject,
  note := "6 of the 8 type III bytes" }
vector erspan3PlatformTrunc := {
  id := "erspan3-platform-truncated", ast := { layers := erspanTermL },
  packet := (erspanPkt 0x22EB (erspanHdr 2 ++ erspanV3 (o := 1) ++ be 8 0)).take 58, expected := .reject,
  note := "4 of the 8 platform bytes" }
vector erspan3RawIP := {
  id := "erspan3-raw-ip-reject", ast := { layers := erspanTermL ++ [P "eth"] },
  packet := erspanPkt 0x22EB (erspanHdr 2 ++ be 4 0x01020304 ++ be 2 50 ++ be 2 (2 * 1024)) (ipv4 6 ++ tcp 12345 80),
  expected := .reject, note := "D-044: FT 2 is an IP packet; only Ethernet payloads are parsed" }
vector erspanType1 := {
  id := "erspan1-no-sequence-reject", ast := { layers := erspanTermL, cond := some (.fieldExists (fp ["erspan", "v2"])) },
  packet := eth 0x0800 ++ ipv4 47 ++ be 2 0 ++ be 2 0x88be ++ eth 0x0800 (dst := 0x100000000001) ++ ipv4 6 ++ tcp 12345 80,
  expected := .reject, note := "D-044: GRE S=0 is type I even when the inner destination starts with version nibble 1" }

def erspanVectors : List Vector := [
  erspan2Chain, erspan3Chain, erspan3Platform, erspan3PlatformMissing, erspanIPv6, erspanInnerVlan, erspanGreMiss,
  erspanVersion0, erspanVersion3, erspanVersionCross, erspanSession, erspanSessionMiss, erspanVlanT, erspanCos,
  erspanTsHit, erspanTsAbsent, erspanTsAbsentNot, erspanSgt, erspanOBracket, erspanOBracketMiss, erspanV2Exists,
  erspanV3ExistsAbsent, erspanIndex, erspanTruncBase, erspan2Exact, erspan2Trunc, erspan3Trunc, erspan3PlatformTrunc,
  erspan3RawIP, erspanType1]

-- IGMP (D-045) ---------------------------------------------------------------

def igmpHdr (type : Nat) (group : Nat) (maxResp : Nat := 100) : Packet := [UInt8.ofNat type, UInt8.ofNat maxResp] ++ be 2 0 ++ be 4 group
/-- v3 report header: the group word holds reserved (16) + number of records (16). -/
def igmpV3Report (records : Nat) : Packet := [0x22, 0] ++ be 2 0 ++ be 2 0 ++ be 2 records
def igmpRecord (recType mcast : Nat) (sources : List Nat := []) : Packet :=
  [UInt8.ofNat recType, 0] ++ be 2 sources.length ++ be 4 mcast ++ (sources.map (be 4)).flatten
/-- IGMP rides in an IPv4 header with the Router Alert option (RFC 2113, IHL 6). -/
def igmpPkt (igmp : Packet) : Packet :=
  eth 0x0800 (dst := 0x01005e010101) ++ ipv4 2 (ttl := 1) (dst := 0xef010101) (ihl := 6) (options := [148, 4, 0, 0]) ++ igmp
def igmpV2Report : Packet := igmpPkt (igmpHdr 0x16 0xef010101 (maxResp := 0))
def igmpQuery : Packet := igmpPkt (igmpHdr 0x11 0)
/-- v3 report joining 239.1.1.1 (CHANGE_TO_EXCLUDE_MODE, no sources). -/
def igmpV3Join : Packet := igmpPkt (igmpV3Report 1 ++ igmpRecord 4 0xef010101)
def igmpL : List Layer := [P "eth", P "ipv4", P "igmp"]
def igmpW (w : Where) : Filter := { layers := igmpL, cond := some w }
def igmpPred (p : Predicate) : Filter := { layers := [P "eth", P "ipv4", .proto { name := "igmp", preds := [p] }] }

vector igmpV2 := {
  id := "igmp-v2-report", ast := { layers := igmpL }, packet := igmpV2Report, expected := .accept [] }
vector igmpQ := {
  id := "igmp-query", ast := { layers := igmpL }, packet := igmpQuery, expected := .accept [] }
vector igmpV3 := {
  id := "igmp-v3-report", ast := { layers := igmpL }, packet := igmpV3Join, expected := .accept [] }
vector igmpVlan := {
  id := "igmp-vlan", ast := { layers := [P "eth", P "vlan", P "ipv4", P "igmp"] },
  packet := eth 0x8100 ++ vlan 100 0x0800 ++ ipv4 2 ++ igmpHdr 0x17 0xef010101, expected := .accept [],
  note := "without the Router Alert option" }
vector igmpProtoMiss := {
  id := "igmp-proto-miss", ast := { layers := igmpL }, expected := .reject, note := "ipv4.protocol 6 is tcp" }
vector igmpNotIcmp := {
  id := "igmp-not-icmp", ast := { layers := [P "eth", P "ipv4", P "icmp"] }, packet := igmpV2Report, expected := .reject }
vector igmpType := {
  id := "igmp-pred-type", ast := igmpPred (.cmp (f "type") .eq (.int 0x16)), packet := igmpV2Report, expected := .accept [] }
vector igmpTypeMiss := {
  id := "igmp-pred-type-miss", ast := igmpPred (.cmp (f "type") .eq (.int 0x17)), packet := igmpV2Report, expected := .reject }
vector igmpGroup := {
  id := "igmp-where-group", ast := igmpW (.litCmp (ff "igmp" "group") .eq (.ipv4 0xef010101)), packet := igmpV2Report, expected := .accept [] }
vector igmpGroupCidr := {
  id := "igmp-where-group-cidr", ast := igmpW (.litCmp (ff "igmp" "group") .eq (.cidr4 0xef000000 8)), packet := igmpV2Report, expected := .accept [] }
vector igmpGeneralQuery := {
  id := "igmp-general-query", ast := igmpW (.and (cmp (fld "igmp" "type") .eq (k 0x11)) (cmp (fld "igmp" "group") .eq (k 0))),
  packet := igmpQuery, expected := .accept [] }
vector igmpMaxResp := {
  id := "igmp-where-max-resp", ast := igmpW (cmp (fld "igmp" "max_resp_code") .gt (k 10)), packet := igmpQuery, expected := .accept [] }
vector igmpRouterAlert := {
  id := "igmp-ipv4-router-alert", ast := igmpW (cmp (fa ["ipv4", "options", "ROUTER_ALERT", "value"]) .eq (k 0)),
  packet := igmpV2Report, expected := .accept [], note := "the ipv4 option walk runs before igmp" }
vector igmpV3NoRecords := {
  id := "igmp-v3-report-no-records", ast := { layers := igmpL }, packet := igmpPkt (igmpV3Report 0), expected := .accept [],
  note := "D-045: group records are not parsed" }
vector igmpV3NoRecordsPadded := {
  id := "igmp-v3-report-no-records-padding", ast := { layers := igmpL },
  packet := igmpPkt (igmpV3Report 0) ++ List.replicate 14 0, expected := .accept [],
  note := "D-045: Ethernet padding is not a group record" }
vector igmpV3Query := {
  id := "igmp-v3-query", ast := igmpW (cmp (fld "igmp" "group") .eq (k 0)),
  packet := igmpPkt (igmpHdr 0x11 0 ++ [0x02, 125] ++ be 2 0), expected := .accept [],
  note := "D-045: the v3 query extension after byte 8 is not read" }
vector igmpTrunc := {
  id := "igmp-truncated", ast := { layers := igmpL }, packet := igmpV2Report.take 45, expected := .reject, note := "7 of 8 bytes" }
vector igmpExact := {
  id := "igmp-exact-fit", ast := { layers := igmpL }, packet := igmpV2Report, expected := .accept [] }
def igmpVectors : List Vector := [
  igmpV2, igmpQ, igmpV3, igmpVlan, igmpProtoMiss, igmpNotIcmp, igmpType, igmpTypeMiss, igmpGroup, igmpGroupCidr,
  igmpGeneralQuery, igmpMaxResp, igmpRouterAlert, igmpV3NoRecords, igmpV3NoRecordsPadded, igmpV3Query,
  igmpTrunc, igmpExact]

def protocolVectors : List Vector := pfcpVectors ++ sctpVectors ++ arpVectors ++ nshVectors ++ erspanVectors ++ igmpVectors

end Kunai
