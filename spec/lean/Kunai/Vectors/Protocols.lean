import Kunai.Vectors.AuxHeaders

/-!
# Protocol vectors: PFCP, SCTP, ARP

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
  id := "arp-ethertype-miss", ast := { layers := arpL }, expected := .reject, note := "eth.ethertype 0x0800 is ipv4" }
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

def protocolVectors : List Vector := pfcpVectors ++ sctpVectors ++ arpVectors

end Kunai
