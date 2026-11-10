import Kunai.Vectors.AuxHeaders

/-!
# Protocol vectors: PFCP

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

def protocolVectors : List Vector := pfcpVectors

end Kunai
