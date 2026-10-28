#!/usr/bin/env bash
# Run as root inside a disposable VM. Uses only TEST_RUN and private bpffs pins.
set -euo pipefail
work=$(mktemp -d /tmp/ninja-argmember.XXXXXX)
pin=/sys/fs/bpf/ninja_argmember_$$
pid=
cleanup() {
  if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  rm -rf "$pin" "$work"
}
trap cleanup EXIT
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
mkdir -p "$pin"
echo "kernel=$(uname -r)"
checks=0
start() {
  local object=$1 config=$2
  if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  rm -f "$work/id"
  printf '%s\n' "$config" > "$work/rules.json"
  ./bpf-ninja inject-run --fail-closed --config "$work/rules.json" -- ./loader "$object" > "$work/id" 2> "$work/inject.err" &
  pid=$!
  for ((i=0;i<100;i++)); do
    [[ -s "$work/id" ]] && break
    kill -0 "$pid" 2>/dev/null || { cat "$work/inject.err"; return 1; }
    sleep 0.1
  done
  ID=$(cat "$work/id")
  [[ "$ID" =~ ^[0-9]+$ ]]
  cat "$work/inject.err"
}
schema() {
  local hook=$1 expr=$2
  ./bpf-ninja -p "$ID" --func "$hook" --list-params --members > /dev/null 2> "$work/schema"
  cat "$work/schema"
  grep -F "$expr" "$work/schema" > /dev/null
  checks=$((checks+1))
}
cap() {
  local name=$1 hook=$2 port=$3
  shift 3
  local rc=0
  timeout -s INT 4 ./bpf-ninja -p "$ID" --func "$hook" -c 3 -w "$work/cap.pcap" "$@" > /dev/null 2> "$work/cap.err" || rc=$?
  if [[ "$port" == none ]]; then
    [[ $rc == 124 ]] || { cat "$work/cap.err"; return 1; }
  else
    [[ $rc == 0 ]] || { cat "$work/cap.err"; return 1; }
  fi
  tcpdump -nn -r "$work/cap.pcap" > "$work/decoded" 2> "$work/tcpdump.err"
  local count got
  count=$(wc -l < "$work/decoded")
  got=$(awk '{for(i=1;i<=NF;i++)if($i~/^10\.0\.0\.2\.[0-9]+:$/){sub(/:$/,"",$i);sub(/^10\.0\.0\.2\./,"",$i);print $i}}' "$work/decoded" | sort -nu | paste -sd,)
  if [[ "$port" == none ]]; then
    [[ "$count" == 0 ]] || { cat "$work/decoded"; return 1; }
  else
    [[ "$count" == 3 && "$got" == "$port" ]] || { cat "$work/decoded"; cat "$work/cap.err"; return 1; }
  fi
  echo "PASS $name: packets=$count dport=${got:-none} rc=$rc"
  if [[ "$name" == member_equal ]]; then cat "$work/cap.err"; cat "$work/decoded"; fi
  checks=$((checks+1))
  rm -f "$work"/cap.pcap*
}
start policies.o '[{"program":"entry","auto":true,"ops":["lookup:any"],"hook":"ninja","stack_lowest_offset":-16}]'
schema ninja_policies 'value->action'
grep -F 'key->dport' "$work/schema" > /dev/null
cap member_equal ninja_policies 443 --arg-filter 'value->action==2'
cap member_not_equal ninja_policies 80 --arg-filter 'value->action!=2'
cap member_be16 ninja_policies 443 --arg-filter 'value->port==be16(443)'
cap key_be16 ninja_policies 443 --arg-filter 'key->dport=be16(443)'
cap member_range_and ninja_policies 443 --arg-filter 'value->action=1..2' --arg-filter 'value->action>=2' --arg-filter 'value->action<=2'
cap member_exit ninja_policies 443 --mode exit --arg-filter 'value->action==2'
cap member_gated ninja_policies 443 --mode entry --mode exit --emit exit --arg-filter 'value->action==2'
cap member_miss ninja_policies none --arg-filter 'value->action==3'
# Integer set keys contain the native interpretation of the member's bytes.
./bpf-ninja set create "$pin/ports" --key 'dport:u16' > /dev/null
./bpf-ninja set add "$pin/ports" dport=47873 > /dev/null
cap member_set ninja_policies 443 --set "ports=$pin/ports,key(dport=arg:key->dport)" --arg-filter @ports
cap member_set_implicit ninja_policies 443 --set "ports=$pin/ports" --arg-filter @ports
./bpf-ninja set del "$pin/ports" dport=47873 > /dev/null
cap member_set_removed ninja_policies none --set "ports=$pin/ports,key(dport=arg:key->dport)" --arg-filter @ports
# The walkthrough's scalar value pointers are u32 for bloom, u64 for queue.
start walkthrough.o '[{"program":"entry","auto":true,"ops":["push:any","pop:any","peek:any"],"hook":"ninja","stack_lowest_offset":-64}]'
schema ninja_seen_peek 'value[0]'
cap bloom_scalar ninja_seen_peek 443 --arg-filter 'value[0]==64'
schema ninja_recent_push 'value[0]'
cap queue_scalar ninja_recent_push 443 --arg-filter 'value[0]=64'
cap scalar_not_equal ninja_seen_peek 443 --arg-filter 'value[0]!=80' --arg-filter 'value[0]!=96'
# A typed lookup miss hook has no value arg. Dispatch retains value=NULL.
# Kernels without arg:untrusted use static hooks and fault-handled ctx reads.
if [[ "$(uname -r)" == 6.1.* ]]; then
  start policies.o '[{"program":"entry","auto":true,"dispatch":true,"static_untrusted":true,"ops":["lookup:any"],"hook":"observe","stack_lowest_offset":-16}]'
else
  start policies.o '[{"program":"entry","auto":true,"dispatch":true,"ops":["lookup:any"],"hook":"observe","stack_lowest_offset":-16}]'
fi
cap dispatch_null observe 22 --arg-filter 'value==null'
cap dispatch_nonnull observe '80,443' --arg-filter 'value!=null'
cap dispatch_null_exit observe 22 --mode exit --arg-filter 'value==null'
cap dispatch_null_gated observe 22 --mode entry --mode exit --emit exit --arg-filter 'value==null'
echo "PASS checks=$checks"
