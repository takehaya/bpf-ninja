#!/usr/bin/env bash
# Run as root inside a disposable VM. Uses only TEST_RUN and private bpffs pins.
set -euo pipefail
work=$(mktemp -d "$PWD/argmember-results.XXXXXX")
pin=/sys/fs/bpf/ninja_argmember_$$
pid=
cleanup() {
  local rc=$?
  if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  rm -rf "$pin"
  echo "Artifacts retained in $work (exit=$rc)"
  return "$rc"
}
trap cleanup EXIT
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
mkdir -p "$pin"
echo "kernel=$(uname -r)"
checks=0
starts=0
start() {
  local object=$1 config=$2
  if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  starts=$((starts+1))
  local dir=$work/start-$starts
  mkdir -p "$dir"
  printf '%s\n' "$config" > "$dir/rules.json"
  ./bpf-ninja inject-run --fail-closed --config "$dir/rules.json" -- ./loader "$object" > "$dir/id" 2> "$dir/inject.err" &
  pid=$!
  for ((i=0;i<100;i++)); do
    [[ -s "$dir/id" ]] && break
    kill -0 "$pid" 2>/dev/null || { cat "$dir/inject.err"; return 1; }
    sleep 0.1
  done
  ID=$(cat "$dir/id")
  [[ "$ID" =~ ^[0-9]+$ ]]
  cat "$dir/inject.err"
}
schema() {
  local hook=$1 expr=$2
  ./bpf-ninja -p "$ID" --func "$hook" --list-params --members > /dev/null 2> "$work/schema-$hook"
  cat "$work/schema-$hook"
  grep -F "$expr" "$work/schema-$hook" > /dev/null
  checks=$((checks+1))
}
cap() {
  local name=$1 hook=$2 port=$3
  shift 3
  local dir=$work/$name
  mkdir -p "$dir"
  local rc=0
  timeout -s INT 4 ./bpf-ninja -p "$ID" --func "$hook" -c 3 -w "$dir/cap.pcap" "$@" > /dev/null 2> "$dir/cap.err" || rc=$?
  if [[ "$port" == none ]]; then
    [[ $rc == 124 ]] || { cat "$dir/cap.err"; return 1; }
  else
    [[ $rc == 0 ]] || { cat "$dir/cap.err"; return 1; }
  fi
  tcpdump -nn -r "$dir/cap.pcap" > "$dir/decoded" 2> "$dir/tcpdump.err"
  local count got
  count=$(wc -l < "$dir/decoded")
  got=$(awk '{for(i=1;i<=NF;i++)if($i~/^10\.0\.0\.2\.[0-9]+:$/){sub(/:$/,"",$i);sub(/^10\.0\.0\.2\./,"",$i);print $i}}' "$dir/decoded" | sort -nu | paste -sd,)
  if [[ "$port" == none ]]; then
    [[ "$count" == 0 ]] || { cat "$dir/decoded"; return 1; }
  else
    [[ "$count" == 3 && "$got" == "$port" ]] || { cat "$dir/decoded"; cat "$dir/cap.err"; return 1; }
  fi
  echo "PASS $name: packets=$count dport=${got:-none} rc=$rc"
  if [[ "$name" == member_equal ]]; then cat "$dir/cap.err"; cat "$dir/decoded"; fi
  checks=$((checks+1))
}
start policies.o '[{"program":"entry","auto":true,"ops":["lookup:any"],"hook":"ninja","stack_lowest_offset":-16}]'
schema ninja_policies 'value->action'
grep -F 'key->dport' "$work/schema-ninja_policies" > /dev/null
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
cap member_set_dotted ninja_policies 443 --set "flows.prod=$pin/ports,key(dport=arg:key->dport)" --arg-filter @flows.prod
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
# Matrix kernels without arg:untrusted use static hooks. Context reads are
# fault-handled only when a direct-load probe rejects this particular target.
case "$(uname -r)" in
  6.1.*|6.6.*|6.12.*|6.15.*)
    start policies.o '[{"program":"entry","auto":true,"dispatch":true,"static_untrusted":true,"ops":["lookup:any"],"hook":"observe","stack_lowest_offset":-16}]' ;;
  *)
    start policies.o '[{"program":"entry","auto":true,"dispatch":true,"ops":["lookup:any"],"hook":"observe","stack_lowest_offset":-16}]' ;;
esac
cap dispatch_null observe 22 --arg-filter 'value==null'
cap dispatch_nonnull observe '80,443' --arg-filter 'value!=null'
cap dispatch_null_exit observe 22 --mode exit --arg-filter 'value==null'
cap dispatch_null_gated observe 22 --mode entry --mode exit --emit exit --arg-filter 'value==null'
echo "PASS checks=$checks"
