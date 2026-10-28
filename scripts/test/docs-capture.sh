#!/bin/bash
# Small, isolated documentation smoke test. Run only in a disposable Linux VM.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export BN_DOCS_BINARY="$ROOT/bpf-ninja"
[[ $(id -u) == 0 ]] || { echo 'root required' >&2; exit 1; }
[[ -x $BN_DOCS_BINARY && -r /sys/kernel/btf/vmlinux ]] || { echo 'build binary and provide kernel BTF' >&2; exit 1; }
[[ $(stat -f -c %T /sys/fs/bpf) == bpf_fs ]] || { echo 'mount bpffs before running this example' >&2; exit 1; }
for tool in ip ping tcpdump timeout nsenter; do
    command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
done

# This suite exercises --cbpf too; reject a default binary before network setup.
"$BN_DOCS_BINARY" --cbpf --dump-asm filter "icmp" >/dev/null || {
    echo "Legacy filters are required; run 'make build-libpcap' first" >&2; exit 1;
}

OUT=$(mktemp -d /tmp/bpf-ninja-docs.XXXXXX)
export BN_DOCS_NS="bn-doc-a-$$"
PEER="bn-doc-b-$$"
PINDIR="/sys/fs/bpf/bn-doc-$$"
PIN="$PINDIR/types"
owned_a=0 owned_b=0 owned_pin=0
cleanup() {
    local ns pid
    # Only our newly created namespaces can contain our capture processes.
    for ns in "$BN_DOCS_NS" "$PEER"; do
        if [[ $ns == "$BN_DOCS_NS" && $owned_a == 0 ]] || [[ $ns == "$PEER" && $owned_b == 0 ]]; then
            continue
        fi
        for pid in $(ip netns pids "$ns"); do kill -TERM "$pid" 2>/dev/null || true; done
        for _ in {1..40}; do
            [[ -z $(ip netns pids "$ns") ]] && break
            sleep 0.05
        done
        for pid in $(ip netns pids "$ns"); do kill -KILL "$pid" 2>/dev/null || true; done
        ip netns del "$ns"
    done
    if [[ $owned_pin == 1 ]]; then
        rm -f -- "$PIN"
        rmdir -- "$PINDIR"
    fi
    echo "Evidence retained in $OUT"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ip netns add "$BN_DOCS_NS"; owned_a=1
ip netns add "$PEER"; owned_b=1
mkdir "$PINDIR"; owned_pin=1
ip -n "$BN_DOCS_NS" link add doc0 type veth peer name doc1
ip -n "$BN_DOCS_NS" link set doc1 netns "$PEER"
ip -n "$BN_DOCS_NS" addr add 192.0.2.1/30 dev doc0
ip -n "$PEER" addr add 192.0.2.2/30 dev doc1
ip -n "$BN_DOCS_NS" link set doc0 up
ip -n "$PEER" link set doc1 up
ip -n "$BN_DOCS_NS" link set lo up
ip -n "$PEER" link set lo up

cat > "$OUT/capture" <<'WRAPPER'
#!/bin/bash
exec nsenter --net="/var/run/netns/$BN_DOCS_NS" -- "$BN_DOCS_BINARY" "$@"
WRAPPER
chmod +x "$OUT/capture"
BINARY="$OUT/capture"
# Shared readiness, deadline, requested stop and summary validation.
source "$ROOT/scripts/test/capture_helpers.sh"
send_ping() { ip netns exec "$PEER" ping -q -c "$1" -i 0.1 -W 1 192.0.2.1 >/dev/null; }
check_pcap() {
    local file=$1 expected=$2 count
    tcpdump -n -r "$file" 'icmp and icmp[0] == 8' > "$file.txt"
    count=$(wc -l < "$file.txt")
    [[ $count -eq $expected ]] || { echo "$file: expected $expected, got $count" >&2; return 1; }
}
check_summary() {
    [[ $(capture_count "$1") -eq $2 ]] && grep -q '^capture status=complete ' "$1"
}

capture_run "$OUT/match.log" count send_ping 3 --mode xdp -i doc0 -c 3 -w "$OUT/match.pcap" 'eth/ipv4/icmp[type==8]'
check_summary "$OUT/match.log" 3
check_pcap "$OUT/match.pcap" 3
capture_run "$OUT/miss.log" signal send_ping 3 --mode xdp -i doc0 -w "$OUT/miss.pcap" 'eth/ipv4/tcp[dport==80]'
check_summary "$OUT/miss.log" 0
check_pcap "$OUT/miss.pcap" 0
capture_run "$OUT/legacy.log" count send_ping 3 --cbpf --mode xdp -i doc0 -c 3 -w "$OUT/legacy.pcap" icmp
check_summary "$OUT/legacy.log" 3
check_pcap "$OUT/legacy.pcap" 3
capture_run "$OUT/raw.log" count send_ping 3 --mode xdp -i doc0 -c 3 --raw-dump -w "$OUT/session" 'eth/ipv4/icmp[type==8]'
"$BN_DOCS_BINARY" convert -r "$OUT/session.W*.cpu*.raw" -o "$OUT/converted.pcap"
check_summary "$OUT/raw.log" 3
check_pcap "$OUT/converted.pcap" 3

"$BN_DOCS_BINARY" set create "$PIN" --key 'type:u8'
"$BN_DOCS_BINARY" set add "$PIN" type=8 tag=7
"$BN_DOCS_BINARY" set schema "$PIN" > "$OUT/schema.txt"
"$BN_DOCS_BINARY" set list "$PIN" > "$OUT/entries.txt"
update_while_capturing() {
    send_ping 3 || return 1
    "$BN_DOCS_BINARY" set del "$PIN" type=8 || return 1
    send_ping 3 || return 1
    "$BN_DOCS_BINARY" set add "$PIN" type=8 tag=7 || return 1
    send_ping 3
}
capture_run "$OUT/set.log" count update_while_capturing 9 --mode xdp -i doc0 -c 6 --set "types=$PIN" -w "$OUT/set.pcap" 'eth/ipv4/icmp[type in @types]'
check_summary "$OUT/set.log" 6
check_pcap "$OUT/set.pcap" 6

finalize_tag() {
    send_ping 3 || return 1
    # Ensure the polling watcher has seen the entry before deleting it.
    # This delay is not used as a completion acknowledgement.
    sleep 2
    "$BN_DOCS_BINARY" set del "$PIN" type=8 || return 1
    timeout 15s bash -c 'until [[ -f $1 ]]; do sleep 0.1; done' -- "$OUT/tag.7.pcap" || return 1
    check_pcap "$OUT/tag.7.pcap" 3
}
CAPTURE_TIMEOUT=25 capture_run "$OUT/tag.log" signal finalize_tag 3 --mode xdp -i doc0 --set "types=$PIN" --split-by-tag --finalize-on-del -w "$OUT/tag.pcap" 'eth/ipv4/icmp[type in @types]'
check_summary "$OUT/tag.log" 3
check_pcap "$OUT/tag.7.pcap" 3
# Offline merge operates on stopped writers and keeps the original shards.
"$BN_DOCS_BINARY" merge --base "$OUT/tag.pcap"
check_pcap "$OUT/tag.7.pcap" 3
echo 'Documentation capture examples passed'
