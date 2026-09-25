#!/bin/bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY="${BINARY:-$PROJECT_DIR/bpf-ninja}"
source "$SCRIPT_DIR/capture_helpers.sh"
PASS=0
FAIL=0

red()   { echo -e "\033[31m$*\033[0m"; }
green() { echo -e "\033[32m$*\033[0m"; }

SKIP=0

run_test() {
    local name="$1"
    shift
    echo -n "  $name ... "
    local output
    output=$("$@" 2>&1)
    local rc=$?
    if [[ $rc -eq 0 ]]; then
        green "PASS"
        PASS=$((PASS + 1))
    elif [[ $rc -eq 77 && ${CI:-} != true && ${CI:-} != 1 ]]; then
        echo "SKIP ($output)"
        SKIP=$((SKIP + 1))
    else
        red "FAIL"
        if [[ -n "$output" ]]; then
            echo "    debug: $output"
        fi
        FAIL=$((FAIL + 1))
    fi
}

# --- helpers ---

send_packets() {
    ip netns exec xdptest ping -c "$1" -W 1 10.0.0.1 >/dev/null 2>&1
}

require_bpftool() {
    if ! command -v bpftool >/dev/null; then
        echo "skipping: bpftool not installed" >&2
        return 77
    fi
    bpftool prog show >/dev/null
}

# Always inspect the final merged file. Python's independent pcap-ng reader
# enforces packet count, lengths, link type, and (when requested) action names.
assert_pcap() {
    python3 "$SCRIPT_DIR/assert_pcap.py" "$@"
}

# run_count_test <expected-min> <bpf-ninja-args...>
# Runs bpf-ninja with the given args in the background, sends 5 pings
# from the test netns, and asserts the captured packet count is at
# least <expected-min>.
run_count_test() {
    local expected=$1 err count result=1
    shift
    err=$(mktemp)
    if capture_run "$err" count send_packets 5 "$@"; then
        count=$(capture_count "$err")
        [[ "$count" -ge "$expected" ]] && result=0
    fi
    [[ $result -eq 0 ]] || cat "$err" >&2
    rm -f "$err"
    return "$result"
}

# run_nomatch_test <bpf-ninja-args...>
# Runs a short-lived bpf-ninja that the ping traffic should not match,
# then asserts zero captures. Uses kill+wait because the binary would
# otherwise block on -c until timeout.
run_nomatch_test() {
    local err count result=1
    err=$(mktemp)
    if capture_run "$err" signal send_packets 3 "$@"; then
        count=$(capture_count "$err")
        [[ "$count" -eq 0 ]] && result=0
    fi
    [[ $result -eq 0 ]] || cat "$err" >&2
    rm -f "$err"
    return "$result"
}

# run_pcap_test <bpf-ninja-args...>
# Captures to a final merged pcap and checks every record.
run_pcap_test() {
    local pcap err result=1
    local checks=()
    [[ -z ${PCAP_CAPLEN:-} ]] || checks+=(--caplen "$PCAP_CAPLEN")
    [[ -z ${PCAP_INTERFACE:-} ]] || checks+=(--interface "$PCAP_INTERFACE")
    pcap=$(mktemp --suffix=.pcap)
    err=$(mktemp)
    if capture_run "$err" count send_packets 5 -w "$pcap" "$@"; then
        assert_pcap "$pcap" --count "$(capture_count "$err")" --min-count 3 "${checks[@]}" && result=0
    fi
    [[ $result -eq 0 ]] || cat "$err" >&2
    rm -f "$pcap" "$pcap".cpu* "$err"
    return "$result"
}

# --- tests ---

test_entry_no_filter()      { run_count_test 3 -i veth0 -c 3; }
test_entry_filter_match()   { run_count_test 3 --cbpf -i veth0 -c 3 "icmp"; }
test_entry_filter_nomatch() { run_nomatch_test --cbpf -i veth0 "tcp port 80"; }
test_exit_capture()         { run_count_test 3 -i veth0 --mode exit -c 3; }
test_pcap_output()          { run_pcap_test -i veth0 -c 3; }

test_prog_id() {
    require_bpftool || return $?
    local prog_id
    prog_id=$(bpftool prog show name xdp_pass 2>/dev/null | head -1 | awk '{print $1}' | tr -d ':')
    [[ -n "$prog_id" ]] || { echo "xdp_pass not found" >&2; return 1; }
    run_count_test 3 -p "$prog_id" -c 3
}

send_tailcall_packets() {
    ip netns exec xdptctest ping -c "$1" -W 1 10.98.0.1 >/dev/null 2>&1
}

test_tailcall_dispatcher() {
    require_bpftool || return $?
    "$SCRIPT_DIR/cleanup_tailcall.sh" 2>/dev/null || true
    local setup_out
    setup_out=$("$SCRIPT_DIR/setup_tailcall.sh" 2>&1)
    local disp_id=$(echo "$setup_out" | tail -1)
    if [[ -z "$disp_id" || ! "$disp_id" =~ ^[0-9]+$ ]]; then
        echo "setup_tailcall failed: $setup_out" >&2
        "$SCRIPT_DIR/cleanup_tailcall.sh" 2>/dev/null || true
        return 1
    fi

    local err=$(mktemp)
    local count=-1
    if capture_run "$err" count send_tailcall_packets 5 -p "$disp_id" -c 3; then
        count=$(capture_count "$err")
    fi
    echo "disp_id=$disp_id count=$count stderr=$(cat "$err")" >&2
    rm -f "$err"
    "$SCRIPT_DIR/cleanup_tailcall.sh" 2>/dev/null || true
    [[ "$count" -ge 3 ]]
}

test_exit_pcap_action() { PCAP_INTERFACE=xdp:PASS run_pcap_test -i veth0 --mode exit -c 3; }

test_dsl_entry_filter_match()    { run_count_test 3 -i veth0 -c 3 "eth/ipv4/icmp"; }
test_dsl_entry_predicate_match() { run_count_test 3 -i veth0 -c 3 "eth/ipv4/icmp[type==8]"; }
test_dsl_entry_filter_nomatch()  { run_nomatch_test -i veth0 "eth/ipv4/tcp"; }
# Bundled icmp_h is the 4-byte common header: Ethernet 14 + IPv4 20
# + ICMP common 4 + requested payload 32 = 70 bytes.
test_dsl_capture_headers()       { PCAP_CAPLEN=70 run_pcap_test -i veth0 -c 3 "eth/ipv4/icmp capture headers+32"; }

# Dummy XDP returns XDP_PASS (=2); this exercises the fexit action atom
# codegen against a known return value.
test_dsl_exit_action() { run_count_test 3 -i veth0 --mode exit -c 3 "eth/ipv4/icmp where action == XDP_PASS"; }

# tc_prog_id resolves the integration's dummy tc clsact classifier
# program ID via bpftool — needed because tc-mode targeting is
# program-ID-only (no interface-based clsact qdisc walk yet, see
# F15 follow-up scope).
tc_prog_id() {
    bpftool prog show name tc_pass 2>/dev/null | head -1 | awk '{print $1}' | tr -d ':'
}

# Dummy tc clsact classifier returns TC_ACT_OK (=0); --mode entry
# and --mode exit attach as fentry/fexit observers and capture
# packets on each ingress event.
test_dsl_tc_entry() {
    require_bpftool || return $?
    local pid_t=$(tc_prog_id)
    [[ -n "$pid_t" ]] || { echo "tc_pass program not found" >&2; return 1; }
    run_count_test 3 --mode entry -p "$pid_t" -c 3 "eth/ipv4/icmp"
}

test_dsl_tc_exit_action() {
    require_bpftool || return $?
    local pid_t=$(tc_prog_id)
    [[ -n "$pid_t" ]] || { echo "tc_pass program not found" >&2; return 1; }
    PCAP_INTERFACE=tc:TC_ACT_OK run_pcap_test --mode exit -p "$pid_t" -c 3 "eth/ipv4/icmp where action == TC_ACT_OK"
}

# --- cgroup-skb hook (setup.sh attaches cgroup_pass to a scratch
# cgroup; skipped when cgroup2 / bpffs / bpftool support is missing).
# The observed traffic is ping over loopback run from INSIDE the
# scratch cgroup: cgroup-skb fires per-socket, so the pinging process
# itself must be a cgroup member (veth traffic from the netns would
# not traverse it). Packet bytes start at the IP header (no Ethernet),
# hence the ipv4-rooted DSL and the LINKTYPE_RAW assertion.
CGROUP_TEST_DIR=/sys/fs/cgroup/bpfninja-test

require_cgroup_target() {
    require_bpftool || return $?
    if ! bpftool cgroup show "$CGROUP_TEST_DIR" 2>/dev/null | grep -q cgroup_pass; then
        echo "skipping: cgroup_pass not attached (no cgroup2/bpffs?)" >&2
        return 77
    fi
}

cgroup_prog_id() {
    bpftool cgroup show "$CGROUP_TEST_DIR" 2>/dev/null | awk '/cgroup_pass/ {print $1; exit}'
}

# send_cgroup_packets <count>: ping loopback from a shell placed into
# the scratch cgroup, generating ICMP through the cgroup-skb hook.
send_cgroup_packets() {
    sudo sh -c "echo \$\$ > '$CGROUP_TEST_DIR/cgroup.procs'; ping -c $1 -W 1 127.0.0.1" >/dev/null 2>&1
}

# run_cgroup_count_test <expected-min> <bpf-ninja-args...>
run_cgroup_count_test() {
    local expected=$1 err count result=1
    shift
    err=$(mktemp)
    if capture_run "$err" count send_cgroup_packets 5 "$@"; then
        count=$(capture_count "$err")
        [[ "$count" -ge "$expected" ]] && result=0
    fi
    [[ $result -eq 0 ]] || cat "$err" >&2
    rm -f "$err"
    return "$result"
}

test_dsl_cgroup_entry() {
    require_cgroup_target || return $?
    local pid_c=$(cgroup_prog_id)
    [[ -n "$pid_c" ]] || { echo "cgroup_pass program id not found" >&2; return 1; }
    run_cgroup_count_test 3 -p "$pid_c" -c 3 "ipv4/icmp"
}

test_dsl_cgroup_exit_action() {
    require_cgroup_target || return $?
    local pid_c=$(cgroup_prog_id)
    [[ -n "$pid_c" ]] || { echo "cgroup_pass program id not found" >&2; return 1; }
    run_cgroup_count_test 3 --mode exit -p "$pid_c" -c 3 "ipv4/icmp where action == SK_PASS"
}

test_cgroup_path_selector() {
    require_cgroup_target || return $?
    run_cgroup_count_test 3 --cgroup "$CGROUP_TEST_DIR" -c 3 "ipv4/icmp"
}

# Asserts the pcap-ng written for a cgroup-skb capture carries
# LINKTYPE_RAW (101), not Ethernet — packets start at the IP header.
test_cgroup_pcap_linktype_raw() {
    require_cgroup_target || return $?
    local pid_c=$(cgroup_prog_id)
    [[ -n "$pid_c" ]] || { echo "cgroup_pass program id not found" >&2; return 1; }
    local pcap=$(mktemp --suffix=.pcap)
    local err=$(mktemp)
    if ! capture_run "$err" count send_cgroup_packets 5 -w "$pcap" -p "$pid_c" -c 3 "ipv4/icmp"; then
        rm -f "$pcap" "$pcap".cpu* "$err"
        return 1
    fi
    local ok=1
    assert_pcap "$pcap" --count "$(capture_count "$err")" --min-count 3 --linktype 101 && ok=0
    rm -f "$pcap" "$pcap".cpu* "$err"
    [[ $ok -eq 0 ]]
}

# Exercises --func subfunction attach + --arg-filter argument reading against
# xdp_argcap, whose capture_point(ctx, pkt_len) uses KEEP_ARGS to keep pkt_len
# on the ABI. A real ping frame (~98 B) satisfies pkt_len>=60 (match) but none
# is >=200 (nomatch); requiring both proves the argument value is actually read
# rather than always/never matching.
send_arg_packets() {
    ip netns exec xdpargtest ping -c "$1" -W 1 10.99.0.1 >/dev/null 2>&1
}

send_arg_set_packets() {
    ip netns exec xdpargtest ping -c "$1" -s 100 -W 1 10.99.0.1 >/dev/null 2>&1
}

test_argfilter() {
    "$SCRIPT_DIR/cleanup_argcap.sh" 2>/dev/null || true
    local setup_out
    if ! setup_out=$("$SCRIPT_DIR/setup_argcap.sh" 2>&1); then
        echo "setup_argcap failed: $setup_out" >&2
        "$SCRIPT_DIR/cleanup_argcap.sh" 2>/dev/null || true
        return 1
    fi

    local errm errn cmatch=-1 cnomatch=-1
    errm=$(mktemp)
    errn=$(mktemp)
    if capture_run "$errm" count send_arg_packets 5 -i va0 --func capture_point --arg-filter "pkt_len>=60" -c 3; then
        cmatch=$(capture_count "$errm")
    fi
    if capture_run "$errn" signal send_arg_packets 3 -i va0 --func capture_point --arg-filter "pkt_len>=200"; then
        cnomatch=$(capture_count "$errn")
    fi
    echo "argfilter match=$cmatch nomatch=$cnomatch stderr_m=$(cat "$errm") stderr_n=$(cat "$errn")" >&2
    rm -f "$errm" "$errn"
    "$SCRIPT_DIR/cleanup_argcap.sh" 2>/dev/null || true
    [[ "$cmatch" -ge 3 && "$cnomatch" -eq 0 ]]
}

# Exercises arg-based pinned-map set matching (--set NAME=/path,key(field=arg:param)
# + --arg-filter @NAME) against capture_point's pkt_len. A `ping -s 100` yields a
# deterministic 142-byte frame that the set matches by membership; swapping the
# set to a length no frame carries proves the lookup actually gates capture. The
# comma inside key(...) also exercises the root slice-flag no-split fix (#74).
test_argfilter_set() {
    local pin=/sys/fs/bpf/argcap_lens_test
    rm -f "$pin" 2>/dev/null || true
    "$SCRIPT_DIR/cleanup_argcap.sh" 2>/dev/null || true
    local setup_out
    if ! setup_out=$("$SCRIPT_DIR/setup_argcap.sh" 2>&1); then
        echo "setup_argcap failed: $setup_out" >&2
        "$SCRIPT_DIR/cleanup_argcap.sh" 2>/dev/null || true
        return 1
    fi
    if ! "$BINARY" set create "$pin" --key "pkt_len:u32" >/dev/null 2>&1 \
        || ! "$BINARY" set add "$pin" pkt_len=142 >/dev/null 2>&1; then
        echo "set create/add failed" >&2
        rm -f "$pin" 2>/dev/null || true
        "$SCRIPT_DIR/cleanup_argcap.sh" 2>/dev/null || true
        return 1
    fi

    local errm errn cmatch=-1 cnomatch=-1
    errm=$(mktemp)
    errn=$(mktemp)
    if capture_run "$errm" count send_arg_set_packets 5 -i va0 --func capture_point --set "LENS=$pin,key(pkt_len=arg:pkt_len)" --arg-filter "@LENS" -c 3; then
        cmatch=$(capture_count "$errm")
    fi

    # Swap the set to a length no frame carries; membership should now miss.
    # Track the swap so an empty set (a failed re-add) cannot false-pass the
    # nomatch half — it must genuinely hold a non-matching entry.
    local swapped=0
    if "$BINARY" set del "$pin" pkt_len=142 >/dev/null 2>&1 \
        && "$BINARY" set add "$pin" pkt_len=12345 >/dev/null 2>&1; then
        swapped=1
    fi
    if capture_run "$errn" signal send_arg_set_packets 3 -i va0 --func capture_point --set "LENS=$pin,key(pkt_len=arg:pkt_len)" --arg-filter "@LENS"; then
        cnomatch=$(capture_count "$errn")
    fi
    echo "argfilter_set match=$cmatch nomatch=$cnomatch swapped=$swapped stderr_m=$(cat "$errm") stderr_n=$(cat "$errn")" >&2
    rm -f "$errm" "$errn" "$pin"
    "$SCRIPT_DIR/cleanup_argcap.sh" 2>/dev/null || true
    [[ "$swapped" -eq 1 && "$cmatch" -ge 3 && "$cnomatch" -eq 0 ]]
}

# Per-entry cap (`set add ... max-bytes=N`) + --exit-when-capped: a tiny
# cap on the entry must make the process exit 0 on its own (no signal),
# and the merged per-tag file must stay near the cap (batch-granular
# overshoot allowed).
test_split_per_entry_cap() {
    local pin=/sys/fs/bpf/bpfninja_capset_$$
    local cap=300
    rm -f "$pin" 2>/dev/null || true
    if ! "$BINARY" set create "$pin" --key "type:u8" >/dev/null 2>&1 \
        || ! "$BINARY" set add "$pin" type=8 tag=1 max-bytes="$cap" >/dev/null 2>&1; then
        echo "set create/add failed" >&2
        rm -f "$pin" 2>/dev/null || true
        return 1
    fi

    local pcap=$(mktemp --suffix=.pcap)
    local err=$(mktemp)
    timeout 15 "$BINARY" -i veth0 --set "caps=$pin" --split-by-tag \
        --exit-when-capped \
        -w "$pcap" 'eth/ipv4/icmp[type in @caps]' > /dev/null 2>"$err" &
    local pid=$!
    sleep 2
    ip netns exec xdptest ping -c 40 -i 0.1 -W 1 10.0.0.1 >/dev/null 2>&1 || true
    wait $pid
    local rc=$?

    local merged="${pcap%.pcap}.1.pcap"
    local size=0
    [[ -f "$merged" ]] && size=$(stat -c %s "$merged")
    local capped=0
    grep -q "capped" "$err" && capped=1
    echo "split_cap rc=$rc size=$size capped=$capped stderr=$(cat "$err")" >&2
    local content_ok=0
    assert_pcap "$merged" --min-count 1 --caplen 98 && content_ok=1
    rm -f "$pcap" "${pcap%.pcap}".*.pcap "$pcap".cpu* "$err" "$pin"
    # 4 KiB slack: the cap is enforced per ringbuf batch per shard, plus
    # the merged file's fixed pcap-ng headers.
    [[ $content_ok -eq 1 && $rc -eq 0 && $capped -eq 1 && $size -gt 0 && $size -le $((cap + 4096)) ]]
}

# Per-entry cap composed with --finalize-on-del: the cap must park the
# entry (state=capped, kernel match stops), the tag must then quiesce
# and finalize to out.<tag>.pcap while the process keeps running, and
# the entry must end as state=finalized in `set list` (still showing
# its key).
test_cap_finalize_flow() {
    local pin=/sys/fs/bpf/bpfninja_capfin_$$
    rm -f "$pin" 2>/dev/null || true
    if ! "$BINARY" set create "$pin" --key "type:u8" >/dev/null 2>&1 \
        || ! "$BINARY" set add "$pin" type=8 tag=1 max-bytes=300 >/dev/null 2>&1; then
        echo "set create/add failed" >&2
        rm -f "$pin" 2>/dev/null || true
        return 1
    fi

    local pcap=$(mktemp --suffix=.pcap)
    local merged="${pcap%.pcap}.1.pcap"
    local err=$(mktemp)
    timeout 25 "$BINARY" -i veth0 --set "caps=$pin" --split-by-tag \
        --finalize-on-del -w "$pcap" 'eth/ipv4/icmp[type in @caps]' > /dev/null 2>"$err" &
    local pid=$!
    sleep 2
    ip netns exec xdptest ping -c 60 -i 0.1 -W 1 10.0.0.1 >/dev/null 2>&1 &
    local pingpid=$!

    # cap (~0.5s of traffic) -> park -> quiesce (2 cycles) -> merge.
    local appeared=0
    for _ in $(seq 1 12); do
        [[ -f "$merged" ]] && { appeared=1; break; }
        sleep 1
    done
    wait $pingpid 2>/dev/null
    local alive=0
    kill -0 $pid 2>/dev/null && alive=1
    local finalized=0
    "$BINARY" set list "$pin" 2>/dev/null | grep -Eq "tag=1 .*state=finalized" && finalized=1
    local size=0
    [[ -f "$merged" ]] && size=$(stat -c %s "$merged")
    kill -INT $pid 2>/dev/null; wait $pid 2>/dev/null
    local rc=$?

    echo "cap_finalize appeared=$appeared alive=$alive finalized=$finalized size=$size rc=$rc list=$("$BINARY" set list "$pin" 2>/dev/null) stderr=$(cat "$err")" >&2
    local content_ok=0
    assert_pcap "$merged" --min-count 1 --caplen 98 && content_ok=1
    rm -f "$pcap" "${pcap%.pcap}".*.pcap "$pcap".cpu* "$err" "$pin"
    # Same cap + batch + header slack as test_split_per_entry_cap.
    [[ $content_ok -eq 1 && $appeared -eq 1 && $alive -eq 1 && $finalized -eq 1 && $rc -eq 0 && $size -gt 0 && $size -le $((300 + 4096)) ]]
}

# All three flags composed: the cap must park the entry, the finalizer
# must produce the ack AND stamp state=finalized BEFORE the process
# exits 0 on its own — finalized is the guaranteed terminal state, so a
# collector polling `set list` never hangs after the exit.
test_cap_finalize_exit() {
    local pin=/sys/fs/bpf/bpfninja_capfx_$$
    rm -f "$pin" 2>/dev/null || true
    if ! "$BINARY" set create "$pin" --key "type:u8" >/dev/null 2>&1 \
        || ! "$BINARY" set add "$pin" type=8 tag=1 max-bytes=300 >/dev/null 2>&1; then
        echo "set create/add failed" >&2
        rm -f "$pin" 2>/dev/null || true
        return 1
    fi

    local pcap=$(mktemp --suffix=.pcap)
    local merged="${pcap%.pcap}.1.pcap"
    local err=$(mktemp)
    timeout 30 "$BINARY" -i veth0 --set "caps=$pin" --split-by-tag \
        --finalize-on-del --exit-when-capped \
        -w "$pcap" 'eth/ipv4/icmp[type in @caps]' > /dev/null 2>"$err" &
    local pid=$!
    sleep 2
    ip netns exec xdptest ping -c 60 -i 0.1 -W 1 10.0.0.1 >/dev/null 2>&1 || true
    wait $pid
    local rc=$?

    local appeared=0
    [[ -f "$merged" ]] && appeared=1
    local finalized=0
    "$BINARY" set list "$pin" 2>/dev/null | grep -Eq "tag=1 .*state=finalized" && finalized=1

    echo "cap_finalize_exit rc=$rc appeared=$appeared finalized=$finalized list=$("$BINARY" set list "$pin" 2>/dev/null) stderr=$(cat "$err")" >&2
    local content_ok=0
    assert_pcap "$merged" --min-count 1 --caplen 98 && content_ok=1
    rm -f "$pcap" "${pcap%.pcap}".*.pcap "$pcap".cpu* "$err" "$pin"
    [[ $content_ok -eq 1 && $rc -eq 0 && $appeared -eq 1 && $finalized -eq 1 ]]
}

# --finalize-on-del: removing a tag's set entry must produce the merged
# out.<tag>.pcap while the process keeps running (the completion ack),
# and the process must still shut down cleanly afterwards.
test_finalize_on_del() {
    local pin=/sys/fs/bpf/bpfninja_finset_$$
    rm -f "$pin" 2>/dev/null || true
    if ! "$BINARY" set create "$pin" --key "type:u8" >/dev/null 2>&1 \
        || ! "$BINARY" set add "$pin" type=8 tag=1 >/dev/null 2>&1; then
        echo "set create/add failed" >&2
        rm -f "$pin" 2>/dev/null || true
        return 1
    fi

    local pcap=$(mktemp --suffix=.pcap)
    local merged="${pcap%.pcap}.1.pcap"
    local err=$(mktemp)
    timeout 20 "$BINARY" -i veth0 --set "caps=$pin" --split-by-tag \
        --finalize-on-del -w "$pcap" 'eth/ipv4/icmp[type in @caps]' > /dev/null 2>"$err" &
    local pid=$!
    sleep 2
    send_packets 5
    "$BINARY" set del "$pin" type=8 >/dev/null 2>&1

    # The ack file should appear within a few quiesce cycles (~1s each).
    local appeared=0
    for _ in $(seq 1 8); do
        [[ -f "$merged" ]] && { appeared=1; break; }
        sleep 1
    done
    local alive=0
    kill -0 $pid 2>/dev/null && alive=1
    local pkts=0
    [[ $appeared -eq 1 ]] && pkts=$(tcpdump -r "$merged" 2>/dev/null | wc -l)
    kill -INT $pid 2>/dev/null; wait $pid 2>/dev/null
    local rc=$?

    echo "finalize_on_del appeared=$appeared alive=$alive pkts=$pkts rc=$rc stderr=$(cat "$err")" >&2
    local content_ok=0
    assert_pcap "$merged" --min-count 1 --caplen 98 && content_ok=1
    rm -f "$pcap" "${pcap%.pcap}".*.pcap "$pcap".cpu* "$err" "$pin"
    [[ $content_ok -eq 1 && $appeared -eq 1 && $alive -eq 1 && $pkts -ge 3 && $rc -eq 0 ]]
}

# --max-bytes (no split): the aggregate cap must stop the capture by
# itself with exit 0.
test_max_bytes_total() {
    local pcap=$(mktemp --suffix=.pcap)
    local err=$(mktemp)
    timeout 15 "$BINARY" -i veth0 --max-bytes 300 -w "$pcap" icmp > /dev/null 2>"$err" &
    local pid=$!
    sleep 2
    ip netns exec xdptest ping -c 40 -i 0.1 -W 1 10.0.0.1 >/dev/null 2>&1 || true
    wait $pid
    local rc=$?
    local count=$(capture_count "$err")
    local reached=0
    grep -q "total output cap reached" "$err" && reached=1
    echo "max_bytes rc=$rc count=$count reached=$reached stderr=$(cat "$err")" >&2
    local content_ok=0
    assert_pcap "$pcap" --count "$count" --min-count 1 && content_ok=1
    rm -f "$pcap" "$pcap".cpu* "$err"
    [[ $content_ok -eq 1 && $rc -eq 0 && $reached -eq 1 && $count -gt 0 ]]
}

test_graceful_shutdown() {
    require_bpftool || return $?
    local prog_id_before=$(bpftool prog show name xdp_pass 2>/dev/null | head -1 | awk '{print $1}' | tr -d ':')

    run_count_test 1 -i veth0 -c 1 || return 1

    local prog_id_after=$(bpftool prog show name xdp_pass 2>/dev/null | head -1 | awk '{print $1}' | tr -d ':')
    echo "before=$prog_id_before after=$prog_id_after" >&2
    [[ -n "$prog_id_after" && "$prog_id_before" == "$prog_id_after" ]]
}

# --- main ---

# Sourcing exposes helpers for fault-injection tests without network setup.
[[ ${BASH_SOURCE[0]} == "$0" ]] || return 0

echo "Checking binary..."
if [[ ! -x "$BINARY" ]]; then
    red "Binary not found: $BINARY"
    red "Run 'go build -o bpf-ninja ./cmd/bpf-ninja/' first"
    exit 1
fi

echo "Setting up test environment..."

# --- multi-point capture (--mode entry EXPR --mode exit EXPR in one run) ---
# Own veth pair with a decap+drop XDP program (decap_drop.c). Two
# --mode are a gated capture: only packets matching the entry filter
# AND the exit filter are emitted. Sent: 5 x A (encap, inner dport 80
# -> DROP), 5 x B (encap, inner dport 443 -> PASS), 5 x C (no encap).
# Expected with the default --emit both: 5 entry records (outer
# header, 104 B, verdict DROP) each immediately followed by its exit
# record (decapsulated inner frame, 62 B) with the same epb_packetid;
# B never appears (exit filter wants DROP), C never appears (entry
# filter wants UDP 6081). Frames are hand-built (no scapy); the pcap-ng
# is parsed by hand because this tshark has no frame.packet_id field.
MP_IF=ddmp0; MP_PEER=ddmp1; MP_NS=ddmptest
setup_multipoint() {
    clang -O2 -g -target bpf -c "$SCRIPT_DIR/decap_drop.c" -o "$SCRIPT_DIR/decap_drop.o" || { echo "FAIL: compiling decap_drop.c" >&2; return 1; }
    cleanup_multipoint
    ip netns add $MP_NS || return 1
    ip link add $MP_IF type veth peer name $MP_PEER || return 1
    ip link set $MP_PEER netns $MP_NS || return 1
    ip link set $MP_IF up && ip netns exec $MP_NS ip link set $MP_PEER up || return 1
    ip link set dev $MP_IF xdp obj "$SCRIPT_DIR/decap_drop.o" sec xdp || return 1
}
cleanup_multipoint() {
    ip link del $MP_IF 2>/dev/null || true
    ip netns del $MP_NS 2>/dev/null || true
}
send_multipoint_frames() {
    ip netns exec $MP_NS python3 - "$MP_PEER" <<'EOF'
import socket, struct, sys
def csum(h):
    s = sum(struct.unpack('!%dH' % (len(h)//2), h)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff
def ipv4(src, dst, proto, payload):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload
def udp(sp, dp, payload): return struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
def tcp(sp, dp): return struct.pack('!HHIIBBHHH', sp, dp, 1, 0, 0x50, 0x02, 1024, 0, 0) + b'\x00' * 8  # 20 B header + 8 B payload
def eth(payload): return b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00' + payload
inner_drop = eth(ipv4('10.1.0.1', '10.1.0.2', 6, tcp(40000, 80)))    # inner TCP dport 80 -> DROP
inner_pass = eth(ipv4('10.1.0.1', '10.1.0.2', 6, tcp(40000, 443)))   # inner TCP dport 443 -> PASS
A = eth(ipv4('10.0.0.2', '10.0.0.1', 17, udp(1234, 6081, inner_drop)))
B = eth(ipv4('10.0.0.2', '10.0.0.1', 17, udp(1234, 6081, inner_pass)))
C = eth(ipv4('10.0.0.2', '10.0.0.1', 17, udp(1234, 9, b'x' * 40)))    # no encap -> entry filter miss
assert len(A) == 104 and len(inner_drop) == 62
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); s.bind((sys.argv[1], 0))
for _ in range(5):
    for f in (A, B, C): s.send(f)
EOF
}
check_multipoint_pcap() {
    # args: want_entries want_drops want_paired files...
    # want_paired '-' = a merged file: ids are not carried, so only
    # interfaces and sizes are checked.
    python3 - "$SCRIPT_DIR" "$@" <<'EOF'
import sys
sys.path.insert(0, sys.argv.pop(1))
from assert_pcap import packets
entries = drops = other = paired = 0
check_ids = sys.argv[3] != '-'
bad = []
for fn in sys.argv[4:]:
    last_entry = None
    for packet in packets(fn):
        if packet['linktype'] != 1: raise ValueError('expected Ethernet linktype')
        caplen, pid, name = packet['caplen'], packet['packet_id'], packet['interface']
        if name.endswith(':entry'):
            entries += 1; last_entry = pid
            if caplen != 104 or (check_ids and pid == 0): bad.append(('entry', fn, caplen, pid))
        elif name.endswith(':DROP'):
            drops += 1
            if caplen != 62 or (check_ids and pid == 0): bad.append(('drop', fn, caplen, pid))
            elif pid == last_entry: paired += 1  # --emit exit has no entry record to pair with
        else:
            other += 1; bad.append(('other', fn, name))
want_entries = int(sys.argv[1]); want_drops = int(sys.argv[2]); want_paired = int(sys.argv[3]) if check_ids else paired
print(f"entry={entries} drop={drops} other={other} paired={paired} bad={bad[:3]}")
sys.exit(0 if (entries == want_entries and drops == want_drops and other == 0 and paired == want_paired and not bad) else 1)
EOF
}
# run_multipoint_case <count> <want_entries> <want_drops> <want_paired> [extra bpf-ninja args...]
run_multipoint_case() {
    local count=$1 we=$2 wd=$3 wp=$4
    shift 4
    local pcap=$(mktemp --suffix=.pcapng)
    local err=$(mktemp)
    if ! CAPTURE_TIMEOUT=15 capture_run "$err" count send_multipoint_frames 5 -i "$MP_IF" --mode entry "eth/ipv4/udp[dport==6081]" --mode exit "eth/ipv4/tcp where action == XDP_DROP" "$@" -w "$pcap" -c "$count"; then
        rm -f "$pcap" "$pcap".cpu* "$err"
        return 1
    fi
    local out
    # The per-CPU shard files carry the packet ids; the merged base file
    # goes through gopacket's reader (which drops the epb_packetid
    # option) but must still hold every record on the right interface.
    out=$(check_multipoint_pcap "$we" "$wd" "$wp" "$pcap".cpu* 2>&1)
    local result=$?
    [[ $result -eq 0 ]] && { out=$(check_multipoint_pcap "$we" "$wd" - "$pcap" 2>&1); result=$?; }
    [[ $result -ne 0 ]] && { echo "$out"; cat "$err"; }
    rm -f "$pcap" "$pcap".cpu* "$err"
    return $result
}
test_multipoint_pairs() {
    setup_multipoint || { echo "FAIL: multipoint veth/xdp setup" >&2; cleanup_multipoint; return 1; }
    local rc=0
    run_multipoint_case 10 5 5 5 || rc=1                        # --emit both (default): 5 entry + 5 exit, paired
    run_multipoint_case 5 5 0 0 --emit entry || rc=1            # only the pre-decap images of the 5 dropped packets
    run_multipoint_case 5 0 5 0 --emit exit || rc=1             # only the decapsulated images (paired=0: no entry record precedes)
    cleanup_multipoint
    [[ $rc -eq 0 ]]
}

"$SCRIPT_DIR/cleanup.sh" 2>/dev/null || true
"$SCRIPT_DIR/setup.sh" || { red "Setup failed"; exit 1; }

echo ""
echo "Running integration tests:"
run_test "entry_no_filter"         test_entry_no_filter
run_test "entry_filter_match"      test_entry_filter_match
run_test "entry_filter_nomatch"    test_entry_filter_nomatch
run_test "exit_capture"            test_exit_capture
run_test "prog_id"                 test_prog_id
run_test "pcap_output"             test_pcap_output
run_test "exit_pcap_action"        test_exit_pcap_action
run_test "tailcall_dispatcher"     test_tailcall_dispatcher
run_test "dsl_entry_filter_match"  test_dsl_entry_filter_match
run_test "dsl_entry_predicate"     test_dsl_entry_predicate_match
run_test "dsl_entry_nomatch"       test_dsl_entry_filter_nomatch
run_test "dsl_capture_headers"     test_dsl_capture_headers
run_test "dsl_exit_action"         test_dsl_exit_action
run_test "dsl_tc_entry"            test_dsl_tc_entry
run_test "dsl_tc_exit_action"      test_dsl_tc_exit_action
run_test "dsl_cgroup_entry"        test_dsl_cgroup_entry
run_test "dsl_cgroup_exit_action"  test_dsl_cgroup_exit_action
run_test "cgroup_path_selector"    test_cgroup_path_selector
run_test "cgroup_pcap_linktype"    test_cgroup_pcap_linktype_raw
run_test "argfilter"               test_argfilter
run_test "argfilter_set"           test_argfilter_set
run_test "split_per_entry_cap"     test_split_per_entry_cap
run_test "cap_finalize_flow"       test_cap_finalize_flow
run_test "cap_finalize_exit"       test_cap_finalize_exit
run_test "finalize_on_del"         test_finalize_on_del
run_test "max_bytes_total"         test_max_bytes_total
run_test "graceful_shutdown"       test_graceful_shutdown
run_test "multipoint_pairs"        test_multipoint_pairs

echo ""
echo "Cleaning up..."
"$SCRIPT_DIR/cleanup.sh" 2>/dev/null || true

echo ""
echo "Results: $(green "$PASS passed"), $(red "$FAIL failed"), $SKIP skipped"
[[ $FAIL -eq 0 ]]
