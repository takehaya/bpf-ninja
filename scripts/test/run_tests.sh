#!/bin/bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY="$PROJECT_DIR/bpf-ninja"
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
    elif echo "$output" | grep -q "skipping"; then
        echo "SKIP"
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
    ip netns exec xdptest ping -c "$1" -W 1 10.0.0.1 >/dev/null 2>&1 || true
}

require_bpftool() {
    if ! bpftool prog show &>/dev/null; then
        echo "skipping: bpftool not working" >&2
        return 1
    fi
}

capture_count() {
    # bpf-ninja の stderr から "N packets captured" を抽出
    grep -oP '\d+(?= packets captured)' "$1" 2>/dev/null || echo 0
}

# read_any_shard <base-pcap-path> [match-pattern]
# After R22 (sharded ringbuf hoist), packets land in $base.cpuN per-CPU
# files; the base $pcap is a SHB+IDBs marker only. This walks the shards
# and returns 0 on the first one that contains at least one packet (and
# optionally matches `match-pattern` in the tshark frame.interface_name
# field). Returns 1 if no shard satisfies the check.
read_any_shard() {
    local base=$1
    local pattern=${2:-}
    local checker=tcpdump
    command -v tshark &>/dev/null && checker=tshark
    for shard in "$base".cpu*; do
        [[ -e "$shard" ]] || continue
        if [[ -n "$pattern" && $checker == tshark ]]; then
            tshark -r "$shard" -c 1 -T fields -e frame.interface_name 2>/dev/null \
                | grep -q "$pattern" && return 0
        else
            tcpdump -r "$shard" -c 1 >/dev/null 2>&1 && return 0
        fi
    done
    return 1
}

# run_count_test <expected-min> <bpf-ninja-args...>
# Runs bpf-ninja with the given args in the background, sends 5 pings
# from the test netns, and asserts the captured packet count is at
# least <expected-min>.
run_count_test() {
    local expected=$1
    shift
    local err=$(mktemp)
    timeout 10 "$BINARY" "$@" > /dev/null 2>"$err" &
    local pid=$!
    sleep 2
    send_packets 5
    wait $pid 2>/dev/null || true
    local count=$(capture_count "$err")
    rm -f "$err"
    [[ "$count" -ge "$expected" ]]
}

# run_nomatch_test <bpf-ninja-args...>
# Runs a short-lived bpf-ninja that the ping traffic should not match,
# then asserts zero captures. Uses kill+wait because the binary would
# otherwise block on -c until timeout.
run_nomatch_test() {
    local err=$(mktemp)
    timeout 5 "$BINARY" "$@" > /dev/null 2>"$err" &
    local pid=$!
    sleep 1
    send_packets 3
    sleep 2
    kill $pid 2>/dev/null; wait $pid 2>/dev/null || true
    local count=$(capture_count "$err")
    rm -f "$err"
    [[ "$count" -eq 0 ]]
}

# run_pcap_test <bpf-ninja-args...>
# Captures to a pcap file and asserts at least one shard contains a
# packet (the base $pcap is SHB+IDBs only after R22).
run_pcap_test() {
    local pcap=$(mktemp --suffix=.pcap)
    local err=$(mktemp)
    timeout 10 "$BINARY" -w "$pcap" "$@" 2>"$err" &
    local pid=$!
    sleep 2
    send_packets 5
    wait $pid 2>/dev/null || true
    read_any_shard "$pcap"
    local result=$?
    rm -f "$pcap" "$pcap".cpu* "$err"
    [[ $result -eq 0 ]]
}

# --- tests ---

test_entry_no_filter()      { run_count_test 3 -i veth0 -c 3; }
test_entry_filter_match()   { run_count_test 3 -i veth0 -c 3 "icmp"; }
test_entry_filter_nomatch() { run_nomatch_test -i veth0 "tcp port 80"; }
test_exit_capture()         { run_count_test 3 -i veth0 --mode exit -c 3; }
test_pcap_output()          { run_pcap_test -i veth0 -c 3; }

test_prog_id() {
    require_bpftool || return 1
    local prog_id=$(bpftool prog show name xdp_pass 2>/dev/null | head -1 | awk '{print $1}' | tr -d ':')
    if [[ -z "$prog_id" ]]; then
        echo "bpftool could not find xdp_pass" >&2
        return 1
    fi

    local err=$(mktemp)
    timeout 10 "$BINARY" -p "$prog_id" -c 3 > /dev/null 2>"$err" &
    local pid=$!
    sleep 2
    send_packets 5
    wait $pid 2>/dev/null || true
    local count=$(capture_count "$err")
    echo "prog_id=$prog_id count=$count stderr=$(cat "$err")" >&2
    rm -f "$err"
    [[ "$count" -ge 3 ]]
}

test_tailcall_dispatcher() {
    require_bpftool || return 1
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
    timeout 10 "$BINARY" -p "$disp_id" -c 3 > /dev/null 2>"$err" &
    local pid=$!
    sleep 2
    ip netns exec xdptctest ping -c 5 -W 1 10.98.0.1 >/dev/null 2>&1 || true
    wait $pid 2>/dev/null || true
    local count=$(capture_count "$err")
    echo "disp_id=$disp_id count=$count stderr=$(cat "$err")" >&2
    rm -f "$err"
    "$SCRIPT_DIR/cleanup_tailcall.sh" 2>/dev/null || true
    [[ "$count" -ge 3 ]]
}

test_exit_pcap_action() {
    local pcap=$(mktemp --suffix=.pcap)
    local err=$(mktemp)
    timeout 10 "$BINARY" -i veth0 --mode exit -w "$pcap" -c 3 2>"$err" &
    local pid=$!
    sleep 2
    send_packets 5
    wait $pid 2>/dev/null || true
    # tshark がいれば xdp:* interface name 込みで検証、 無ければ単なる
    # parse 可能性 fallback (cpuN shard の 1 つでも 1 packet あれば pass)。
    read_any_shard "$pcap" "xdp:"
    local result=$?
    rm -f "$pcap" "$pcap".cpu* "$err"
    [[ $result -eq 0 ]]
}

test_dsl_entry_filter_match()    { run_count_test 3 -i veth0 -c 3 "eth/ipv4/icmp"; }
test_dsl_entry_predicate_match() { run_count_test 3 -i veth0 -c 3 "eth/ipv4/icmp[type==8]"; }
test_dsl_entry_filter_nomatch()  { run_nomatch_test -i veth0 "eth/ipv4/tcp"; }
test_dsl_capture_headers()       { run_pcap_test -i veth0 -c 3 "eth/ipv4/icmp capture headers+32"; }

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
    require_bpftool || return 1
    local pid_t=$(tc_prog_id)
    [[ -n "$pid_t" ]] || { echo "tc_pass program not found" >&2; return 1; }
    run_count_test 3 --mode entry -p "$pid_t" -c 3 "eth/ipv4/icmp"
}

test_dsl_tc_exit_action() {
    require_bpftool || return 1
    local pid_t=$(tc_prog_id)
    [[ -n "$pid_t" ]] || { echo "tc_pass program not found" >&2; return 1; }
    run_count_test 3 --mode exit -p "$pid_t" -c 3 "eth/ipv4/icmp where action == TC_ACT_OK"
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
    require_bpftool || return 1
    if ! bpftool cgroup show "$CGROUP_TEST_DIR" 2>/dev/null | grep -q cgroup_pass; then
        echo "skipping: cgroup_pass not attached (no cgroup2/bpffs?)" >&2
        return 1
    fi
}

cgroup_prog_id() {
    bpftool cgroup show "$CGROUP_TEST_DIR" 2>/dev/null | awk '/cgroup_pass/ {print $1; exit}'
}

# send_cgroup_packets <count>: ping loopback from a shell placed into
# the scratch cgroup, generating ICMP through the cgroup-skb hook.
send_cgroup_packets() {
    sudo sh -c "echo \$\$ > '$CGROUP_TEST_DIR/cgroup.procs'; ping -c $1 -W 1 127.0.0.1" >/dev/null 2>&1 || true
}

# run_cgroup_count_test <expected-min> <bpf-ninja-args...>
run_cgroup_count_test() {
    local expected=$1
    shift
    local err=$(mktemp)
    timeout 10 "$BINARY" "$@" > /dev/null 2>"$err" &
    local pid=$!
    sleep 2
    send_cgroup_packets 5
    wait $pid 2>/dev/null || true
    local count=$(capture_count "$err")
    rm -f "$err"
    [[ "$count" -ge "$expected" ]]
}

test_dsl_cgroup_entry() {
    require_cgroup_target || return 1
    local pid_c=$(cgroup_prog_id)
    [[ -n "$pid_c" ]] || { echo "cgroup_pass program id not found" >&2; return 1; }
    run_cgroup_count_test 3 -p "$pid_c" -c 3 "ipv4/icmp"
}

test_dsl_cgroup_exit_action() {
    require_cgroup_target || return 1
    local pid_c=$(cgroup_prog_id)
    [[ -n "$pid_c" ]] || { echo "cgroup_pass program id not found" >&2; return 1; }
    run_cgroup_count_test 3 --mode exit -p "$pid_c" -c 3 "ipv4/icmp where action == SK_PASS"
}

test_cgroup_path_selector() {
    require_cgroup_target || return 1
    run_cgroup_count_test 3 --cgroup "$CGROUP_TEST_DIR" -c 3 "ipv4/icmp"
}

# Asserts the pcap-ng written for a cgroup-skb capture carries
# LINKTYPE_RAW (101), not Ethernet — packets start at the IP header.
test_cgroup_pcap_linktype_raw() {
    require_cgroup_target || return 1
    local pid_c=$(cgroup_prog_id)
    [[ -n "$pid_c" ]] || { echo "cgroup_pass program id not found" >&2; return 1; }
    local pcap=$(mktemp --suffix=.pcap)
    local err=$(mktemp)
    timeout 10 "$BINARY" -w "$pcap" -p "$pid_c" -c 3 "ipv4/icmp" 2>"$err" &
    local pid=$!
    sleep 2
    send_cgroup_packets 5
    wait $pid 2>/dev/null || true
    local ok=1
    for shard in "$pcap".cpu*; do
        [[ -e "$shard" ]] || continue
        # tcpdump names DLT 101 "RAW (Raw IP)" in its -r banner (stderr).
        if tcpdump -r "$shard" -c 1 2>&1 | grep -qi "RAW"; then
            ok=0
            break
        fi
    done
    rm -f "$pcap" "$pcap".cpu* "$err"
    [[ $ok -eq 0 ]]
}

# Exercises --func subfunction attach + --arg-filter argument reading against
# xdp_argcap, whose capture_point(ctx, pkt_len) uses KEEP_ARGS to keep pkt_len
# on the ABI. A real ping frame (~98 B) satisfies pkt_len>=60 (match) but none
# is >=200 (nomatch); requiring both proves the argument value is actually read
# rather than always/never matching.
test_argfilter() {
    "$SCRIPT_DIR/cleanup_argcap.sh" 2>/dev/null || true
    local setup_out
    if ! setup_out=$("$SCRIPT_DIR/setup_argcap.sh" 2>&1); then
        echo "setup_argcap failed: $setup_out" >&2
        "$SCRIPT_DIR/cleanup_argcap.sh" 2>/dev/null || true
        return 1
    fi

    local errm=$(mktemp)
    timeout 10 "$BINARY" -i va0 --func capture_point --arg-filter "pkt_len>=60" -c 3 > /dev/null 2>"$errm" &
    local pm=$!
    sleep 2
    ip netns exec xdpargtest ping -c 5 -W 1 10.99.0.1 >/dev/null 2>&1 || true
    wait $pm 2>/dev/null || true
    local cmatch=$(capture_count "$errm")

    local errn=$(mktemp)
    timeout 6 "$BINARY" -i va0 --func capture_point --arg-filter "pkt_len>=200" > /dev/null 2>"$errn" &
    local pn=$!
    sleep 1
    ip netns exec xdpargtest ping -c 3 -W 1 10.99.0.1 >/dev/null 2>&1 || true
    sleep 2
    kill $pn 2>/dev/null; wait $pn 2>/dev/null || true
    local cnomatch=$(capture_count "$errn")

    # Both runs must reach the normal shutdown ("N packets captured");
    # otherwise a crash/parse error before capture would leave cnomatch=0 and
    # false-pass the nomatch half.
    local ranm=0 rann=0
    grep -q "packets captured" "$errm" && ranm=1
    grep -q "packets captured" "$errn" && rann=1

    echo "argfilter match=$cmatch nomatch=$cnomatch ranm=$ranm rann=$rann stderr_m=$(cat "$errm") stderr_n=$(cat "$errn")" >&2
    rm -f "$errm" "$errn"
    "$SCRIPT_DIR/cleanup_argcap.sh" 2>/dev/null || true
    [[ "$ranm" -eq 1 && "$rann" -eq 1 && "$cmatch" -ge 3 && "$cnomatch" -eq 0 ]]
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

    local errm=$(mktemp)
    timeout 12 "$BINARY" -i va0 --func capture_point --set "LENS=$pin,key(pkt_len=arg:pkt_len)" --arg-filter "@LENS" -c 3 > /dev/null 2>"$errm" &
    local pm=$!
    sleep 2
    ip netns exec xdpargtest ping -c 5 -s 100 -W 1 10.99.0.1 >/dev/null 2>&1 || true
    wait $pm 2>/dev/null || true
    local cmatch=$(capture_count "$errm")

    # Swap the set to a length no frame carries; membership should now miss.
    # Track the swap so an empty set (a failed re-add) cannot false-pass the
    # nomatch half — it must genuinely hold a non-matching entry.
    local swapped=0
    if "$BINARY" set del "$pin" pkt_len=142 >/dev/null 2>&1 \
        && "$BINARY" set add "$pin" pkt_len=12345 >/dev/null 2>&1; then
        swapped=1
    fi
    local errn=$(mktemp)
    timeout 6 "$BINARY" -i va0 --func capture_point --set "LENS=$pin,key(pkt_len=arg:pkt_len)" --arg-filter "@LENS" > /dev/null 2>"$errn" &
    local pn=$!
    sleep 1
    ip netns exec xdpargtest ping -c 3 -s 100 -W 1 10.99.0.1 >/dev/null 2>&1 || true
    sleep 2
    kill $pn 2>/dev/null; wait $pn 2>/dev/null || true
    local cnomatch=$(capture_count "$errn")

    local ranm=0 rann=0
    grep -q "packets captured" "$errm" && ranm=1
    grep -q "packets captured" "$errn" && rann=1

    echo "argfilter_set match=$cmatch nomatch=$cnomatch swapped=$swapped ranm=$ranm rann=$rann stderr_m=$(cat "$errm") stderr_n=$(cat "$errn")" >&2
    rm -f "$errm" "$errn" "$pin"
    "$SCRIPT_DIR/cleanup_argcap.sh" 2>/dev/null || true
    [[ "$swapped" -eq 1 && "$ranm" -eq 1 && "$rann" -eq 1 && "$cmatch" -ge 3 && "$cnomatch" -eq 0 ]]
}

test_graceful_shutdown() {
    require_bpftool || return 1
    local prog_id_before=$(bpftool prog show name xdp_pass 2>/dev/null | head -1 | awk '{print $1}' | tr -d ':')

    timeout 5 "$BINARY" -i veth0 -c 1 > /dev/null 2>/dev/null &
    local pid=$!
    sleep 2
    send_packets 3
    wait $pid 2>/dev/null || true

    local prog_id_after=$(bpftool prog show name xdp_pass 2>/dev/null | head -1 | awk '{print $1}' | tr -d ':')
    echo "before=$prog_id_before after=$prog_id_after" >&2
    [[ -n "$prog_id_after" && "$prog_id_before" == "$prog_id_after" ]]
}

# --- main ---

echo "Checking binary..."
if [[ ! -x "$BINARY" ]]; then
    red "Binary not found: $BINARY"
    red "Run 'go build -o bpf-ninja ./cmd/bpf-ninja/' first"
    exit 1
fi

echo "Setting up test environment..."
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
run_test "graceful_shutdown"       test_graceful_shutdown

echo ""
echo "Cleaning up..."
"$SCRIPT_DIR/cleanup.sh" 2>/dev/null || true

echo ""
echo "Results: $(green "$PASS passed"), $(red "$FAIL failed"), $SKIP skipped"
[[ $FAIL -eq 0 ]]
