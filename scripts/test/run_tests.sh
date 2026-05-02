#!/bin/bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY="$PROJECT_DIR/xdp-ninja"
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
    # xdp-ninja の stderr から "N packets captured" を抽出
    grep -oP '\d+(?= packets captured)' "$1" 2>/dev/null || echo 0
}

# run_count_test <expected-min> <xdp-ninja-args...>
# Runs xdp-ninja with the given args in the background, sends 5 pings
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

# run_nomatch_test <xdp-ninja-args...>
# Runs a short-lived xdp-ninja that the ping traffic should not match,
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

# run_pcap_test <xdp-ninja-args...>
# Captures to a pcap file and asserts tcpdump can parse it back.
run_pcap_test() {
    local pcap=$(mktemp --suffix=.pcap)
    local err=$(mktemp)
    timeout 10 "$BINARY" -w "$pcap" "$@" 2>"$err" &
    local pid=$!
    sleep 2
    send_packets 5
    wait $pid 2>/dev/null || true
    tcpdump -r "$pcap" -c 1 > /dev/null 2>&1
    local result=$?
    rm -f "$pcap" "$err"
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
    # tshark でインターフェース名に xdp: が含まれるか確認
    # tshark がなければ tcpdump で読めることだけ確認
    if command -v tshark &>/dev/null; then
        tshark -r "$pcap" -T fields -e frame.interface_name 2>/dev/null | grep -q "xdp:"
        local result=$?
    else
        tcpdump -r "$pcap" -c 1 > /dev/null 2>&1
        local result=$?
    fi
    rm -f "$pcap" "$err"
    [[ $result -eq 0 ]]
}

test_dsl_entry_filter_match()    { run_count_test 3 --dsl -i veth0 -c 3 "eth/ipv4/icmp"; }
test_dsl_entry_predicate_match() { run_count_test 3 --dsl -i veth0 -c 3 "eth/ipv4/icmp[type==8]"; }
test_dsl_entry_filter_nomatch()  { run_nomatch_test --dsl -i veth0 "eth/ipv4/tcp"; }
test_dsl_capture_headers()       { run_pcap_test --dsl -i veth0 -c 3 "eth/ipv4/icmp capture headers+32"; }

# Dummy XDP returns XDP_PASS (=2); this exercises the fexit action atom
# codegen against a known return value.
test_dsl_exit_action() { run_count_test 3 --dsl -i veth0 --mode exit -c 3 "eth/ipv4/icmp where action == XDP_PASS"; }

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
    red "Run 'go build -o xdp-ninja ./cmd/xdp-ninja/' first"
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
run_test "graceful_shutdown"       test_graceful_shutdown

echo ""
echo "Cleaning up..."
"$SCRIPT_DIR/cleanup.sh" 2>/dev/null || true

echo ""
echo "Results: $(green "$PASS passed"), $(red "$FAIL failed"), $SKIP skipped"
[[ $FAIL -eq 0 ]]
