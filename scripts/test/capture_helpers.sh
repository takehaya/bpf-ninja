#!/bin/bash

# A missing summary is an error, not a capture count of zero. Exactly one
# shutdown summary must be present; diagnostics containing these words do not
# count as summaries.
capture_count() {
    awk '
        /^[0-9]+ packets captured( \(raw-dump\))?$/ { count=$1; summaries++ }
        END { if (summaries != 1) exit 1; print count }
    ' "$1"
}

# capture_run <stderr-file> <count|signal> <sender-function> <packet-count> <args...>
# Send only after the reader announces readiness. The timeout is a failure even
# if the child prints a summary while handling the timeout signal.
capture_run() {
    local err=$1 mode=$2 sender=$3 packets=$4
    shift 4
    local pid child attempt pidfile rc=0 ready=0 failed=0
    pidfile=$(mktemp)
    # Record the actual child PID before exec. Signal that child, so timeout
    # returns its real exit status instead of masking it with its own 143.
    timeout --kill-after=2s "${CAPTURE_TIMEOUT:-10}s" bash -c '
        printf "%s\n" "$BASHPID" > "$1"
        shift
        exec "$@"
    ' capture-child "$pidfile" "$BINARY" "$@" > /dev/null 2>"$err" &
    pid=$!
    for ((attempt=0; attempt<${CAPTURE_READY_POLLS:-100}; attempt++)); do
        if ! kill -0 "$pid" 2>/dev/null; then
            break
        fi
        if grep -q '^capturing (.*)\.\.\.$' "$err"; then
            ready=1
            break
        fi
        sleep 0.05
    done
    child=$(cat "$pidfile")
    [[ $child =~ ^[0-9]+$ ]] || child=$pid
    if [[ $ready -ne 1 ]]; then
        echo "capture did not become ready" >&2
        failed=1
    elif ! "$sender" "$packets"; then
        echo "test traffic failed" >&2
        failed=1
    fi
    if [[ $failed -eq 1 ]]; then
        kill -TERM "$child" 2>/dev/null || true
    elif [[ $mode == signal ]]; then
        sleep "${CAPTURE_SETTLE:-0.2}"
        # A negative case must remain alive until we request its shutdown.
        if ! kill -TERM "$child" 2>/dev/null; then
            echo "capture exited before the requested shutdown" >&2
            failed=1
        fi
    elif [[ $mode != count ]]; then
        echo "unknown capture mode: $mode" >&2
        failed=1
        kill -TERM "$child" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || rc=$?
    rm -f "$pidfile"
    # Both natural and requested graceful shutdown must return 0.
    # Timeout expiry (124) and signal termination without handling are errors.
    if [[ $rc -ne 0 ]]; then
        echo "capture exited with status $rc" >&2
        failed=1
    fi
    if ! capture_count "$err" >/dev/null; then
        echo "capture shutdown summary missing or ambiguous" >&2
        failed=1
    fi
    if [[ $failed -ne 0 ]]; then
        cat "$err" >&2
        return 1
    fi
}
