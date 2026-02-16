#!/bin/bash
set -e

SCRIPT_DIR="$(dirname "$0")"
if [ -f "$SCRIPT_DIR/.env" ]; then
    export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
else
    echo "ERROR: .env file not found in $SCRIPT_DIR!"
    exit 1
fi

REMOTE_HOST="${REMOTE_HOST:-dionisus}"
REMOTE_DIR="${REMOTE_GO_FUZZ_DIR:-/home/wolfie/lota-go-fuzz}"

echo "=== Checking Fuzz Status on $REMOTE_HOST ==="

ssh -t "$REMOTE_HOST" "
    echo '--- Running Fuzz Processes ---'
    pgrep -a fuzz_ | grep -v 'run_fuzzers.sh' || echo 'No fuzzers running!'
    
    echo ''
    echo '--- Log Sizes ---'
    ls -lh $REMOTE_DIR/logs/*.log 2>/dev/null
    
    echo ''
    echo '--- PANICS / CRASHES ---'
    if grep -r 'panic:' $REMOTE_DIR/logs/; then
        echo '!!! CRITICAL: PANIC DETECTED IN LOGS !!!'
    else
        echo 'No panics found in logs.'
    fi
    
    if [ -d '$REMOTE_DIR/testdata' ]; then
        echo 'Checking for crash dump files...'
        find $REMOTE_DIR/testdata -type f | grep -v 'corpus' || echo 'No crash dump files found.'
    fi
"
