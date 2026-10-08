#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_steam_setup_dropin.sh
#
# What `lota-steam-setup --install-systemd-dropin` does to a running host.
# The drop-in it writes is read at agent startup, so it changes nothing
# until the next boot -- and restarting the agent to make it land sooner
# spends the boot's PCR 14 commitment, which stops the host attesting
# until it reboots anyway. `--verify` says exactly that to an operator,
# so the verb must not do it.
#
# Requires:
#   - bash, and a writable temp directory
#
# Runs unprivileged: LOTA_SETUP_DROPIN_DIR points the verb at a directory
# the caller owns, which is also why it touches no systemd on this host.

set -euo pipefail

# The assertions grep the script's own messages
export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
SETUP="$REPO_DIR/scripts/lota-steam-setup"

if [[ ! -x "$SETUP" ]]; then
    echo "[steam-setup-dropin] missing artifact: $SETUP" >&2
    exit 2
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

failures=0

check() {
    local msg="$1"
    shift
    if "$@"; then
	echo "PASS: $msg"
    else
	echo "FAIL: $msg"
	failures=$((failures + 1))
    fi
}

says() { grep -qi -- "$2" <<<"$1"; }
denies() { ! grep -qi -- "$2" <<<"$1"; }

# A systemctl that records what it was asked to do and answers nothing.
# The verb must be able to run to completion without any of these calls
# reaching a unit on the machine the test runs on.
mkdir -p "$WORK_DIR/bin"
cat >"$WORK_DIR/bin/systemctl" <<'STUB'
#!/bin/bash
printf '%s\n' "$*" >>"$SYSTEMCTL_CALLS"
exit 0
STUB
chmod 0755 "$WORK_DIR/bin/systemctl"

export SYSTEMCTL_CALLS="$WORK_DIR/systemctl.calls"
: >"$SYSTEMCTL_CALLS"

dropin_dir="$WORK_DIR/lota-agent.service.d"
dropin="$dropin_dir/10-xdg-runtime.conf"

rc=0
out=$(PATH="$WORK_DIR/bin:$PATH" \
	  LOTA_SETUP_DROPIN_DIR="$dropin_dir" \
	  SUDO_UID=1234 \
	  "$SETUP" --install-systemd-dropin 2>&1) || rc=$?

check "the verb succeeds against a redirected drop-in directory" \
      test "$rc" -eq 0
check "it writes the drop-in it names" test -f "$dropin"
check "the drop-in pins the operator's runtime directory" \
      grep -qx 'Environment=XDG_RUNTIME_DIR=/run/user/1234' "$dropin"
check "the drop-in is world-readable, as systemd needs" \
      test "$(stat -c '%a' "$dropin" 2>/dev/null)" = "644"

# Restarting the socket unit propagates into the service -- the socket Triggers=
# it and the service Requires= the socket -- so the stop runs
# ExecStop=lota-agent --shutdown and the boot commitment is spent.
# Nothing about writing a file that is read at startup needs it.
check "no unit is restarted" \
      denies "$(cat "$SYSTEMCTL_CALLS")" 'restart'
check "no unit is stopped" \
      denies "$(cat "$SYSTEMCTL_CALLS")" 'stop'
check "the agent is not touched at all" \
      denies "$(cat "$SYSTEMCTL_CALLS")" 'lota-agent'

# What the operator is owed instead: the same sentence --register-uid already
# gives them, since the two verbs configure the same listener by different
# roads and must not disagree about when it appears.
check "the verb says the drop-in takes effect at the next boot" \
      says "$out" 'next boot'
check "the verb says nothing it does stops the running agent" \
      says "$out" 'nothing here stops it'
check "the verb does not claim the listener is already there" \
      denies "$out" 'drop-in active'

if [[ $failures -gt 0 ]]; then
    echo ""
    echo "--- verb output ---"
    printf '%s\n' "$out"
    echo "--- systemctl calls ---"
    cat "$SYSTEMCTL_CALLS"
    echo ""
    echo "[steam-setup-dropin] $failures check(s) failed"
    exit 1
fi

echo "[steam-setup-dropin] all checks passed"
