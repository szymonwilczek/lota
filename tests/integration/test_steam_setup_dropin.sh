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

. "$(dirname "$0")/../lib/test.sh"
test_begin "steam setup dropin"

# The assertions grep the script's own messages
export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
SETUP="$REPO_DIR/scripts/lota-steam-setup"

if [[ ! -x "$SETUP" ]]; then
    FAIL "missing artifact: %s" "$SETUP"
    test_end
fi

WORK_DIR=$(mktemp -d)
test_cleanup 'rm -rf "$WORK_DIR"'

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

TEST "the verb succeeds against a redirected drop-in directory"
test "$rc" -eq 0 || FAIL "exit %d: %s" "$rc" "$out"
TEST "it writes the drop-in it names"
test -f "$dropin" || FAIL
TEST "the drop-in pins the operator's runtime directory"
grep -qx 'Environment=XDG_RUNTIME_DIR=/run/user/1234' "$dropin" || FAIL
TEST "the drop-in is world-readable, as systemd needs"
test "$(stat -c '%a' "$dropin" 2>/dev/null)" = "644" || FAIL

# Restarting the socket unit propagates into the service -- the socket Triggers=
# it and the service Requires= the socket -- so the stop runs
# ExecStop=lota-agent --shutdown and the boot commitment is spent.
# Nothing about writing a file that is read at startup needs it.
TEST "no unit is restarted"
denies "$(cat "$SYSTEMCTL_CALLS")" 'restart' ||
    FAIL "%s" "$(cat "$SYSTEMCTL_CALLS")"
TEST "no unit is stopped"
denies "$(cat "$SYSTEMCTL_CALLS")" 'stop' ||
    FAIL "%s" "$(cat "$SYSTEMCTL_CALLS")"
TEST "the agent is not touched at all"
denies "$(cat "$SYSTEMCTL_CALLS")" 'lota-agent' ||
    FAIL "%s" "$(cat "$SYSTEMCTL_CALLS")"

# What the operator is owed instead: the same sentence --register-uid already
# gives them, since the two verbs configure the same listener by different
# roads and must not disagree about when it appears.
TEST "the verb says the drop-in takes effect at the next boot"
says "$out" 'next boot' || FAIL "%s" "$out"
TEST "the verb says nothing it does stops the running agent"
says "$out" 'nothing here stops it' || FAIL "%s" "$out"
TEST "the verb does not claim the listener is already there"
denies "$out" 'drop-in active' || FAIL "%s" "$out"

TEST "the usage names the directory the drop-in goes in"
says "$("$SETUP" --help)" '/etc/systemd/system/lota-agent.service.d)' ||
    FAIL "%s" "$("$SETUP" --help)"

# Both verbs at once: refused before either writes anything.
rm -rf "$dropin_dir"
rc=0
both_out=$(PATH="$WORK_DIR/bin:$PATH" \
	   LOTA_SETUP_DROPIN_DIR="$dropin_dir" \
	   SUDO_UID=1234 \
	   "$SETUP" --install-systemd-dropin --register-uid 2>&1) || rc=$?
TEST "the two verbs together are refused"
test "$rc" -eq 1 || FAIL "exit %d: %s" "$rc" "$both_out"
TEST "the refusal says they are alternatives"
says "$both_out" 'are alternatives' || FAIL "%s" "$both_out"
TEST "neither verb wrote anything"
test ! -e "$dropin_dir" || FAIL

# A directory that cannot be created ends the verb, with no success line.
: >"$WORK_DIR/not-a-dir"
rc=0
bad_out=$(PATH="$WORK_DIR/bin:$PATH" \
	  LOTA_SETUP_DROPIN_DIR="$WORK_DIR/not-a-dir/lota-agent.service.d" \
	  SUDO_UID=1234 \
	  "$SETUP" --install-systemd-dropin 2>&1) || rc=$?
TEST "an unwritable drop-in directory fails the verb"
test "$rc" -eq 1 || FAIL "exit %d: %s" "$rc" "$bad_out"
TEST "the failure is named"
says "$bad_out" '\[FAIL\] cannot create' || FAIL "%s" "$bad_out"
TEST "no success line follows it"
denies "$bad_out" 'drop-in installed' || FAIL "%s" "$bad_out"

test_end
