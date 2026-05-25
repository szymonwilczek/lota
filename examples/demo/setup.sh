#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Paced operator runner for the live demo.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
EXAMPLES_BIN="$BUILD_DIR/examples"

LISTEN_ADDR="${LOTA_DEMO_LISTEN:-127.0.0.1:7443}"
SERVER_URL="${LOTA_DEMO_SERVER_URL:-http://$LISTEN_ADDR}"
GAME_ID="${LOTA_DEMO_GAME_ID:-trust-pong}"
INTERVAL_SEC="${LOTA_DEMO_INTERVAL_SEC:-5}"
TPM_PORT="${LOTA_DEMO_TPM_PORT:-23221}"
TPM_CTRL_PORT=""

DRY_RUN=0
NO_BUILD=0
AUTO_YES=0
KEEP_TMP=0

TMP_DIR=""
LOG_DIR=""
TPM_DIR=""
RUNTIME_DIR=""
AIK_DIR=""
AIK_PEM=""
TCTI=""
AGENT_STARTED=0

PIDS=()

usage() {
	cat <<EOF
Usage: $0 [--dry-run] [--yes] [--no-build] [--keep-tmp]
          [--listen HOST:PORT] [--game-id ID] [--interval SEC]
          [--tpm-port PORT]

Runs the local swtpm-backed demo chain:
  make all && make examples
  swtpm sandbox
  lota-agent --test-signed
  demo_server
  demo_anticheat
  trust_pong

The real run needs root because the current agent test server binds
/run/lota/lota.sock. Use: sudo -E examples/demo/setup.sh
EOF
}

log() {
	printf '\n==> %s\n' "$*"
}

note() {
	printf '    %s\n' "$*"
}

die() {
	printf 'setup.sh: %s\n' "$*" >&2
	exit 1
}

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

need_file() {
	[ -e "$1" ] || die "missing required artifact: $1"
}

need_artifact() {
	if [ "$DRY_RUN" -eq 1 ]; then
		note "expects artifact: $1"
		return 0
	fi
	need_file "$1"
}

pause_gate() {
	if [ "$DRY_RUN" -eq 1 ] || [ "$AUTO_YES" -eq 1 ]; then
		return
	fi
	read -r -p "press ENTER to continue: " _ || true
}

run_or_print() {
	if [ "$DRY_RUN" -eq 1 ]; then
		printf '+'
		printf ' %q' "$@"
		printf '\n'
		return 0
	fi
	"$@"
}

cleanup() {
	trap - EXIT INT TERM

	if [ "$AGENT_STARTED" -eq 1 ] && [ -x "$BUILD_DIR/lota-agent" ]; then
		"$BUILD_DIR/lota-agent" --shutdown >/dev/null 2>&1 || true
	fi

	for i in "${!PIDS[@]}"; do
		pid="${PIDS[$i]}"
		if kill -0 "$pid" >/dev/null 2>&1; then
			kill "$pid" >/dev/null 2>&1 || true
		fi
	done

	for pid in "${PIDS[@]}"; do
		wait "$pid" >/dev/null 2>&1 || true
	done

	if [ -n "$TPM_DIR" ] && [ -f "$TPM_DIR/swtpm.pid" ]; then
		pid="$(cat "$TPM_DIR/swtpm.pid" 2>/dev/null || true)"
		if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
			kill "$pid" >/dev/null 2>&1 || true
			wait "$pid" >/dev/null 2>&1 || true
		fi
	fi

	if [ -n "$TMP_DIR" ] && [ "$KEEP_TMP" -eq 0 ]; then
		rm -rf "$TMP_DIR"
	elif [ -n "$TMP_DIR" ]; then
		note "kept tmp dir: $TMP_DIR"
	fi
}

start_bg() {
	local name="$1"
	local log_file
	shift

	log_file="$LOG_DIR/$name.log"
	note "$name log: $log_file"

	if [ "$DRY_RUN" -eq 1 ]; then
		printf '+'
		printf ' %q' "$@"
		printf ' >%q 2>&1 &\n' "$log_file"
		return 0
	fi

	"$@" >"$log_file" 2>&1 &
	PIDS+=("$!")
}

ensure_pid_alive() {
	local name="$1"
	local pid="$2"
	local log_file="$3"

	if ! kill -0 "$pid" >/dev/null 2>&1; then
		if [ -f "$log_file" ]; then
			tail -n 40 "$log_file" >&2 || true
		fi
		die "$name exited early"
	fi
}

wait_for_socket() {
	local path="$1"
	local name="$2"
	local pid="$3"
	local log_file="$4"

	for _ in $(seq 1 20); do
		[ -S "$path" ] && return 0
		ensure_pid_alive "$name" "$pid" "$log_file"
		sleep 1
	done

	tail -n 40 "$log_file" >&2 || true
	die "timeout waiting for socket $path"
}

wait_for_http() {
	local url="$1"
	local name="$2"
	local pid="$3"
	local log_file="$4"

	for _ in $(seq 1 20); do
		if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
			return 0
		fi
		ensure_pid_alive "$name" "$pid" "$log_file"
		sleep 1
	done

	tail -n 40 "$log_file" >&2 || true
	die "timeout waiting for HTTP endpoint $url"
}

export_aik_public() {
	for _ in $(seq 1 30); do
		if TPM2TOOLS_TCTI="$TCTI" tpm2_readpublic -c 0x81010002 \
			-f pem -o "$AIK_PEM" >"$LOG_DIR/tpm2_readpublic.log" 2>&1; then
			return 0
		fi
		sleep 1
	done

	tail -n 40 "$LOG_DIR/tpm2_readpublic.log" >&2 || true
	die "could not export AIK public key from swtpm"
}

parse_args() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--dry-run)
			DRY_RUN=1
			;;
		--yes)
			AUTO_YES=1
			;;
		--no-build)
			NO_BUILD=1
			;;
		--keep-tmp)
			KEEP_TMP=1
			;;
		--listen)
			[ "$#" -ge 2 ] || die "--listen requires HOST:PORT"
			LISTEN_ADDR="$2"
			SERVER_URL="http://$LISTEN_ADDR"
			shift
			;;
		--game-id)
			[ "$#" -ge 2 ] || die "--game-id requires ID"
			GAME_ID="$2"
			shift
			;;
		--interval)
			[ "$#" -ge 2 ] || die "--interval requires seconds"
			INTERVAL_SEC="$2"
			shift
			;;
		--tpm-port)
			[ "$#" -ge 2 ] || die "--tpm-port requires PORT"
			TPM_PORT="$2"
			shift
			;;
		--help | -h)
			usage
			exit 0
			;;
		*)
			die "unknown argument: $1"
			;;
		esac
		shift
	done
}

check_inputs() {
	need_cmd make
	need_cmd curl
	need_cmd swtpm
	need_cmd swtpm_setup
	need_cmd tpm2_getrandom
	need_cmd tpm2_readpublic

	case "$INTERVAL_SEC" in
	'' | *[!0-9]*)
		die "--interval must be a positive integer"
		;;
	esac
	[ "$INTERVAL_SEC" -gt 0 ] || die "--interval must be > 0"

	case "$TPM_PORT" in
	'' | *[!0-9]*)
		die "--tpm-port must be a TCP port"
		;;
	esac
	if [ "$TPM_PORT" -le 0 ] || [ "$TPM_PORT" -ge 65535 ]; then
		die "--tpm-port must be in range 1..65534"
	fi
	if [ -n "${LOTA_DEMO_TPM_CTRL_PORT:-}" ]; then
		die "LOTA_DEMO_TPM_CTRL_PORT is not supported; swtpm control port is --tpm-port + 1"
	fi
	TPM_CTRL_PORT=$((TPM_PORT + 1))

	if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
		die "real run needs root for /run/lota/lota.sock; use sudo -E $0"
	fi

	if [ "$DRY_RUN" -eq 0 ] && [ -S /run/lota/lota.sock ]; then
		die "/run/lota/lota.sock already exists; stop the existing agent before the demo"
	fi
}

init_tmp() {
	TMP_DIR="$(mktemp -d /tmp/lota-demo.XXXXXX)"
	LOG_DIR="$TMP_DIR/logs"
	TPM_DIR="$TMP_DIR/swtpm"
	RUNTIME_DIR="$TMP_DIR/runtime"
	AIK_DIR="$TMP_DIR/aik"
	AIK_PEM="$AIK_DIR/aik.pem"
	TCTI="swtpm:host=127.0.0.1,port=$TPM_PORT"

	mkdir -p "$LOG_DIR" "$TPM_DIR" "$RUNTIME_DIR" "$AIK_DIR"
	trap cleanup EXIT INT TERM
}

build_all() {
	log "Step 1/7: build agent, verifier, SDKs, and examples"
	if [ "$NO_BUILD" -eq 1 ]; then
		note "skipping build because --no-build was passed"
		return
	fi
	run_or_print make -C "$ROOT_DIR" all
	run_or_print make -C "$ROOT_DIR" examples
}

start_swtpm() {
	log "Step 2/7: start isolated swtpm sandbox"
	note "TPM state: $TPM_DIR"
	note "TCTI: $TCTI"

	run_or_print swtpm_setup --tpm2 --tpmstate "$TPM_DIR" --createek \
		--decryption --overwrite

	if [ "$DRY_RUN" -eq 1 ]; then
		run_or_print swtpm socket --tpm2 --tpmstate "dir=$TPM_DIR" \
			--flags startup-clear \
			--ctrl "type=tcp,port=$TPM_CTRL_PORT,bindaddr=127.0.0.1" \
			--server "type=tcp,port=$TPM_PORT,bindaddr=127.0.0.1" \
			--daemon --pid "file=$TPM_DIR/swtpm.pid"
		return
	fi

	swtpm socket --tpm2 --tpmstate "dir=$TPM_DIR" \
		--flags startup-clear \
		--ctrl "type=tcp,port=$TPM_CTRL_PORT,bindaddr=127.0.0.1" \
		--server "type=tcp,port=$TPM_PORT,bindaddr=127.0.0.1" \
		--daemon --pid "file=$TPM_DIR/swtpm.pid" \
		>"$LOG_DIR/swtpm.log" 2>&1

	TPM2TOOLS_TCTI="$TCTI" tpm2_getrandom 4 -o "$TMP_DIR/tpm.rand" \
		>"$LOG_DIR/tpm2_getrandom.log" 2>&1
}

verify_demo_artifacts() {
	log "Step 3/7: verify demo artifacts"
	need_artifact "$BUILD_DIR/lota-agent"
	need_artifact "$EXAMPLES_BIN/demo_server"
	need_artifact "$EXAMPLES_BIN/demo_anticheat"
	need_artifact "$EXAMPLES_BIN/trust_pong"
	note "demo server doubles as the verifier for LACH heartbeats"
	note "logs will be written under $LOG_DIR"
}

start_agent() {
	local pid
	local log_file

	log "Step 4/7: start lota-agent against swtpm"
	start_bg agent env \
		LOTA_TCTI="$TCTI" \
		LOTA_AIK_META_PATH="$AIK_DIR/aik_meta.dat" \
		XDG_RUNTIME_DIR="$RUNTIME_DIR" \
		"$BUILD_DIR/lota-agent" --test-signed

	if [ "$DRY_RUN" -eq 1 ]; then
		return
	fi

	AGENT_STARTED=1
	pid="${PIDS[-1]}"
	log_file="$LOG_DIR/agent.log"
	wait_for_socket /run/lota/lota.sock agent "$pid" "$log_file"
	export_aik_public
	note "exported AIK public key: $AIK_PEM"
}

start_demo_server() {
	local pid
	local log_file

	log "Step 5/7: start demo verifier/server"
	start_bg demo_server "$EXAMPLES_BIN/demo_server" \
		--listen "$LISTEN_ADDR" \
		--aik-pub "$AIK_PEM" \
		--expected-games "$GAME_ID=lota-demo-CS2-clone"

	if [ "$DRY_RUN" -eq 1 ]; then
		return
	fi

	pid="${PIDS[-1]}"
	log_file="$LOG_DIR/demo_server.log"
	wait_for_http "$SERVER_URL/state?game_id=$GAME_ID" demo_server "$pid" \
		"$log_file"
}

start_heartbeat() {
	local once_log

	log "Step 6/7: launch demo_anticheat heartbeat producer"
	once_log="$LOG_DIR/demo_anticheat_once.log"

	if [ "$DRY_RUN" -eq 1 ]; then
		run_or_print "$EXAMPLES_BIN/demo_anticheat" \
			--server "$SERVER_URL/heartbeat" \
			--game-id "$GAME_ID" \
			--interval "$INTERVAL_SEC" \
			--once
		start_bg demo_anticheat "$EXAMPLES_BIN/demo_anticheat" \
			--server "$SERVER_URL/heartbeat" \
			--game-id "$GAME_ID" \
			--interval "$INTERVAL_SEC"
		return
	fi

	if ! "$EXAMPLES_BIN/demo_anticheat" \
		--server "$SERVER_URL/heartbeat" \
		--game-id "$GAME_ID" \
		--interval "$INTERVAL_SEC" \
		--once >"$once_log" 2>&1; then
		tail -n 40 "$once_log" >&2 || true
		die "first heartbeat did not return TRUSTED"
	fi

	start_bg demo_anticheat "$EXAMPLES_BIN/demo_anticheat" \
		--server "$SERVER_URL/heartbeat" \
		--game-id "$GAME_ID" \
		--interval "$INTERVAL_SEC"
}

launch_game() {
	local demo_user
	local demo_uid
	local user_runtime
	local -a game_env
	local -a cmd

	log "Step 7/7: launch trust_pong"
	note "close the window or press Esc/Q to tear the demo down"

	game_env=(
		"DISPLAY=${DISPLAY:-}"
		"WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-}"
		"XAUTHORITY=${XAUTHORITY:-}"
		"DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-}"
	)

	demo_user="${SUDO_USER:-}"
	if [ -n "$demo_user" ] && [ "$demo_user" != "root" ] &&
		command -v sudo >/dev/null 2>&1; then
		demo_uid="$(id -u "$demo_user")"
		user_runtime="${XDG_RUNTIME_DIR:-/run/user/$demo_uid}"
		game_env+=("XDG_RUNTIME_DIR=$user_runtime")
		cmd=(sudo -u "$demo_user" env "${game_env[@]}"
			"$EXAMPLES_BIN/trust_pong"
			--server "$SERVER_URL"
			--game-id "$GAME_ID")
	else
		game_env+=("XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-$RUNTIME_DIR}")
		cmd=(env "${game_env[@]}"
			"$EXAMPLES_BIN/trust_pong"
			--server "$SERVER_URL"
			--game-id "$GAME_ID")
	fi

	run_or_print "${cmd[@]}"
}

main() {
	parse_args "$@"
	check_inputs

	if [ "$DRY_RUN" -eq 0 ]; then
		init_tmp
	else
		TMP_DIR="/tmp/lota-demo.DRYRUN"
		LOG_DIR="$TMP_DIR/logs"
		TPM_DIR="$TMP_DIR/swtpm"
		RUNTIME_DIR="$TMP_DIR/runtime"
		AIK_DIR="$TMP_DIR/aik"
		AIK_PEM="$AIK_DIR/aik.pem"
		TCTI="swtpm:host=127.0.0.1,port=$TPM_PORT"
	fi

	build_all
	pause_gate
	start_swtpm
	pause_gate
	verify_demo_artifacts
	pause_gate
	start_agent
	pause_gate
	start_demo_server
	pause_gate
	start_heartbeat
	pause_gate
	launch_game
}

main "$@"
