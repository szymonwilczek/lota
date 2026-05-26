# CS2 / Proton hook integration

This walk-through validates the LOTA Wine/Proton hook against a real
Counter-Strike 2 install on Steam. It does not bundle any game asset
and does not modify the game binary; the hook attaches through
`LD_PRELOAD` from Steam's launch-options field so that every game
launch carries the attestation bridge for the lifetime of the Wine
prefix.

Counter-Strike 2 (Steam app id `730`, formerly CS:GO) runs under
Proton on Linux. The matrix below names the Proton releases the hook
has been exercised against; older Proton lines may also work but are
not tracked.

| Proton             | Hook tested |
| ------------------ | ----------- |
| Proton 9.0-4       | yes         |
| Proton Experimental| yes         |
| Proton 8.x         | no          |

## Prerequisites

1. **Working LOTA install** with the agent running and reachable on
   `/run/lota/lota.sock`. The agent does not need to be in enforce
   mode for the hook to attach; the hook reads attestation, it does
   not gate execve.

   ```sh
   systemctl status lota-agent.service
   ls -l /run/lota/lota.sock
   ```

2. **Built and installed artefacts.** `sudo make install` deploys
   the hook library to `/usr/lib64/liblota_wine_hook.so` and the
   wrapper scripts to `/usr/bin/lota-{proton-hook,steam-setup}`.

3. **Steam Runtime is the host's Steam**, not a Flatpak/Snap copy.
   The Flatpak Steam sandbox blocks `LD_PRELOAD` paths outside the
   container, so the hook cannot reach `liblota_wine_hook.so` from
   `/usr/lib64`. If you must use Flatpak Steam, install the hook
   inside the Steam Flatpak runtime or skip this walk-through.

4. **CS2 installed** via Steam and launched at least once so Proton
   has provisioned the Wine prefix.

## One-time host setup

1. **Create the `lota` group** and add the operator user to it. The
   agent socket is owned `root:lota mode 0660`, and the Steam
   pressure-vessel container inherits the launching user's
   supplementary group set, so the hook can only `connect()` to
   the socket when the user is in the `lota` group:

   ```sh
   sudo groupadd --system lota
   sudo usermod -aG lota "$USER"
   # `newgrp lota` activates the group in the current shell
   # without a full re-login; restart Steam from that shell so
   # CS2 inherits the new group.
   ```

2. **Start the agent with the operator's `XDG_RUNTIME_DIR`** so it
   creates the container-accessible secondary listener at
   `$XDG_RUNTIME_DIR/lota/lota.sock`. The systemd unit runs the
   agent as root and ignores the operator's runtime dir by
   default, so for the integration test launch it directly:

   ```sh
   sudo systemctl stop lota-agent.socket lota-agent.service
   sudo env XDG_RUNTIME_DIR=/run/user/"$(id -u)" \
       /usr/bin/lota-agent --test-ipc
   ```

   The startup banner names both listeners; the second one is the
   path the hook will use:

   ```
   IPC listening on /run/lota/lota.sock
   IPC extra listener on /run/user/1000/lota/lota.sock
   ```

   `--test-ipc` is a no-TPM simulated-attested mode that proves
   the IPC bridge end-to-end without a TPM quote; `--test-signed`
   takes the same shape but routes through the real TPM, and the
   full systemd unit is for the eventual production path once the
   `Environment=XDG_RUNTIME_DIR=...` wiring lands there.

3. **Run `lota-steam-setup`** under the operator account (not
   root) to confirm the runtime preconditions:

   ```sh
   lota-steam-setup
   ```

   The script verifies `XDG_RUNTIME_DIR`, the `lota` group
   membership, the hook library at `/usr/lib64/`, and prints the
   exact Steam launch-options string for the next step.
   `lota-steam-setup --verify` re-runs the checks without
   modifying anything.

## Wire it into CS2

1. Open Steam, right-click `Counter-Strike 2` -> `Properties...`.
2. Under **General -> Launch options**, paste:

   ```
   PRESSURE_VESSEL_FILESYSTEMS_RW=/run/user/1000/lota LOTA_HOOK_SOCKET=/run/user/1000/lota/lota.sock LOTA_HOOK_LOG_LEVEL=info lota-proton-hook %command%
   ```

   Replace `1000` with the operator's UID (`id -u`). The three
   environment variables carry the integration glue:

   - `PRESSURE_VESSEL_FILESYSTEMS_RW=<dir>` tells Steam's
     pressure-vessel container manager to bind-mount the named
     host directory into the container with the same path. By
     default pressure-vessel replaces `/run/user/<uid>` with a
     fresh tmpfs and selectively re-binds known sockets
     (pipewire, pulseaudio, dbus); the LOTA socket is not in
     that allowlist and is therefore invisible inside the
     container unless this variable adds the parent directory.
   - `LOTA_HOOK_SOCKET=<path>` points the hook at the
     user-scoped secondary listener instead of the
     root-namespace `/run/lota/lota.sock` (which is not visible
     in the container at all).
   - `LOTA_HOOK_LOG_LEVEL=info` keeps the constructor / refresh
     events in Steam's `console-linux.txt`; raise to `debug`
     while bringing the integration up, drop to `warn` once it
     is stable.

3. Confirm Compatibility -> **Force the use of a specific Steam
   Play compatibility tool** is set to Proton 9.0-4 or Proton
   Experimental.
4. Close the dialog. The next CS2 launch is hooked.

For a one-off verification without persisting the launch option,
the same wiring is reachable from the command line:

```sh
LOTA_HOOK_LOG_LEVEL=info \
LOTA_HOOK_SOCKET=/run/user/"$(id -u)"/lota/lota.sock \
PRESSURE_VESSEL_FILESYSTEMS_RW=/run/user/"$(id -u)"/lota \
lota-proton-hook steam-runtime-launch-client -- steam://rungameid/730
```

## What the hook produces at runtime

Constructor-side (in the Wine/Proton process), the hook connects to
the LOTA agent, asks for a freshly attested gaming token, and
atomically writes three files under `$XDG_RUNTIME_DIR/lota/`:

| File          | Format     | Owner                            |
| ------------- | ---------- | -------------------------------- |
| `lota-status` | text       | hook state, last refresh, errors |
| `lota-token.bin` | binary  | raw gaming SDK attestation token |
| `lota-snapshot.bin` | binary | combined flags + token blob   |

A background refresh thread re-queries the agent every
`LOTA_HOOK_REFRESH_SEC` seconds (default 60) and rewrites the files
atomically. The destructor unlinks them on clean shutdown so a
process crash leaves the files behind for post-mortem and a clean
exit leaves the directory empty.

Verify after launching CS2 (run from the operator account, not
root, so `$XDG_RUNTIME_DIR` resolves to the user's runtime dir):

```sh
ls -l   "$XDG_RUNTIME_DIR/lota/"
cat     "$XDG_RUNTIME_DIR/lota/lota-status"
```

A healthy run prints `LOTA_ATTESTED=1`, a non-zero
`LOTA_VALID_UNTIL` timestamp, and `LOTA_PID` matching the game
process. The `lota-token.bin` file size matches the
`LOTA_GAMING_MAX_TOKEN` budget exposed by the gaming SDK; the
binary is opaque to the operator but `xxd | head` is enough to
confirm it is not all-zeros. Under `--test-ipc` the agent refuses
`GET_TOKEN` because no `policy_digest` is loaded, so the binary
token file is empty -- the status file alone proves the IPC
bridge end-to-end; the binary token requires `--test-signed` or
the full daemon path.

The `lota-proton-hook` wrapper attaches the hook only to processes
whose executable lives outside the FHS system paths (`/usr/`,
`/bin`, `/sbin`, `/lib`, `/lib64`). Steam-tree binaries (the
`reaper`, `cs2`, Proton helpers) activate the hook; the launcher
shell, `basename`, `dirname`, `ldconfig`, and the rest of the
POSIX utility chain that Steam Runtime calls out to do not. The
filter is overridable through `LOTA_HOOK_ACTIVATE_PATH=<prefix-list>`
(positive pin) or `LOTA_HOOK_SKIP_PATH=<prefix-list>` (extend the
skip set for distros that keep utilities outside FHS, e.g.
`/nix/store/`).

## Hook environment overrides

The hook honours a small set of environment variables, all
documented in `include/lota_wine_hook.h`.

| Variable                     | Effect                                         |
| ---------------------------- | ---------------------------------------------- |
| `LOTA_HOOK_DISABLE=1`        | wrapper `exec`s the game without `LD_PRELOAD` |
| `LOTA_HOOK_LOG_LEVEL`        | `debug` / `info` / `warn` / `error` / `silent` |
| `LOTA_HOOK_TOKEN_DIR`        | override the token sink directory             |
| `LOTA_HOOK_REFRESH_SEC`      | seconds between agent re-queries (default 60) |
| `LOTA_HOOK_SOCKET`           | override the agent socket path                |
| `LOTA_HOOK_ACTIVATE_PATH`    | positive `/proc/self/exe` prefix pin          |
| `LOTA_HOOK_SKIP_PATH`        | extend the FHS system-path skip list          |

Set them on Steam's launch line, e.g.:

```
LOTA_HOOK_LOG_LEVEL=debug LOTA_HOOK_SOCKET=/run/user/1000/lota/lota.sock \
PRESSURE_VESSEL_FILESYSTEMS_RW=/run/user/1000/lota \
lota-proton-hook %command%
```

Logs are written to the game's stderr, which Steam captures under
`~/.steam/steam/logs/console_log.txt` and `stderr.txt` inside the
Proton prefix.

## Fallback when attestation is unavailable

The hook is designed to never wedge the game. If the agent is not
reachable, the hook logs the failure, leaves the token directory
empty, and lets the game keep running. The `lota-proton-hook`
wrapper has the same property at the launcher layer: if
`liblota_wine_hook.so` is missing from every standard path or if
`LOTA_HOOK_DISABLE=1` is exported, the wrapper writes a single
warning to stderr and `exec`s `%command%` unchanged so CS2 still
launches.

This matters for two operator scenarios:

- **Fresh install before host bring-up.** The wrapper does not
  block launch while the operator is still resolving the agent
  install. CS2 boots, the launch-option entry stays valid, and
  the next launch after the agent comes up picks up attestation
  automatically.
- **Live tamper of the hook artefact.** Removing
  `liblota_wine_hook.so` between launches degrades to the
  unhooked path on the next launch; the in-flight game keeps its
  process-loaded copy until exit. The agent's own measurements
  (boot commitment, runtime BPF telemetry) continue to fire
  whether or not the hook is loaded into the game.

## Caveats vs Valve Anti-Cheat (VAC)

VAC inspects loaded shared objects in the game process and flags
unrecognised `LD_PRELOAD` libraries on its own ban heuristics. The
hook is built for an EAC / BattlEye style integration where the
anti-cheat vendor explicitly allows the LOTA bridge; running it
against a competitive VAC-enabled CS2 server is therefore at the
operator's own risk. For the walk-through, exercise the
hook against a local **Practice with Bots** match or a community
server that does not enforce VAC. The hook itself never injects
into the network protocol; it only writes attestation artefacts to
disk that the host-side verifier consumes out-of-band.

## Troubleshooting

The hook logs every state transition as a `lota-hook: ...` line in
Steam's `~/.local/share/Steam/logs/console-linux.txt`. Tail that
file during a launch attempt and match against this table:

| Symptom in console-linux.txt                 | Root cause                                                                                                                                                                                                                                  |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lota-proton-hook: hook library not found`   | `make install` skipped, or installed to a non-standard `LIBDIR`. Set `LOTA_HOOK_LIB_PATH` to the actual `.so` path, or re-run `sudo install -m 755 build/liblota_wine_hook.so /usr/lib64/`.                                                |
| `hook active (pid=...)` repeated for shells / utilities | The hook was loaded with `LOTA_HOOK_ACTIVATE_PATH` set to a prefix that matches a system path, or `LOTA_HOOK_SKIP_PATH` was set in a way that overrides the FHS default. Drop the env override and let the built-in `/usr/, /bin/, /sbin/, /lib/, /lib64/` skip list apply. |
| `agent not available, retrying in 60s` from the game PID (`/proc/<pid>/exe` ends in `/cs2`) | The socket the hook is pointed at is not reachable inside the pressure-vessel container. The most common cause is that `PRESSURE_VESSEL_FILESYSTEMS_RW` is missing from the launch options, so the container's tmpfs view of `/run/user/<uid>` does not include the LOTA socket directory. |
| `connected to agent` followed by `get_token: Agent returned error` | Agent reachable but refusing token issuance. Under `--test-ipc` this is expected (`policy_digest is not set`). Switch to `--test-signed` plus a loaded policy for the full token path. |
| No files appear under `$XDG_RUNTIME_DIR/lota` (only `lota.sock`) | The token directory was created by the agent (root-owned) before the hook tried to write. Remove the directory and let the hook recreate it as the operator user, or `chown` it to `$USER:lota`.                                                  |
| Game window never appears, Steam shows "Running" | Older hook revisions (before the `should_activate()` filter) ran the constructor inside every launcher utility and stalled on the 2 s connect timeout per hop. Reinstall `liblota_wine_hook.so` from this tree.                                  |

For deeper diagnosis, raise the hook log level and tail the Steam
console log:

```sh
# in Steam launch options, swap LOG_LEVEL=info -> LOG_LEVEL=debug
tail -F ~/.local/share/Steam/logs/console-linux.txt | grep -aE "lota-hook|lota-proton-hook"
```

Every hook line is tagged `lota-hook:` so the relevant entries are
trivial to grep out of the surrounding Proton noise.

To check the in-container view of the socket directory (helps
diagnose `PRESSURE_VESSEL_FILESYSTEMS_RW` issues without rebooting
the game):

```sh
cs2_pid=$(pgrep -f "linuxsteamrt64/cs2" | head -n1)
ls -l "/proc/$cs2_pid/root/run/user/$(id -u)/lota/"
```

A healthy container view lists `lota.sock`; a tmpfs-only view
(empty directory or only the placeholder files the hook itself
created) means the bind-mount did not happen.
