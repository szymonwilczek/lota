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

Run the Steam-runtime verifier under your user account (not root) so
it sees the correct `XDG_RUNTIME_DIR`:

```sh
lota-steam-setup
```

The script:

- verifies `XDG_RUNTIME_DIR` is set,
- confirms the agent socket exists at `/run/lota/lota.sock`,
- checks the `lota` group exists and that the current user is a
  member,
- locates `liblota_wine_hook.so` in the standard library paths,
- creates `$XDG_RUNTIME_DIR/lota/` with mode `0750` so the
  Steam pressure-vessel container has a writable token sink,
- prints the exact Steam launch-options string to paste into the
  CS2 properties dialog.

`lota-steam-setup --verify` re-runs the checks without modifying
anything; useful from the demo script or from a verification pass
before each launch.

## Wire it into CS2

1. Open Steam, right-click `Counter-Strike 2` -> `Properties...`.
2. Under **General -> Launch options**, paste:

   ```
   lota-proton-hook %command%
   ```

3. Confirm Compatibility -> **Force the use of a specific Steam Play
   compatibility tool** is set to Proton 9.0-4 or Proton
   Experimental.
4. Close the dialog. The next CS2 launch is hooked.

For a one-off verification without persisting the launch option,
the same wiring is reachable from the command line:

```sh
LOTA_HOOK_LOG_LEVEL=info lota-proton-hook \
    steam-runtime-launch-client -- steam://rungameid/730
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

Verify after launching CS2:

```sh
ls -l "$XDG_RUNTIME_DIR/lota/"
cat   "$XDG_RUNTIME_DIR/lota/lota-status"
```

A healthy run prints `state=ready` plus a recent `last_refresh`
timestamp. The `lota-token.bin` file size matches the
`LOTA_GAMING_MAX_TOKEN` budget exposed by the gaming SDK; the
binary is opaque to the operator but `xxd | head` is enough to
confirm it is not all-zeros.

## Hook environment overrides

The hook honours a small set of environment variables, all
documented in `include/lota_wine_hook.h`.

| Variable                | Effect                                         |
| ----------------------- | ---------------------------------------------- |
| `LOTA_HOOK_DISABLE=1`   | wrapper `exec`s the game without `LD_PRELOAD` |
| `LOTA_HOOK_LOG_LEVEL`   | `debug` / `info` / `warn` / `error` / `silent` |
| `LOTA_HOOK_TOKEN_DIR`   | override the token sink directory             |
| `LOTA_HOOK_REFRESH_SEC` | seconds between agent re-queries (default 60) |
| `LOTA_HOOK_SOCKET`      | override the agent socket path                |

Set them on Steam's launch line, e.g.:

```
LOTA_HOOK_LOG_LEVEL=debug lota-proton-hook %command%
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

| Symptom                                       | Likely cause                                                                                |
| --------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `lota-proton-hook: hook library not found`    | `make install` skipped or installed to a non-standard `LIBDIR`; set `LOTA_HOOK_LIB_PATH`    |
| No files appear under `$XDG_RUNTIME_DIR/lota` | `XDG_RUNTIME_DIR` unset in Steam's environment; rerun `lota-steam-setup` from a login shell |
| `state=error connect`                         | agent socket missing or wrong permissions; verify `/run/lota/lota.sock` and `lota` group    |
| `state=error attest`                          | agent up but TPM gate failed; check `journalctl -u lota-agent` for the failed measurement   |
| Game stutters on launch                       | hook constructor blocks until first token fetch; raise `LOTA_HOOK_REFRESH_SEC` if needed    |

For deeper diagnosis, raise the hook log level and tail the Proton
log:

```sh
LOTA_HOOK_LOG_LEVEL=debug lota-proton-hook %command%
tail -F ~/.steam/steam/logs/console_log.txt
```

Every hook line is tagged `lota-hook:` so the relevant entries are
trivial to grep out of the surrounding Proton noise.
