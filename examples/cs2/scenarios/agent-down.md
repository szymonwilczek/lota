# Scenario: hook reacts when the agent goes down

This walk-through exercises the LOTA hook's "graceful degradation"
contract. The hook is designed to never wedge the game, and the
agent is allowed to disappear out from under a live session
without taking the game with it. The visible signal is the
`lota-status` file under `$XDG_RUNTIME_DIR/lota/`: the hook keeps
the file in sync with the agent's last known attestation state and
unlinks it on a clean detach.

The scenario is operator-driven and runs against the
`--test-signed` agent the main
[examples/cs2/README.md](../README.md) walk-through uses for
the end-to-end integration test. No game state is destroyed and
the hook will recover on its own when the agent comes back up.

## Prerequisites

- The agent is running with the operator's `XDG_RUNTIME_DIR` in
  scope (TPM-signed token path, fixture policy digest applied):
  ```sh
  sudo env XDG_RUNTIME_DIR=/run/user/"$(id -u)" \
      /usr/bin/lota-agent --test-signed
  ```
- Counter-Strike 2 launches cleanly with the LOTA launch options
  set (see the main CS2 README). At a minimum the launch line
  must include `lota-proton-hook %command%` plus
  `PRESSURE_VESSEL_FILESYSTEMS_RW` and `LOTA_HOOK_SOCKET`
  pointing at the user-runtime listener.
- The operator account is in the `lota` group and the Steam
  process inherited that group.

## Walk-through

Open three terminals on the host. The first two attach to LOTA
state; the third is the operator's control surface.

### Terminal 1: watch the verdict

```sh
examples/cs2/scenarios/verify-attested.sh --interval 1
```

The watcher prints one line per transition. With the agent up and
the hook attached it stays at `TRUSTED`.

### Terminal 2: tail the hook log

```sh
tail -F ~/.local/share/Steam/logs/console-linux.txt | grep -aE \
    "lota-hook|lota-proton-hook"
```

Healthy steady state shows the constructor lines from the game
process (and the Steam reaper) plus periodic
`refresh` / `connected to agent` messages.

### Terminal 3: drive the scenario

1. Launch CS2 from Steam. Confirm Terminal 1 prints `TRUSTED`
   within a heartbeat or two of the game opening:

   ```
   21:55:34 TRUSTED
   ```

2. Kill the agent:

   ```sh
   sudo pkill -INT lota-agent
   ```

   Within `LOTA_HOOK_REFRESH_SEC` (default 60) the hook detects
   the disconnect on its next poll, loses the
   subscribe channel, and the watcher flips:

   ```
   21:56:34 OFFLINE
   ```

   The hook log (Terminal 2) prints the matching
   `connection lost (...)` line before going quiet.

3. Restart the agent in the same shape:

   ```sh
   sudo env XDG_RUNTIME_DIR=/run/user/"$(id -u)" \
       /usr/bin/lota-agent --test-signed
   ```

   On the next refresh tick the hook reconnects, rewrites
   `lota-status`, and the watcher returns to `TRUSTED`:

   ```
   21:57:35 TRUSTED
   ```

4. Quit CS2 from inside the game. The hook destructor leaves
   the artefacts in place (the next session overwrites them);
   if you want to verify the OFFLINE path independently you can
   kill the agent before quitting CS2 and confirm the watcher
   flips. CS2's shutdown is unaffected.

## What this proves

- The hook does not block the game on an agent disconnect; CS2
  keeps running through Terminal 3 step 2 and the operator can
  finish a round of bot play with the agent down.
- The hook re-establishes the attestation channel on its own
  cadence; no game restart, no LD_PRELOAD reload.
- The verdict surface (`lota-status`) is the single source of
  truth a server-side or game-side integrator polls. The hook
  writes `LOTA_OFFLINE=1` on disconnect so the watcher can
  distinguish OFFLINE (no agent) from UNTRUSTED (agent says
  no); the watcher in `verify-attested.sh` is the minimal
  possible consumer of both signals and ships with the demo so
  an integrator does not have to invent it.
- Per-state log lines in `console-linux.txt` are stable enough to
  drive a runtime monitor (`grep -E 'connection lost|connected to
  agent'`); the contract is documented in
  [`src/sdk/lota_wine_hook.c`](../../../src/sdk/lota_wine_hook.c).

## Failure-mode notes

If the watcher stays at `OFFLINE` after step 3:

- Confirm the agent banner prints
  `IPC extra listener on /run/user/<uid>/lota/lota.sock`. If only
  the `/run/lota/lota.sock` listener appears, the
  `XDG_RUNTIME_DIR=...` environment did not reach the agent.
- Confirm `PRESSURE_VESSEL_FILESYSTEMS_RW` is still set in CS2's
  launch options; pressure-vessel re-creates the container's
  /run/user/<uid> tmpfs on every launch and the bind-mount is
  needed every time.
- Confirm the operator user is still in the `lota` group
  (`id | grep lota`); a Steam restart from a non-`lota` shell
  rebuilds the supplementary group set without `lota`.
