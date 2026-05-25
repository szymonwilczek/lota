# demo_game / trust_pong

Reference SDL2 client for the LOTA end-to-end demo. The game is deliberately a one-paddle Pong (paddle vs back wall, score on bounce) so the operators's attention stays on the integration story:

The banner across the top of the window mirrors the verdict the
demo server publishes for the `trust-pong` game id, and the game
freezes after two consecutive UNTRUSTED heartbeats with an overlay
that says `INTEGRITY LOSS - session terminated`.

trust_pong only **consumes** the verdict; it does not produce heartbeats itself. 
The heartbeats come from `demo_anticheat`, which runs as a separate process exactly like a real anti-cheat helper ships next to a game.

## Build prerequisites

The fragment under `make examples` builds `trust_pong` only when the demo system dependencies are present, and prints a clear SKIP line otherwise:

| Package                | Fedora                  |
| ---------------------- | ----------------------- |
| SDL2                   | `SDL2-devel`            |
| libcurl                | `libcurl-devel`         |

The binary lands at `build/examples/trust_pong`.

## Text rendering

trust_pong does not use system fonts. The UI uses a tiny monospace
bitmap renderer embedded in `ui.c` and draws text with SDL rectangles.
That keeps the demo deterministic and avoids font lookup, bundled
assets, network fetches, and package-manager bootstrap work.

## Flags

| Flag             | Default                       | Meaning                                              |
| ---------------- | ----------------------------- | ---------------------------------------------------- |
| `--server URL`   | `http://127.0.0.1:7443`       | demo server base URL (no `/endpoint` suffix)         |
| `--game-id ID`   | `trust-pong`                  | game id passed to `/nonce` and `/state`              |
| `--socket PATH`  | default agent socket          | override the agent UNIX socket path                  |
| `--help`         | n/a                           | print usage and exit                                 |

## Controls

| Key                | Action                                              |
| ------------------ | --------------------------------------------------- |
| `W` / `Up`         | move paddle up                                      |
| `S` / `Down`       | move paddle down                                    |
| `Esc` / `Q`        | quit                                                |

## Cold-launch contract

When the agent is unreachable, the server is down, or the policy is
wrong, trust_pong still opens its window. The banner shows
`OFFLINE`, the status detail appears on its own row below the verdict,
the rendered Pong loop keeps running, and the polling thread retries
the `/state` endpoint every 750 ms. The game switches to the live verdict the
moment a heartbeat lands. The startup path never crashes on a
failed handshake; that is the explicit acceptance criterion for
H-NEW-2 step 3.

## Verdict palette

| Verdict   | Header                                              |
| --------- | --------------------------------------------------- |
| CHECKING  | `CHECKING` with status detail on the second row     |
| TRUSTED   | `TRUSTED` with license detail on the second row     |
| UNTRUSTED | `UNTRUSTED` with verifier detail on the second row  |
| FROZEN    | `INTEGRITY LOSS` plus terminated overlay            |
| OFFLINE   | `OFFLINE` with curl / startup detail on row two     |

The second row in the header echoes whichever server response field is
most recently surfaced (`license=lota-demo-CS2-clone` on TRUSTED, the
verifier's free-form reason on UNTRUSTED, the curl error string on
OFFLINE). The rest of the screen is intentionally plain.
