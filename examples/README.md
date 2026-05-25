# LOTA examples

End-to-end integration material that demonstrates how the framework is
deployed in a real game stack. Every subdirectory under `examples/` is
intentionally a single-purpose component; they are wired together by
`examples/demo/setup.sh` once every piece is in tree.

| Directory          | Role                                                         |
| ------------------ | ------------------------------------------------------------ |
| `demo_server/`     | Go reference server: nonce issuance + heartbeat verification |
| `demo_anticheat/`  | C heartbeat producer driven by the anti-cheat SDK            |
| `demo_game/`       | SDL2 client (`trust_pong`) that mirrors the server verdict   |
| `demo/`            | End-to-end deploy + tampering scenario + asciinema cast      |
| `cs2/`             | Proton / CS2 integration smoke note                          |

The whole tree is built with `make examples` from the repository root.
The target is opt-in: `make all` does not depend on it, so the agent
build stays the same speed it has always been.
