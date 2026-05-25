# demo_server

Reference game server for the LOTA end-to-end demo. The process is a single Go binary that:

1. mints attestation nonces and per-session ids,
2. decodes anti-cheat heartbeats off the wire (`LACH` framing),
3. verifies the embedded LOTA token against a configured AIK public
   key, and
4. surfaces the most recent verdict so the SDL2 demo (`trust_pong`)
   can mirror it without owning a heartbeat channel of its own.

Build with `make examples` from the repository root; the binary lands
at `build/examples/demo_server`.

## Flags

| Flag                 | Default                                | Meaning                                                   |
| -------------------- | -------------------------------------- | --------------------------------------------------------- |
| `--listen`           | `127.0.0.1:7443`                       | host:port to listen on (loopback only by design)          |
| `--aik-pub`          | (none)                                 | path to the AIK public key (DER or PEM); required outside tests |
| `--expected-games`   | `trust-pong=lota-demo-CS2-clone`       | comma-separated `game_id=license` entries the server accepts |
| `--max-age`          | `300`                                  | maximum heartbeat age in seconds before UNTRUSTED         |

TLS is intentionally out of scope. The demo runs on loopback so the operator can curl every endpoint without bringing in a CA. 
The production guidance is "put the verifier behind your existing game auth gateway"; that gateway already owns TLS termination.

## Endpoints

### `POST /nonce`

Body: `{"game_id": "trust-pong"}`.

Mints a per-session UUID and 32 random nonce bytes.
The client uses the nonce as input to `lota_get_token()` so the server can bind a given attestation to a specific challenge.

```sh
curl -s http://127.0.0.1:7443/nonce \
     -d '{"game_id":"trust-pong"}' | jq
```

Response:

```json
{
  "session_id": "0e7e9f5b-3e3d-4f57-9d80-58dcb6c2d8d4",
  "nonce": "<base64 of 32 bytes>",
  "license": "lota-demo-CS2-clone"
}
```

### `POST /heartbeat`

Body: raw LACH bytes (binary, `Content-Type: application/octet-stream`).
The handler:

1. parses the 78-byte header documented in `include/lota_anticheat.h`,
2. rejects on bad magic / version / size / unsupported `domain_version`
   (verdict `REJECT`, HTTP 400),
3. fails closed on an unknown `game_id_hash`, replayed / stale
   sequence, future timestamp, or signature/nonce mismatch (verdict
   `UNTRUSTED`, HTTP 200),
4. returns `{"state":"TRUSTED","license":"lota-demo-CS2-clone"}` only
   when the embedded LOTA token verifies against the configured AIK
   and every freshness check passes.

```sh
curl -s --data-binary @heartbeat.bin \
     -H 'Content-Type: application/octet-stream' \
     http://127.0.0.1:7443/heartbeat
```

### `GET /state?game_id=trust-pong`

Returns the most recent verdict the server saw for a given game id,
or `PENDING` when no heartbeat has arrived yet. `trust_pong` polls
this endpoint to drive its banner so the SDL2 client itself never has
to parse LACH packets.

## Logging

Every state transition writes one line to stdout in
`[RFC3339Nano] session=<uuid|hex> seq=<n> state=<verdict>
reason=<...>` form, so the demo operator can follow the entire run
by `tail -f`-ing the server.

## Tests

`go test ./...` covers each verdict branch with a fabricated heartbeat:
TRUSTED, UNTRUSTED-on-bad-signature, UNTRUSTED-on-unknown-game,
UNTRUSTED-on-tampered-header, UNTRUSTED-on-flag-mismatch,
UNTRUSTED-on-replay, REJECT-on-bad-magic, REJECT-on-unsupported-domain,
REJECT-on-truncated-token, plus `/nonce` and `/state` happy paths and
failure modes.
