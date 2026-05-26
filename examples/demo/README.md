# Live demo

End-to-end walk-through of the LOTA attestation chain on a single
Fedora 44 host. The runner stands up an isolated `swtpm`, the LOTA
agent, the demo verifier/server, the heartbeat producer, and the
SDL2 client, then hands off to the operator. A second script flips
the trust verdict on demand so the failure path is visible during a
walk-through.

## Five-step operator path

1. **Clone** the repository and `cd` into it.

2. **Install dependencies.** Project build prerequisites plus the
   demo-only tools listed under [Dependencies](#dependencies). On
   Fedora 44 the demo-only set is

   ```sh
   sudo dnf install swtpm swtpm-tools tpm2-tools tpm2-tss-devel \
                    SDL2-devel libcurl-devel golang
   ```

3. **Run the paced runner.** From the repository root:

   ```sh
   sudo -E examples/demo/setup.sh
   ```

   The script pauses at each phase (`press ENTER to continue:`). On
   the sixth ENTER `trust_pong` opens with a green `TRUSTED` banner
   and a live score against the back wall. The runner prints the
   sandbox path (`/tmp/lota-demo.XXXXXX`) and the marker path
   `<sandbox>/tamper.marker` at the producer step so the next script
   needs no configuration.

4. **Watch the green path.** Every heartbeat tick (default 5 s, see
   `--interval`) writes one line to the producer's log under the
   sandbox `logs/` directory:

   ```
   demo_anticheat: seq=7 state=TRUSTED latency=12.4ms http=200
   ```

   The `trust_pong` banner mirrors the same verdict; the score
   counter keeps incrementing.

5. **Trigger the failure path.** From a second terminal, with the
   demo still running:

   ```sh
   examples/demo/demo_tamper.sh
   ```

   The script discovers the active sandbox, arms the tamper marker,
   and holds it until Ctrl-C. The next producer tick flips the
   banner to red `INTEGRITY LOSS` and (after two consecutive
   UNTRUSTED ticks, matching `trust_pong`'s
   `untrusted_streak >= 2`) the play field freezes with
   `INTEGRITY LOSS - session terminated`. Ctrl-C on `demo_tamper.sh`
   unlinks the marker; the next tick returns `TRUSTED` and the
   client resumes.

Press Esc or close the `trust_pong` window to end the demo. The
runner's EXIT trap stops every background process, tears down
`swtpm`, and removes the sandbox unless `--keep-tmp` was passed.

## Asciinema capture

To record a walk-through, run the demo under `asciinema`:

```sh
asciinema rec --max-wait 2 --command "examples/demo/setup.sh --yes" \
              examples/demo/asciinema.cast
```

`--max-wait 2` collapses long ENTER pauses to two seconds so the
playback stays under two minutes. Trigger `demo_tamper.sh` from a
second terminal at the appropriate point in the recording; the
producer's per-tick log lines make the verdict transition visible
without narration.

## Dependencies

Install the normal project dependencies plus the demo tools:

| Tooling          | Fedora package examples                         |
| ---------------- | ----------------------------------------------- |
| TPM sandbox      | `swtpm`, `swtpm-tools`, `tpm2-tools`            |
| TSS2 loader      | `tpm2-tss-devel`                                |
| examples build   | `SDL2-devel`, `libcurl-devel`, `golang`, `make` |

The runner uses the `swtpm` TCTI directly through the agent's
`LOTA_TCTI` override; it does not talk to `/dev/tpmrm0`. This is a
LOTA-level environment variable passed into the TSS2 TCTI loader,
not a promise that libtss2 itself reads `LOTA_TCTI`. AIK metadata
and AIK auth are redirected with `LOTA_AIK_META_PATH` into the same
temporary demo directory.

## setup.sh reference

| Flag                  | Meaning                                       |
| --------------------- | --------------------------------------------- |
| `--dry-run`           | print the ordered steps without starting them |
| `--yes`               | skip ENTER gates                              |
| `--no-build`          | require existing artifacts under `build/`     |
| `--keep-tmp`          | keep logs and swtpm state after exit          |
| `--listen HOST:PORT`  | demo server listen address                    |
| `--interval SEC`      | heartbeat interval for `demo_anticheat`       |
| `--tpm-port PORT`     | swtpm command port; control port is `PORT+1`  |

The runner exposes the marker path through the producer step so
`demo_tamper.sh` can discover it without flags; for non-default
sandboxes feed it explicitly with `--demo-dir` or `--marker`.

The real run currently needs root because `lota-agent --test-signed`
binds `/run/lota/lota.sock`. If you want build artifacts owned by
your normal user, build first and skip the build phase:

```sh
make all
make examples
sudo -E examples/demo/setup.sh --no-build
```

CI and quick ordering checks use:

```sh
examples/demo/setup.sh --dry-run --yes
```

## demo_tamper.sh reference

| Flag             | Meaning                                                  |
| ---------------- | -------------------------------------------------------- |
| `--marker PATH`  | explicit marker file; refused outside `/tmp/lota-demo.*` |
| `--demo-dir DIR` | sandbox root; marker is `DIR/tamper.marker`              |
| `--hold-sec SEC` | auto-disarm after `SEC` seconds instead of Ctrl-C        |

The script picks the newest `/tmp/lota-demo.*` directory if neither
`--marker` nor `--demo-dir` is given. Disarming happens through a
single `trap` on EXIT / INT / TERM, so killing the script (or
letting `--hold-sec` lapse) always removes the marker; the
producer's next tick returns to `TRUSTED` without operator
intervention.

## Runtime notes

The runner refuses to start if `/run/lota/lota.sock` already exists.
All background processes write logs under the sandbox `logs/`
directory printed at the start of the demo:

```
agent.log            lota-agent --test-signed
demo_server.log      Go demo server / verifier
demo_anticheat.log   heartbeat producer (per-tick verdict lines)
swtpm.log            swtpm sandbox
tpm2_*.log           tpm2-tools probes used during AIK export
```

On normal exit the runner asks the signed IPC server to shut down,
stops the demo server and heartbeat producer, stops `swtpm`, and
removes the temp directory unless `--keep-tmp` was passed.

## Component documentation

Each binary keeps its own integrator-facing README next to the
source:

- [examples/demo_server/README.md](../demo_server/README.md) - HTTP
  surface, accepted payloads, expected response schema.
- [examples/demo_anticheat/README.md](../demo_anticheat/README.md) -
  producer flags, exit codes, tamper hook, and integration notes
  against EAC / BattlEye.
- [examples/demo_game/README.md](../demo_game/README.md) - SDL2
  client flags, controls, cold-launch contract, verdict palette.
