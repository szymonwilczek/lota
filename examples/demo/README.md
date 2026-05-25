# Live demo

`setup.sh` is the paced runner. It builds the tree, starts an isolated `swtpm`, 
runs the signed IPC test server, starts the demo verifier/server, starts the heartbeat producer, 
and then launches `trust_pong`.

The script waits for ENTER between phases so the operator can explain
what just happened before moving to the next process.

## Dependencies

Install the normal project dependencies plus the demo tools:

| Tooling          | Fedora package examples                         |
| ---------------- | ----------------------------------------------- |
| TPM sandbox      | `swtpm`, `swtpm-tools`, `tpm2-tools`            |
| TSS2 loader      | `tpm2-tss-devel`                                |
| examples build   | `SDL2-devel`, `libcurl-devel`, `golang`, `make` |

The runner uses the `swtpm` TCTI directly through the agent's
`LOTA_TCTI` override; it does not talk to `/dev/tpmrm0`. This is a
LOTA-level environment variable passed into the TSS2 TCTI loader, not
a promise that libtss2 itself reads `LOTA_TCTI`. AIK metadata and AIK
auth are redirected with `LOTA_AIK_META_PATH` into the same temporary
demo directory.

## Run

From the repository root:

```sh
sudo -E examples/demo/setup.sh
```

The real run currently needs root because `lota-agent --test-signed`
binds `/run/lota/lota.sock`. If you want build artifacts owned by your
normal user, build first and then skip the build phase:

```sh
make all
make examples
sudo -E examples/demo/setup.sh --no-build
```

Useful flags:

| Flag                  | Meaning                                       |
| --------------------- | --------------------------------------------- |
| `--dry-run`           | print the ordered steps without starting them |
| `--yes`               | skip ENTER gates                              |
| `--no-build`          | require existing artifacts under `build/`     |
| `--keep-tmp`          | keep logs and swtpm state after exit          |
| `--listen HOST:PORT`  | demo server listen address                    |
| `--interval SEC`      | heartbeat interval for `demo_anticheat`       |
| `--tpm-port PORT`     | swtpm command port; control port is `PORT+1`  |

CI and quick ordering checks use:

```sh
examples/demo/setup.sh --dry-run --yes
```

## Runtime Notes

The script refuses to start if `/run/lota/lota.sock` already exists.
All background processes write logs under the temporary demo directory 
printed by the script.

On normal exit the runner asks the signed IPC server to shut
down, stops the demo server and heartbeat producer, stops `swtpm`, and
removes the temp directory unless `--keep-tmp` was passed.

`demo_tamper.sh` is still the next step. This only proves the
green path: swtpm-backed signed tokens reach the demo server, the first
heartbeat returns `TRUSTED`, and `trust_pong` displays the live status.
