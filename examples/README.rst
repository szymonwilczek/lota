.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

LOTA examples
=============

End-to-end integration material that demonstrates how the framework is deployed
in a real game stack. Every subdirectory under ``examples/`` is intentionally a
single-purpose component; they are wired together by ``examples/demo/setup.sh``
once every piece is in tree.

+---------------------+-------------------------------------------------------+
| Directory           | Role                                                  |
+=====================+=======================================================+
| ``enrollment/``     | Privacy CA enrollment end-to-end: stand up            |
|                     | ``lota-attest-ca``, enroll an AIK via credential      |
|                     | activation, attest to a verifier that trusts only the |
|                     | CA root.                                              |
+---------------------+-------------------------------------------------------+
| ``ci-gate/``        | Enterprise reference: a CI/CD step proves its host is  |
|                     | attested before a relying party releases a secret to   |
|                     | it. Fail-closed, exit-code driven, with a rootless     |
|                     | swTPM-backed end-to-end run.                           |
+---------------------+-------------------------------------------------------+
| ``demo_server/``    | Go reference server: nonce issuance + heartbeat       |
|                     | verification                                          |
+---------------------+-------------------------------------------------------+
| ``demo_anticheat/`` | C heartbeat producer driven by the anti-cheat SDK     |
+---------------------+-------------------------------------------------------+
| ``demo_game/``      | SDL2 client (``trust_pong``) that mirrors the server  |
|                     | verdict                                               |
+---------------------+-------------------------------------------------------+
| ``demo/``           | End-to-end deploy + tampering scenario + asciinema    |
|                     | cast                                                  |
+---------------------+-------------------------------------------------------+
| ``cs2/``            | Proton / CS2 integration smoke note                   |
+---------------------+-------------------------------------------------------+
| ``block-demo/``     | Self-protecting victim + dummy evil.so; proves the    |
|                     | BPF LSM gate rejects an unauthorised dlopen           |
|                     | end-to-end.                                           |
+---------------------+-------------------------------------------------------+
| ``sealed-key/``     | Offline sealed-key round-trip: seal a secret to the   |
|                     | boot/PCR state, unseal it, and prove it fails closed  |
|                     | after the state changes.                              |
+---------------------+-------------------------------------------------------+
| ``ha-postgres/``    | Multi-instance verifier on a shared Postgres backend: |
|                     | two instances share enforcement and session-token     |
|                     | state via ``--pg-dsn``, so a token issued by one      |
|                     | validates on the other.                               |
+---------------------+-------------------------------------------------------+

``anticheat-integration.rst`` is the map for a studio forking the
game-side material: what to copy, what to consume, what must change, and
where the licence line falls.

The whole tree is built with ``make examples`` from the repository root. The
target is opt-in: ``make all`` does not depend on it, so the agent build stays
the same speed it has always been.
