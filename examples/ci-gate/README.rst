.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=====================
CI/CD release gate
=====================

The enterprise reference integration: a pipeline step proves the host it
runs on is attested before a relying party releases a secret to it.

Signing keys, registry credentials and deployment tokens are handed to
build agents on the strength of a pipeline identity -- an OIDC token, a
runner registration, a static credential in a vault. All of those say
*which job* is asking. None says *what the machine underneath it is
running*, so a compromised runner with a valid identity is still a valid
caller.

This integration adds the missing half. The gate releases nothing until
the caller answers a fresh challenge with a token signed by a TPM on a
host in the state the gate requires.

Two programs
============

``lota-ci-attest`` -- the pipeline step (``attest_step.c``, C, links the
gaming SDK)
   Connects to the local agent, gets the challenge from the gate, asks the
   agent for a token answering it, presents the token, and writes the
   released secret. Every failure is fail-closed: the output file is
   created only after a release, so a step that fails for any reason
   leaves the job without the secret rather than proceeding with a stale
   one.

``lota-release-gate`` -- the relying party (``gate/``, Go, imports
``sdk/server``)
   Issues single-use challenges, verifies presented tokens, applies its
   policy, and releases or refuses with a reason. It guards one secret
   read from a file; a production gate differs in what it does after the
   verdict -- fetch from a real secret store, mint a short-lived
   credential, sign an artifact -- not in the four steps before it.

Build
=====

Both build from ``make examples`` at the repository root, into
``build/examples/``.

The C step builds the way an integrator's does: through ``pkg-config``
against the **installed** SDK, never against the build tree. ``make
examples`` first lays the package contents out under ``build/stage`` (the
``sdk-stage`` target), so the flags come from the same ``.pc`` files
``lota-sdk-devel`` ships:

.. code:: sh

   cc $(pkg-config --cflags lota-gaming) -o step step.c \
      $(pkg-config --libs lota-gaming) $(pkg-config --libs libcurl)

With the packages installed system-wide, that line is the whole build.

Run the end-to-end proof
========================

.. code:: sh

   make all examples
   ./examples/ci-gate/run.sh

``run.sh`` needs no root and no real TPM. It starts a throwaway swTPM,
runs ``lota-agent`` under ``systemd-socket-activate`` so the agent listens
on a path in ``/tmp`` instead of ``/run/lota``, and then asserts the two
outcomes that matter:

* an attested host receives the secret, byte for byte, written ``0600``;
* a host the gate does not trust exits non-zero, writes **no** file, and
  is recorded as refused in the gate's audit output.

Requires ``swtpm``, ``swtpm_setup``, ``tpm2_readpublic`` and
``systemd-socket-activate``.

Exit codes
==========

The step reports what happened as an exit code, because a pipeline treats
"this host is not allowed" and "the gate was unreachable" differently: the
first is a policy decision to act on, the second is infrastructure to
retry.

.. list-table::
   :header-rows: 1
   :widths: 12 88

   * - Code
     - Meaning
   * - ``0``
     - Released. The secret is in the file named by ``--out``.
   * - ``2``
     - Usage error.
   * - ``3``
     - No LOTA agent on this host, so nothing can be proven.
   * - ``4``
     - The agent issued no token (not attested, or TPM unavailable).
   * - ``5``
     - The gate was unreachable or answered unintelligibly.
   * - ``6``
     - The gate refused. Its reason is on stderr.
   * - ``7``
     - Released, but the secret could not be written.

Gate flags
==========

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Flag
     - Default
     - Meaning
   * - ``--listen``
     - ``127.0.0.1:8500``
     - Address to serve on.
   * - ``--aik-pub``
     - (required)
     - AIK public key of the host allowed through, PEM or DER.
   * - ``--secret-file``
     - (required)
     - File holding the secret to release.
   * - ``--require``
     - ``attested,tpm``
     - Host state the caller must prove: ``attested``, ``tpm``,
       ``iommu``, ``bpf``, ``secureboot``.
   * - ``--nonce-ttl``
     - ``60s``
     - How long an issued challenge stays spendable.
   * - ``--max-token-life``
     - ``15m``
     - Refuse a token whose remaining validity exceeds this. ``0``
       disables.
   * - ``--tls-cert`` / ``--tls-key``
     - (none)
     - PEM keypair; enables HTTPS.

What the gate actually checks
=============================

In order, and each one refuses on its own:

1. **The challenge is one this gate issued, and is unspent.** The nonce is
   consumed by the *attempt*, not by the verdict -- a failed try does not
   leave its challenge spendable, or a captured token could be ground
   against the gate until something else changed.
2. **The token verifies against the trusted AIK.**
   ``sdk/server.VerifyToken`` checks the TPM signature and that the quote
   binds this exact challenge along with the flags, PCR mask, policy
   digest and runtime state. A token from another machine fails here.
3. **The host carries the required state.** The refusal names the missing
   bits, so a pipeline log says ``missing required state: secureboot``
   rather than "denied".
4. **The token is not implausibly long-lived.** ``--max-token-life`` is
   the gate's own window inside the one both verifiers already apply; see
   ``Documentation/contributor/development/contracts.rst``.

What this reference does **not** do
===================================

It trusts one AIK, given on the command line. A fleet's worth of hosts
means a verifier and its enrollment records rather than a flag -- see
``examples/enrollment/README.rst`` -- and the gate then asks the verifier
whether a client is currently trusted instead of pinning a key. The shape of the
release decision does not change.

It also releases a static secret. Minting a short-lived credential scoped
to the verified host is the better production choice, and it happens at
exactly the same point in the flow.
