.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==================
Sealed key example
==================

Two scripts that seal secrets to the TPM and show when they open. A sealed
secret is released only while chosen PCRs hold the values they held at seal
time; the check runs on the host, with no verifier. The commands and their
messages are described in `sealed-keys.rst
<../../Documentation/admin-guide/bringup/sealed-keys.rst>`__, the TPM
objects and blob formats in `tpm.rst <../../Documentation/agent/tpm.rst>`__.

Sealing binds a secret to a boot state, not to a process. Any process with
access to the TPM unseals while the registers match, and a secret a program
holds after unsealing is as exposed as any other value in its memory.

seal-demo.sh
============

Runs ``lota-agent --seal`` three times and ``--unseal`` four times. It needs
root, a TPM and ``tpm2-tools``; ``AGENT`` names the agent binary, by default
``/usr/bin/lota-agent``:

.. code-block:: sh

   sudo AGENT=/path/to/lota-agent examples/sealed-key/seal-demo.sh

The steps:

#. Seals a short key to the default PCRs 0, 1 and 7 and prints the blob
   size.
#. Unseals it and compares it with the original.
#. Seals the key to PCR 16 alone (``--seal-pcrs 0x10000``), extends PCR 16
   with ``tpm2_pcrextend``, and expects the unseal to fail. PCR 16 is the
   debug PCR, outside the default set, so the step moves a bound PCR
   without a reboot and without touching the first blob. PCR 16 stays
   extended after the script; ``tpm2_pcrreset 16`` sets it back to zero.
#. Seals 4096 random bytes, which go into an envelope, unseals them and
   compares. It then flips the last byte, which is ciphertext, and expects
   the unseal to fail on the AES-256-GCM tag.

The script exits non-zero at the first step that does not behave, and ends
with::

   All steps passed: the key only unseals in the sealed boot state.

anti-rollback-recipe.sh
=======================

A sealed secret has no version. It opens in every boot that reproduces its
PCR state, so a secret meant to be replaced keeps opening after the new one
is issued. The agent does not version or revoke sealed secrets. This script
shows how to do it with ``tpm2-tools`` alone, using a TPM NV counter.

It needs ``tpm2-tools`` and a TPM, as root or through ``TPM2TOOLS_TCTI``:

.. code-block:: sh

   sudo examples/sealed-key/anti-rollback-recipe.sh

#. Defines an NV counter, increments it once and reads its value.
#. Persists a storage parent.
#. Builds the policy ``PolicyPCR`` over ``PCR_LIST`` and ``PolicyNV``
   requiring the counter to be at most the value read.
#. Seals a secret under that policy and unseals it.
#. Increments the counter and expects the unseal to fail, although the PCRs
   still match.

On exit it removes the counter and the parent it created. Three variables
set the TPM resources it uses:

``NV_INDEX``
  The counter's NV index, by default ``0x1500016``.

``PARENT_HANDLE``
  The persistent handle of the parent, by default ``0x81000010``.

``PCR_LIST``
  The PCR selection of the policy, by default ``sha256:0,7``.

An index or handle already in use makes the script fail at that step. An NV
counter is a TPM resource shared by everything on the host; one counter
revokes every secret sealed at or below its value.
