.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=====
Agent
=====

``lota-agent`` runs on the attested host. It loads the signed BPF LSM program
that enforces the host's policy, commits its own binary to PCR 14 once per
boot, and answers with TPM quotes: tokens for a local title over the IPC
socket, and attestation reports for the verifier of each enrolled publisher.
The source is under :ghsrc:`src/agent`.

Contents
========

* :doc:`command-line` -- the verbs and options of ``lota-agent``.
* :doc:`configuration` -- ``/etc/lota/lota.conf`` and its keys.
* :doc:`publishers` -- the profile of each publisher: its AIK, CA and verifier.
* :doc:`lifecycle` -- the units, the PCR 14 commitment and stopping the agent.
* :doc:`tpm` -- what the agent requires of the TPM and keeps in it.
* :doc:`protection` -- how a title asks for protection and what the BPF LSM
  keeps out of it.
* :doc:`boot-evidence` -- the PCR values and PCR 7 events a relying party
  checks against a token.
* :doc:`ipc` -- the socket protocol and the D-Bus interface.
* :doc:`tokens` -- the quote a title hands to its server.
* :doc:`journal` -- where the agent's messages go and when they repeat.
* :doc:`runtime-measurement` -- the digest of the code a protected
  process maps.

.. toctree::
   :hidden:

   command-line
   configuration
   publishers
   lifecycle
   tpm
   protection
   boot-evidence
   ipc
   tokens
   journal
   runtime-measurement

Roles
=====

The same binary serves several roles, chosen by its command line.

Enforcement daemon
  ``lota-agent`` with no verb, run by ``lota-agent.service``. It loads and
  attaches the LSM program, extends PCR 14, serves ``/run/lota/lota.sock``
  and the ``org.lota.Agent1`` D-Bus name, and mints tokens. The unit runs it
  as root with ``Type=notify`` and a watchdog, and stops it with
  ``lota-agent --shutdown`` (:doc:`lifecycle`).

Attestation loop
  ``lota-agent --attest``, run by ``lota-attest.service``. It sends a report
  to the verifier of each configured publisher at that publisher's interval.
  The unit orders it after ``lota-agent.service``, grants it no
  capabilities, and does not restart it on exit status 78. The loop is a
  client of the daemon's IPC socket.

One-shot commands
  Every other verb, such as ``--status``, ``--enroll`` or ``--seal``, does
  its work and exits. ``--status``, ``--shutdown`` and
  ``--terminate-protected`` talk to the running daemon over the IPC socket
  (:doc:`command-line`).

Daemon startup
==============

The daemon starts in this order (:ghsrc:`src/agent/main.c`). A step that
fails ends the start with the exit status listed below.

#. It sets ``PR_SET_NO_NEW_PRIVS`` and clears ``PR_SET_DUMPABLE``; every
   invocation of the binary does this.
#. It reads ``/etc/lota/lota.conf`` (:doc:`configuration`) and the command
   line. A one-shot verb runs here and exits.
#. It refuses a ``--mode`` weaker than the file's ``enforce`` without
   ``--insecure-allow-mode-downgrade``.
#. With ``--daemon`` it detaches; from then on its messages reach the
   journal alone.
#. It creates the PID file; a file another agent holds ends the start with
   status 3.
#. It builds the publisher list from the profiles in the file, refuses to
   run under a tracer, and loads its seccomp filter.
#. It checks the startup policy, the signature of the enforcement object
   against ``policy_pubkey``, and the object's integrity layout. A refusal
   here leaves PCR 14 untouched.
#. It opens the IPC socket, or takes it from ``lota-agent.socket``, then the
   container listener and D-Bus.
#. It reads the IOMMU, kernel appraisal and Secure Boot state, and logs it.
#. It refuses a host that did not boot via UEFI.
#. It opens the TPM, binds the first publisher's profile, and provisions the
   AIK (:doc:`tpm`). A profile that does not bind is a warning; tokens are
   then signed with the host AIK.
#. It extends PCR 14 with its boot commitment. When this boot's commitment
   is already there, the status and every token carry ``AGENT_RESTARTED``
   until reboot.
#. It loads the LSM program, applies the startup policy, attaches the hooks
   and opens the event ring buffer.
#. It tells systemd it is ready and enters its event loop.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 12 88

   * - Status
     - Meaning
   * - 0
     - The daemon left its event loop on request, or a one-shot command
       succeeded.
   * - 1
     - Any other failure, including a transient one (``EIO``, ``EMFILE``,
       ``ENFILE``, ``ENOMEM``, ``EAGAIN``, ``EINTR``, ``EBUSY``) in a startup
       check.
   * - 3
     - Another agent holds the PID file.
   * - 78
     - The host needs operator action before the agent can start: a host
       configuration the agent refuses, a startup check that fails for a
       reason other than the transient ones, or a PCR 14 commitment the
       agent refuses this boot.

The status values are in :ghsrc:`src/agent/exit_status.h`.
``lota-agent.service`` does not restart on 3 or 78, and ``lota-attest.service``
does not restart on 78.

Files
=====

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Path
     - Content
   * - ``/etc/lota/lota.conf``
     - The configuration. The package does not own it.
   * - ``/etc/lota/policy.pub``
     - A fleet's own enforcement key. When present it replaces
       ``/usr/lib/lota/enforcement.pub``.
   * - ``/usr/lib/lota/lota_lsm.bpf.o``
     - The enforcement object, with its signature ``lota_lsm.bpf.o.sig`` and
       the key ``enforcement.pub`` beside it.
   * - ``/var/lib/lota/``
     - Mode 0700. ``aik_meta.dat`` describes the host AIK;
       ``clock_state.dat`` records the last PCR 14 commitment.
   * - ``/var/lib/lota/profiles/<id>/``
     - One directory per publisher, named by the lowercase hex SHA-256 of
       the SubjectPublicKeyInfo of its CA trust anchor
       (:ghsrc:`src/agent/profile.h`). It holds ``enroll_state.dat``,
       ``aik_cert.der``, ``aik_meta.dat``, ``aik_handle``, ``consent``,
       and the AIK's auth value in ``aik_auth.dat``, ``aik_auth.sealed``
       or both (:doc:`configuration`).
   * - ``/run/lota/lota.sock``
     - The IPC socket, mode 0660, owner ``root:lota`` (:doc:`ipc`).
   * - ``/run/lota/lota-agent.pid``
     - The daemon's PID file.
   * - ``/run/lota/pcr14_baseline``
     - Written in the initramfs by ``lota-pcr14-lock``, read when the daemon
       extends PCR 14.
   * - ``/run/lota/bench.json``
     - Mode 0640, written with ``--bench``.
   * - ``/etc/dbus-1/system.d/org.lota.Agent1.conf``
     - The bus policy: root alone owns the name; root and group ``lota``
       talk to it.
