.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

============
Command line
============

``lota-agent`` takes one verb and the options it reads. Without a verb it
runs the enforcement daemon. The options are parsed in
:ghsrc:`src/agent/cli.c`, the verbs are dispatched in
:ghsrc:`src/agent/diagnostics.c`, and ``lota-agent --help`` prints the same
list.

.. code-block:: console

   # lota-agent [options]
   # lota-agent --status
   # lota-agent --attest

Parsing
=======

The agent reads ``/etc/lota/lota.conf``, or the file ``--config`` names,
before the options; an option then replaces the value from the file, and a
list option adds to the file's list (:doc:`configuration`). A missing
default file is no error; a missing file named by ``--config`` ends the
command with ``Config file not found:``. A default file the user cannot read
gives a warning, and the command goes on with the defaults.

``--help``, ``--gen-signing-key``, ``--sign-policy`` and ``--verify-policy``
do not read the file, so its contents do not change their result; with
``--dump-config`` the last three read it.

An unknown option, or a missing argument, prints the usage and exits with
status 1. ``--help`` prints it and exits with status 0. Most options also
have the one-letter form listed below; the others have none.

One verb runs per invocation. When several are given, the first in this
order runs and the rest are ignored: ``--shutdown``, ``--status``,
``--terminate-protected``, ``--dump-config``, ``--gen-signing-key``,
``--sign-policy``, ``--verify-policy``, ``--test-tpm``, ``--seal``,
``--unseal``, ``--seal-aik-auth``, ``--reprovision-aik``,
``--seal-persist-primary``, ``--seal-evict-primary``, ``--test-iommu``,
``--export-policy``, ``--test-ipc``, ``--test-signed``,
``--list-publishers``, ``--forget-publisher``, ``--allow-publisher``,
``--add-publisher``, ``--reenroll``, ``--enroll``, ``--attest``.

A verb that fails with an error code exits with status 1; the statuses of
the daemon are in :doc:`index`.

Daemon control
==============

These verbs talk to the running daemon over ``/run/lota/lota.sock``
(:doc:`ipc`), so the caller needs access to the socket.

``--shutdown``
  Asks the daemon to stop and waits up to 60 seconds for its PID file to be
  released. It prints ``Agent stopped.`` and exits with status 0; a daemon
  still running after the wait gives status 1. The daemon spends PCR 14 as
  it stops, so it starts again only after a reboot (:doc:`lifecycle`).

``--status``
  Prints the daemon's mode, status flags, applied policy keys, last
  attestation time, token expiry and attestation counts, as any caller of
  the socket reads them.

``--terminate-protected PID``
  Asks the daemon to end a protected process with ``SIGTERM``, or with
  ``SIGKILL`` when ``--force`` is given. The owner of the process or root
  may ask. The daemon reports the end to the publisher until the host
  reboots (:doc:`protection`). PID is a positive decimal number; anything
  else gives ``Invalid PID:``.

``--force``
  With ``--terminate-protected``: send ``SIGKILL``.

Attestation
===========

``--attest``, ``-a``
  Sends attestation reports. With publisher profiles in the configuration,
  or with no verifier named at all, it runs as a loop at the interval
  below and keeps running. With only ``--server`` or the file's ``server``
  key and no interval it sends one report and exits. With profiles it
  refuses ``--server`` and ``--pin-sha256``: each profile names its own
  verifier and pin.

``--attest-interval SECS``, ``-I SECS``
  The loop interval: 0, or 30 to 240. A value out of range ends the
  command. 0 means the default: 240 seconds for profiles or for no verifier,
  one report for a single verifier. The option also implies ``--attest``,
  and with ``--add-publisher`` it sets the profile's interval.

``--server HOST``, ``-s HOST``
  The verifier. No default.

``--port PORT``, ``-p PORT``
  The verifier port, 1 to 65535. Default 8443.

``--ca-cert PATH``, ``-C PATH``
  The publisher's CA trust anchor, PEM or DER. It verifies the TLS peer in
  place of the system CA store, and it names the publisher profile that
  holds the AIK certificate, so ``--enroll`` needs it.

``--pin-sha256 HEX``, ``-F HEX``
  Pins the verifier's certificate by its SHA-256 fingerprint: 64 hex
  digits, with colons or spaces allowed. A pin that does not parse ends the
  command.

``--no-verify-tls``, ``-K``
  Turns off verification of the peer's certificate. ``--enroll`` and
  ``--attest`` refuse it without ``--insecure-allow-no-verify-tls``. A pin
  still applies.

``--insecure-allow-no-verify-tls``
  Acknowledges ``--no-verify-tls``.

Publishers
==========

``--enroll``
  Enrolls the AIK with the publisher's attestation CA by credential
  activation and stores the certificate it issues in the publisher's
  profile. It needs ``--ca-server`` and ``--ca-cert``. Running it records
  the consent of the user who runs it, as ``--allow-publisher`` does.

``--ca-server HOST``
  The attestation CA.

``--ca-port PORT``
  The CA port, 1 to 65535. Default 8444.

``--enroll-token-file PATH``
  A file with the enrollment token of a tenant, presented to the CA during
  ``--enroll``. ``--reenroll`` and certificate renewal reuse the token, not
  the path.

``--reenroll``
  Enrolls again each publisher whose certificate does not name the key at
  its handle, at the endpoint and with the anchor its ``--enroll``
  recorded.

``--publisher ID``
  With ``--reenroll``: that publisher alone. A ``--ca-server``,
  ``--ca-port`` or ``--ca-cert`` given on the command line then replaces
  the recorded one.

``--add-publisher HOST``
  Writes a publisher profile into the configuration file. HOST is the
  publisher's attestation CA, ``--ca-cert`` its trust anchor, ``--server``
  and ``--port`` its verifier; without ``--server`` the profile names no
  verifier. It records no consent.

``--publisher-name NAME``
  With ``--add-publisher``: the profile's name. Default: a prefix of the
  publisher identity.

``--reporting MODE``
  With ``--add-publisher``: ``session`` (the default) reports only while a
  title of that publisher runs, ``continuous`` reports always. Another value
  ends the command.

``--allow-publisher HEX``
  Records consent for one publisher, named by the SHA-256 of its CA trust
  anchor's public key. The agent enrolls with no publisher on its own before
  consent is recorded.

``--list-publishers``
  Lists every publisher this host answers to, what it stores for each, and
  when consent was given.

``--forget-publisher HEX``
  Destroys the publisher's AIK and everything stored for it. The publisher
  needs consent and a new key to be answered again.

TPM and sealing
===============

The TPM verbs are described in :doc:`tpm`.

``--test-tpm``, ``-t``
  Reports on the TPM operations and exits. It creates no persistent key; it
  skips the quote when the attestation handle is free. When PCR 14 waits for
  this boot's commitment, it extends the register as the daemon does.

``--seal``
  Reads a secret from standard input, seals it to the PCR state and writes
  the sealed blob to standard output. Up to 128 bytes are sealed directly;
  up to 64 KiB go into an envelope of a sealed key and AES-256-GCM. An
  empty secret is refused.

``--unseal``
  Reads a sealed blob from standard input and writes the secret to standard
  output. It fails when the PCR state differs from the one sealed to.

``--seal-pcrs MASK``
  The PCR mask for ``--seal``, in C notation (``0x83``, ``131``). It is not
  empty and names no PCR above 23. Default 0x83: PCRs 0, 1 and 7. 0x4083
  adds PCR 14, which binds the secret to a boot state that includes the
  agent's commitment: any process with TPM access unseals while the
  registers match, and an upgrade of the agent makes it unreadable.

``--seal-aik-auth``
  Seals the AIK authorization value to the current boot state.

``--reprovision-aik``
  Rotates the AIK authorization value and seals it again after a change of
  the boot state. The key stays the same; when one changes, the command
  names the ``--reenroll --publisher`` command for it.

``--seal-persist-primary``
  Stores the seal storage primary key at a persistent handle. Seal and
  unseal use it, and skip ``CreatePrimary``, with
  ``seal_persistent_primary = true`` in the configuration.

``--seal-evict-primary``
  Removes that key. Blobs sealed before stay valid.

Diagnostics
===========

``--dump-config``, ``-Z``
  Prints the configuration as the file and the options together set it, and
  exits.

``--test-iommu``, ``-i``
  Checks the IOMMU, prints what it found and ``PASSED`` or ``FAILED``, and
  exits with status 0 or 1.

``--export-policy``, ``-E``
  Writes a YAML policy of the running system to standard output, for the
  verifier. It opens the TPM and performs the self-measurement.

``--test-ipc``, ``-c``
  Runs the IPC server without a TPM, in a simulated attested state, until
  interrupted. It answers status, D-Bus and profile binding; it refuses
  ``GET_TOKEN``.

``--test-signed``, ``-S``
  Runs the IPC server with tokens signed by the TPM, until interrupted.

Daemon options
==============

``--config PATH``, ``-f PATH``
  The configuration file. Default ``/etc/lota/lota.conf``.

``--bpf PATH``, ``-b PATH``
  The enforcement object. Default ``/usr/lib/lota/lota_lsm.bpf.o``; its
  signature is the same path with ``.sig`` appended.

``--mode MODE``, ``-m MODE``
  ``enforce`` refuses what the policy refuses; ``monitor`` logs it. The mode
  changes the policy alone: the agent and the protected processes are
  guarded in both, and the agent refuses every signal that would end it,
  from root too. A mode weaker than the file's ``enforce`` needs
  ``--insecure-allow-mode-downgrade``. Another value ends the command.

``--insecure-allow-mode-downgrade``
  Acknowledges a ``--mode monitor`` below the file's ``enforce``.

``--insecure-allow-mutable-rootfs``
  Starts with a warning when ``/dev/tpmrm0`` or ``/dev/tpm0`` lacks the
  SELinux label ``lota_tpm_device_t``; another root domain can then hold
  the TPM resource manager.

``--strict-mmap``, ``-M``
  Refuses an executable ``mmap`` of a library that is not trusted.

``--strict-exec``, ``-Y``
  Enforces the strict executable policy, with the fs-verity allow list.

``--block-ptrace``, ``-P``
  Refuses every ptrace attach.

``--strict-modules``, ``-J``
  Enforces the strict policy for loading kernel modules and firmware.

``--block-anon-exec``, ``-X``
  Refuses anonymous executable mappings.

The five switches above take effect in ``enforce`` mode alone.
``--strict-exec`` and ``--strict-modules`` refuse to start without an
``--allow-verity`` entry.

``--bench``
  Writes the agent's cost to ``/run/lota/bench.json`` each second. It
  changes no policy; the status word and the attestation report say it is
  on.

``--protect-pid PID``, ``-R PID``
  Adds PID to the daemon's protected set, with ptrace refused. The daemon
  reads it at start alone. The process has to be running then; a PID that
  names none is refused before PCR 14 is spent. At most 1024 entries,
  counting the file's. A process protects itself through the SDK with
  ``lota_protect_self()``.

``--trust-lib PATH``, ``-L PATH``
  Adds a library to the trusted list. At most 64 entries, counting the
  file's.

``--allow-verity PATH``, ``-A PATH``
  Adds a file protected by fs-verity to the allow list, by its digest. At
  most 256 entries, counting the file's.

``--daemon``, ``-d``
  Forks into the background. Under systemd it is not needed.

``--pid-file PATH``, ``-D PATH``
  The PID file. Default ``/run/lota/lota-agent.pid``.

The paths of ``--trust-lib`` and ``--allow-verity`` are absolute, have no
``..`` segment and no control characters.

Policy signing
==============

``--gen-signing-key PREFIX``, ``-G PREFIX``
  Generates an Ed25519 key pair, ``PREFIX.key`` and ``PREFIX.pub``. An
  existing file is not overwritten.

``--sign-policy FILE``, ``-g FILE``
  Signs a YAML policy with ``--signing-key`` and writes ``FILE.sig``.

``--signing-key PATH``, ``-k PATH``
  The Ed25519 private key, PEM.

``--verify-policy FILE``, ``-V FILE``
  Verifies ``FILE.sig`` against FILE.

``--policy-pubkey PATH``, ``-Q PATH``
  The Ed25519 public key, PEM. It verifies both policy signatures and the
  signature of the enforcement object. Without it the agent takes
  ``policy_pubkey`` from the file, then ``/etc/lota/policy.pub``, then
  ``/usr/lib/lota/enforcement.pub``, the first one it can read.

Environment
===========

``LOTA_TCTI``
  A TCTI configuration string for the TPM in place of ``/dev/tpmrm0``.

``LOTA_AIK_META_PATH``
  The host AIK record in place of ``/var/lib/lota/aik_meta.dat``: an
  absolute path of letters, digits, ``/``, ``.``, ``_`` and ``-``, without
  ``..``.

``LOTA_UEFI_FIRMWARE_PATH``
  The path whose presence says the host booted via UEFI, in place of
  ``/sys/firmware/efi``.

The three variables above are read by the one-shot verbs and by an
``--attest`` that sends one report. The daemon and the ``--attest`` loop
ignore them (:ghsrc:`src/agent/attest.h`).

``NOTIFY_SOCKET``
  The systemd notification socket. The agent accepts
  ``/run/systemd/notify``, ``/run/user/<uid>/systemd/notify`` for its own
  UID, and ``@org/freedesktop/systemd1/notify``. The first socket and its
  directory are owned by root, the second by that UID, and the directory is
  not writable by group or others. Any other value is dropped, and the agent
  sends systemd no notification.

``JOURNAL_STREAM``, ``INVOCATION_ID``
  Tell the agent it runs under systemd, with its output in the journal
  (:doc:`journal`).

``TSS2_LOG``
  The publisher verbs and ``--enroll`` set it to ``all+none`` when it is
  not set, so the TPM library adds no lines to their output.
