.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============
Configuration
=============

The agent reads one configuration file at the start of every invocation:
``/etc/lota/lota.conf``, or the file ``--config`` names. The file sets what
the options of :doc:`command-line` also set, holds the publisher profiles,
and carries the few settings no option reaches. The parser is
:ghsrc:`src/agent/config.c`; :ghsrc:`configs/lota.conf.example` lists every
key with a comment.

File
====

The package does not own ``/etc/lota/lota.conf``; an upgrade never replaces
it. ``--add-publisher`` appends profiles to it, and grows it to at most
262144 bytes.

The agent opens the file with ``O_NOFOLLOW``, so a symbolic link in its
place is refused. It loads the file only when the file is regular, neither
group- nor world-writable, and owned by root; a caller other than root also
accepts a file it owns itself.

A missing default file is no error and leaves every key at its default. A
default file the caller cannot read gives a warning and the defaults. A file
``--config`` names must exist and be readable. Any other failure, including a
single bad line, ends the command with status 1.

Syntax
======

The file is lines of ``key = value``. Whitespace around the key and the value
is dropped. A line whose first character after leading whitespace is ``#`` is
a comment, and so is an empty line; a ``#`` later in a line is part of the
value. A line is at most 1022 characters; a longer one is an error.

Every key also has a spelling with ``-`` in place of ``_``, and ``bpf_path``
also answers to ``bpf``. A boolean takes ``true``, ``yes`` or ``1`` and
``false``, ``no`` or ``0``.

A path is absolute, holds no ``..`` component and no control character, and
is taken as written: symbolic links in it are not resolved. An empty value
clears a single path key. A list key adds one entry per line, and refuses an
empty value.

The parser reports every bad line with its file and line number and goes on
to the end, so one pass shows every problem. A file with any error is refused
whole: an unknown key, a line with no ``=``, an empty key, a value out of
range or too long, or a profile that does not validate.

Keys
====

Keys before the first ``[profile ...]`` header are top-level keys. The last
column says what ``SIGHUP`` does with a changed value (`Reloading`_).

.. list-table::
   :header-rows: 1
   :widths: 24 50 26

   * - Key
     - Value
     - On reload
   * - ``server``
     - Verifier host for a report with no profile. No default.
     - Next start.
   * - ``port``
     - Its port, 1 to 65535. Default 8443.
     - Next start.
   * - ``ca_cert``
     - Path of the CA certificate the verifier's TLS chain must reach.
     - Next start.
   * - ``pin_sha256``
     - SHA-256 of the verifier's certificate: 64 hex characters, colons and
       spaces allowed. Refused when the file has profiles.
     - Next start.
   * - ``no_verify_tls``
     - Always refused; the command line alone turns TLS verification off.
     - --
   * - ``mode``
     - ``monitor`` or ``enforce``. Default ``enforce``.
     - Applied.
   * - ``strict_mmap``, ``strict_exec``, ``block_ptrace``,
       ``strict_modules``, ``block_anon_exec``
     - Booleans, default false. In effect only in ``enforce`` mode;
       ``strict_exec`` and ``strict_modules`` also need ``allow_verity``
       entries.
     - Applied.
   * - ``allow_verity``
     - List, at most 256: a file whose fs-verity digest the agent allows.
       The paths are measured at startup.
     - Next start.
   * - ``trust_lib``
     - List, at most 64: a library path the agent trusts.
     - Applied.
   * - ``protect_pid``
     - List, at most 1024: a PID, 1 to 4294967295, to protect.
     - Applied.
   * - ``bpf_path``
     - Path of the enforcement object. Default
       ``/usr/lib/lota/lota_lsm.bpf.o``.
     - Next start.
   * - ``policy_pubkey``
     - Path of the key that verifies the object's signature, and the
       file's own signature on a reload that leaves ``enforce``.
     - Next start.
   * - ``bench``
     - Boolean, default false: write ``/run/lota/bench.json``.
     - Next start.
   * - ``attest_interval``
     - Seconds between reports: 0, or 30 to 240. Default 0 (`Intervals`_).
     - Next start.
   * - ``aik_handle``
     - Persistent handle of the host AIK, in any base, nonzero, at most
       0xffffffff. Default 0x81010002.
     - Next start.
   * - ``seal_aik_auth``
     - Boolean, default false: also keep the AIK authorization sealed to
       PCRs, and try that copy first.
     - Next start.
   * - ``seal_aik_auth_strict``
     - Boolean, default false: seal the AIK authorization, remove the
       plaintext copy, and use no other.
     - Next start.
   * - ``seal_persistent_primary``
     - Boolean, default false: seal under the persistent primary key in
       place of a transient one (:doc:`tpm`).
     - Next start.
   * - ``kernel_path``
     - Path of the kernel image the report names. Default
       ``/boot/vmlinuz-`` followed by the running release.
     - Next start.
   * - ``container_listener_uid``
     - List, at most 4, no repeats: a user, 0 to 4294967295, served an IPC
       socket at ``/run/user/<uid>/lota/lota.sock``. With no entry the
       agent serves one in its own ``XDG_RUNTIME_DIR``, when that is set
       (:doc:`ipc`).
     - Next start.
   * - ``daemon``
     - Boolean, default false: detach as ``--daemon`` does.
     - Next start.
   * - ``pid_file``
     - Path of the PID file. Default ``/run/lota/lota-agent.pid``.
     - Next start.
   * - ``log_level``
     - ``error``, ``warn``, ``info`` or ``debug``. Default ``info``.
     - Applied.

The command line wins over the file for a single value, and adds to the
file's lists (:doc:`command-line`). ``--dump-config`` prints what the two
set together.

Intervals
---------

``attest_interval`` and ``--attest-interval`` are 0, or 30 to 240 seconds.
The ceiling keeps a token the agent mints inside every relying party's
freshness window. With 0, ``--attest`` reports once to a ``server`` named
with no profile, and every 240 seconds to publisher profiles.

Publisher profiles
==================

A ``[profile "name"]`` header opens a profile, and every key up to the next
header belongs to it. A profile describes one publisher: its CA, which
enrolls the host, and its verifier, which takes the reports
(:doc:`publishers`).

The name is not empty, is shorter than 64 characters and holds no ``"`` and
no control character. A file has at most 8 profiles and no two with the same
name. A header that does not parse, or names a section other than
``profile``, is an error, and the keys under it are not read.

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Key
     - Value
   * - ``ca``
     - Host of the publisher's CA. Required.
   * - ``ca_port``
     - Its port. Default 8444.
   * - ``ca_cert``
     - Path of the CA's trust anchor. Required. Its key names the
       profile's state directory (:doc:`index`).
   * - ``verifier``
     - Host of the publisher's verifier, without a port. Required.
       ``none`` makes the profile token-only: no report is sent, while the
       profile still enrolls, keeps its AIK and renews its certificate.
   * - ``verifier_port``
     - Its port. Default 8443. Refused with ``verifier = none``.
   * - ``pin_sha256``
     - SHA-256 of the verifier's certificate, as at top level.
   * - ``reporting``
     - ``session`` (default): report while a title bound to the publisher
       is connected. ``continuous``: report all the time.
   * - ``interval``
     - Seconds between reports to this publisher, as ``attest_interval``.
       0 takes the top-level value.

.. code-block:: ini

   mode = enforce
   log_level = info

   [profile "example"]
   ca = ca.example.net
   ca_cert = /etc/lota/example-ca.pem
   verifier = verifier.example.net

Reloading
=========

``SIGHUP`` makes the daemon and the ``--attest`` loop read the file again.
A file that does not load leaves the running state untouched, and a missing
file is a warning.

The daemon applies a changed ``mode``, the five switches, ``protect_pid``,
``trust_lib``, ``log_level`` and the profiles at once. A reload that leaves
``enforce`` needs ``policy_pubkey`` set in the file the daemon started with,
and a ``<file>.sig`` beside the file that verifies under that key; otherwise
the reload is refused whole. A switch, library or PID given on the command
line stays in effect even when the file drops it.

Every key marked "Next start" keeps the value the agent started with. For
``allow_verity``, ``bench``, the three ``seal_*`` keys, ``kernel_path``,
``policy_pubkey``, ``aik_handle`` and ``container_listener_uid`` the agent
logs that the change waits for the next start.

The ``--attest`` loop rebuilds its publisher list from the profiles and
keeps everything else. A loop started with ``--pin-sha256`` and no profiles
refuses a reload that adds profiles, and goes on reporting to its server.
