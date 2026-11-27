.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

============
PCR policies
============

A PCR policy is the YAML file that says what the verifier accepts from a
host: which PCR values, kernel images and agent builds, and which kernel
security features the host must run with. The verifier reads it with
``--policy`` at start (`command-line.rst
<../Documentation/verifier/command-line.rst>`__) and checks every report
against it (`index.rst <../Documentation/verifier/index.rst>`__). The parser
is ``src/verifier/verify/pcr.go``.

Templates
=========

``testing.yaml``
  Pins nothing and requires nothing. The verifier loads it only with
  ``--allow-permissive-policy``.

``production.yaml``
  Requires IOMMU, enforce mode, Secure Boot and the command line denylist,
  with ``profile: enterprise``. The PCR pins and the agent hash ship commented
  out, so the file as shipped loads only with ``--allow-permissive-policy``
  and ``--allow-unpinned-agent``; fill in one of them first (`Choosing the
  pins`_).

``strict.yaml``
  Sets every ``require_*`` key and pins PCR 0, 1 and 7. The pins ship as
  ``REPLACE_WITH_...`` placeholders, which stop the verifier at start until
  they hold digests.

Loading
=======

Each ``--policy`` file is read once, at start; a changed file takes effect
when the verifier restarts. The file is read in this order, and the first
failure stops the verifier:

#. The file is at most 64 KiB.
#. With ``--policy-pubkey``, ``PATH.sig`` holds a 64-byte raw Ed25519
   signature over the bytes read (`Signing`_).
#. The YAML parses, holds no second document with content, and every key
   is one of `Keys`_. A misspelt key stops the verifier with its name and
   line.
#. Each ``pcrs`` index is between 0 and 23, and each ``pcrs`` value and
   ``kernel_hashes`` and ``agent_hashes`` entry is 64 hex digits, kept in
   lower case. ``profile`` is empty, ``enterprise`` or ``consumer``.
#. Without ``--allow-permissive-policy``, the policy pins a PCR, a kernel
   hash or an agent hash.
#. Without ``--allow-unpinned-agent``, a policy that sets
   ``require_secureboot`` and pins no PCR lists an agent hash. With neither,
   the first agent hash a host reports would be pinned unchecked.
#. ``tenant`` is empty or a valid tenant name (`multi-tenancy.rst
   <../Documentation/admin-guide/multi-tenancy.rst>`__).
#. No other file binds the same ``tenant``, and no file loaded before it has
   the same ``name``.

A policy that leaves a check open is logged as a warning and loads:

* ``no PCR values defined -> any PCR set will pass``;
* ``no kernel/agent hash allowlists -> any binary accepted``;
* ``no security requirements enabled -> effectively permissive``, when it
  pins no PCR and sets no ``require_*`` key.

The first file is the active policy. It verifies every client whose tenant
binds no policy of its own. A later file reaches clients only through its
``tenant`` key, and the verifier warns about one that has none. With no
``--policy`` at all the verifier refuses to start, unless
``--allow-permissive-policy`` loads the built-in ``default`` policy, which
sets ``require_iommu``, ``require_enforce`` and ``require_module_sig`` and
pins nothing. ``--report-only`` reads no policy, and ignores a ``--policy``
given to it.

Keys
====

``name``
  The policy's name, used in logs and in the decision log. Unique among the
  loaded files.

``description``
  Free text. The verifier does not read it.

``tenant``
  Binds the policy to clients whose AIK certificate names this tenant. Empty
  binds none.

``profile``
  ``enterprise``, the default, or ``consumer``. ``consumer`` turns on
  self-service re-anchor of a drifted PCR 0, 1 and 7 baseline for the
  policy's tenant ("Re-anchor" in `index.rst
  <../Documentation/verifier/index.rst>`__). It moves a baseline only under
  ``require_secureboot`` and only when the event log proves Secure Boot on.
  ``--enable-self-service-reanchor``, when given, overrides the profile of
  every policy.

``pcrs``
  A map of PCR index to the expected SHA-256 value, 64 hex digits. Each
  pinned PCR joins the challenge mask, and a report whose value differs is
  refused with ``pcr_fail``. The verifier logs ``policy verification
  failed`` with every mismatch, in index order, digests in full::

    PCR 0 mismatch: got 3d45..., expected 9a1f...; PCR 7 mismatch: got ...

  The verifier holds PCR 0, 1 and 7 as a per-client baseline, and PCR 14
  against its boot commitment. A client's first round sets the baseline
  when the policy pins PCR 0, 1 and 7, when the baseline store already holds
  the client, when ``require_secureboot`` holds on the event log, or under
  ``--allow-tofu-boot-baseline``. Otherwise the round is refused with
  ``boot baseline not enrolled``.

``kernel_hashes``
  SHA-256 digests of the kernel images a host may boot, 64 hex digits each.
  The digest compared is the one the boot loader measured into PCR 9, taken
  from the event log; the report's own kernel hash is not used. A host
  whose log measures no kernel image, two different ones, or whose PCR 9 is
  not quoted or does not replay is refused with ``kernel_image_required``,
  as is one whose image is not listed. Every kernel update needs a new
  entry. Empty skips the check.

``agent_hashes``
  SHA-256 digests of the agent builds a host may run, 64 hex digits each. A
  host reporting a hash off the list is refused with ``integrity_mismatch``
  and the log line ``agent hash not in allowed list``. A listed hash other
  than the client's pinned one moves the pin (`agent-update.rst
  <../Documentation/admin-guide/agent-update.rst>`__). Empty skips the list;
  the agent hash is then pinned on first use.

``require_iommu``
  The agent reports DMA remapping on, or the round is ``iommu_fail``.

``require_enforce``
  The agent runs in enforce mode, or the round is ``enforce_required``.

``require_module_sig``
  The kernel enforces module signatures, or the round is
  ``module_sig_required``.

``require_secureboot``
  The event log carries the ``SecureBoot`` variable the firmware measured
  into PCR 7, with value 1, and PCR 7 is quoted and replays. Otherwise the
  round is ``secureboot_required``. The Secure Boot flag the agent reports
  is not read. The key also gives a first round its boot baseline without
  a PCR pin ("Baselines" in `index.rst
  <../Documentation/verifier/index.rst>`__).

``require_cmdline_policy``
  Each kernel command line measured into PCR 8 is free of the denylist
  (`Command line denylist`_), or the round is ``cmdline_required``. PCR 8
  joins the challenge mask.

``cmdline_deny``
  Rules added to the built-in denylist, in its rule forms. Read only with
  ``require_cmdline_policy``.

``require_lockdown``
  Kernel lockdown is in integrity or confidentiality mode, or the round is
  ``lockdown_required``.

``require_ima_appraisal``
  IMA appraises executables in a blocking mode, or the round is
  ``ima_appraisal_required``. The agent counts an ``appraise`` rule on
  ``BPRM_CHECK`` or with no ``func=``, with Secure Boot on, or with no
  ``ima_appraise=off``, ``log`` or ``fix`` on the command line. A stock host has
  no such rule and no signed files, so the key refuses it.

``require_iommu``, ``require_enforce``, ``require_module_sig``,
``require_lockdown`` and ``require_ima_appraisal`` read flags of the agent's
own report (`report-format.rst
<../Documentation/verifier/report-format.rst>`__), so they hold what the
agent saw. ``require_secureboot`` and ``require_cmdline_policy`` read the
event log the quote binds.

The checks run in the order of the list above, from ``pcrs`` on, and the
first that fails gives the verdict.

Command line denylist
=====================

The built-in rules (``src/verifier/verify/kernel_trust.go``):

======================== ==============================================
Rule                     Matches
======================== ==============================================
``init=``, ``rdinit=``   Another first process, with any value.
``rd.break``             The initramfs shell before the root switch.
``lockdown=none``        Lockdown off.
``module.sig_enforce=0`` Unsigned modules allowed.
``selinux=0``            SELinux off.
``enforcing=0``          SELinux permissive.
``apparmor=0``           AppArmor off.
``security=none``        No major security module.
``systemd.debug_shell``  A root shell on a virtual console.
``kgdboc=``              The kernel debugger on a console.
======================== ==============================================

A rule takes one of two forms:

``param`` or ``param=``
  The parameter alone or with any value.

``param=value``
  That exact pair.

A ``-`` in a parameter name matches ``_``, as in the kernel. The command line
is split on whitespace alone, so a denied parameter inside a quoted value
matches too.

The verifier reads the command lines from the PCR 8 ``EV_IPL`` events whose
digest covers their text: GRUB's ``kernel_cmdline:`` and ``grub_cmd: linux``
events. It checks every line it finds, since the log does not say which one
booted. The round is refused when PCR 8 is not quoted or does not replay,
when an event's digest does not cover its text, or when PCR 8 is non-zero and
the log holds no command line. A quoted PCR 8 of zero that no event extends,
as on systemd-boot or a UKI, skips the check.

Exporting a policy
==================

``lota-agent --export-policy`` writes a policy of the host it runs on to
standard output (``src/agent/policy.c``):

.. code-block:: sh

   sudo lota-agent --export-policy > fleet.yaml

The file holds:

* ``name: <hostname>-baseline`` and a description naming the host;
* ``pcrs`` with PCR 0, 1, 4, 7 and 11 as the TPM reads them now;
* ``kernel_hashes`` with the image digest from the PCR 9 event log, or an
  empty list and a comment saying why there is none;
* ``agent_hashes`` with the SHA-256 of the running agent binary;
* each ``require_*`` key except ``require_cmdline_policy``, set to what the
  host has now. ``require_enforce`` is the mode the configuration or
  ``--mode`` sets.

It writes no ``tenant``, ``profile``, ``require_cmdline_policy`` or
``cmdline_deny``. The pins describe this host's boot chain: a host that
differs, or this one after a firmware or boot loader update, is refused.
Review the file before loading it.

Choosing the pins
=================

Identical machines
  Pin PCR 0, 1 and 7 from a reference host. A machine whose firmware or
  Secure Boot state differs is refused on its first round, and the pins also
  give it its boot baseline. Keep ``profile`` at ``enterprise``: a pinned
  PCR fails the policy check before any re-anchor is tried.

Machines with their own firmware each
  Pin no PCR. Set ``require_secureboot`` and ``require_cmdline_policy``,
  which read the event log and fit every machine, list the agent builds in
  ``agent_hashes``, and set ``profile: consumer`` so a firmware update moves
  the baseline. Each machine's first round pins its own PCR 0, 1 and 7.

``kernel_hashes`` binds the exact kernel image and needs an entry per kernel
update. PCR 7 changes when the Secure Boot keys or state do, and when shim
measures a new SBAT level or MOK list, as a shim update can. A kernel signed
by the same key leaves it as it is.

No template pins PCR 8. GRUB measures there the commands it runs, whose
arguments carry values from ``grubenv``, so PCR 8 differs between healthy
boots. ``require_cmdline_policy`` checks the command line from its event log
instead.

Signing
=======

With ``--policy-pubkey`` the verifier loads only a policy signed by that key
(`verifier command line <../Documentation/verifier/command-line.rst>`__). The
agent makes the key and the signature (`agent command line
<../Documentation/agent/command-line.rst>`__):

.. code-block:: sh

   lota-agent --gen-signing-key policy
   lota-agent --sign-policy fleet.yaml --signing-key policy.key
   lota-verifier --policy fleet.yaml --policy-pubkey policy.pub ...

``--sign-policy`` writes ``fleet.yaml.sig`` beside the file. The signature
covers every byte, comments and ``tenant`` included, so any edit needs a new
signature.

Updating
========

Add a new agent build to ``agent_hashes`` before hosts boot it and keep the
old one until the fleet has moved (`agent-update.rst
<../Documentation/admin-guide/agent-update.rst>`__). Add a new kernel image to
``kernel_hashes`` the same way, when the list is in use. Then sign the file
again and restart each verifier instance.
