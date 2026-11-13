.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=========================
Runtime image measurement
=========================

Runtime image measurement: which numbers identify a mapping
===========================================================

Measuring a protected process's executable images means enumerating its
mappings from ``/proc/<pid>/maps``, opening each through
``/proc/<pid>/map_files/<range>``, and confirming the handle still describes
what was enumerated. That confirmation is the contract, and it is easy to get
wrong in a way that only shows on some filesystems.

**A device number from ``/proc/<pid>/maps`` and one from ``stat()`` are not the
same quantity.** ``maps`` prints the filesystem's ``s_dev``; ``stat()`` returns
whatever the filesystem chooses to report, and btrfs reports a separate
anonymous device per subvolume. For one live mapping on a btrfs root the two
differ, so code that compares one against the other rejects every mapping on
that host -- silently, since the rejection looks like a mapping that moved.

The identity is therefore built from numbers of one kind:

* the device and inode of the enumerated range, and the device and inode of the
  range re-read from ``/proc/<pid>/maps`` after the handle was opened, are
  compared with each other -- same API, same meaning;
* the opened handle's own inode is compared against the enumerated inode, which
  is what ties the file being measured to the range that was enumerated.

Both halves are load-bearing. Dropping the device comparison would accept the
same inode number appearing on another filesystem; dropping the handle's inode
would accept a measurement of whatever the range points at now.

The same rule decides **which mapping is the process's own executable**, and
that decision is not cosmetic: an executable that cannot be measured fails the
measurement, while a library that cannot be measured is coverage the relying
party judges. The measurement therefore reports the identity of the handle it
opened (``struct lota_rt_open_identity``, a ``stat()`` device and inode) and
the caller compares that against a ``stat()`` of ``/proc/<pid>/exe``. Comparing
either against a number parsed out of ``maps`` recognises no executable at all
on a per-subvolume-device filesystem, which downgrades the fatal case to a
coverage note and makes the refusal name whichever object was recorded last.

A mapping the agent cannot open, or one that no longer resolves to the inode
enumerated, is a gap of the same kind and never contributes a digest. Its
handle gives no identity, so it stops the measurement only when no mapping
measured as the executable; the refusal then carries the errno of the open.

Runtime measurement coverage
============================

Every token folds a kernel-anchored measurement of the live code of each
protected process, and that measurement can cover an object only when the
kernel holds an fs-verity digest for it. What a platform provides therefore
decides how much of a process's code the measurement can account for.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Platform
     - Coverage
   * - A title's own binaries
     - Full, on any verity-capable filesystem. Whoever ships the title
       enables it, with ``lota-install --verity-manifest`` or the
       equivalent in their own packaging. A store install nothing measured
       takes the second road: the kernel hashes that executable's content
       and the token sets ``LOTA_FLAG_IMAGE_CONTENT_HASHED``. With no digest
       and a filesystem the host does not serve itself (FUSE, a network
       mount), the agent refuses the token with
       ``LOTA_ERR_UNMEASURABLE_SELF``. Another protected process being
       unmeasurable never refuses this caller, since any local program may
       ask for protection; it clears the coverage flag instead. So does
       memory with no file behind it, such as the memfd Wine maps Windows
       images out of: no digest can exist for it.
   * - Distribution libraries on a package-managed host
     - **None, today.** Fedora ships ``libc``, ``libcurl`` and the rest
       without fs-verity, so those objects are absent from the fold and the
       token reports partial coverage
       (``LOTA_FLAG_IMAGE_FULLY_MEASURED`` clear). They are never
       content-hashed, as a mapped library stays writable. Enabling verity
       on them by hand lasts until the next update of the owning package, which
       replaces the inode and the digest with it. Whether partial coverage
       is acceptable is the relying party's policy.
   * - Image-based and composed filesystems
     - Not consumed yet. An image-based host (composefs, an OSTree
       deployment, a dm-verity root) already carries per-file or
       whole-image integrity, and consuming that as measurement evidence
       would give full coverage without per-file enablement. LOTA does not
       read those sources today; a protected process on such a host reports
       coverage over whatever fs-verity digests are present.

A relying party that requires full coverage asks for
``LOTA_FLAG_IMAGE_FULLY_MEASURED`` and, on a package-managed host, will not
get it. One that requires fs-verity for the title's own executable refuses
``LOTA_FLAG_IMAGE_CONTENT_HASHED`` and loses every unmeasured store install.
Both are statements about the platform, not about the machine
concealing anything: an unmeasurable object is reported as unmeasured and is
never folded in as though it had been measured.

What the agent journals about it
--------------------------------

The agent writes a line when its answer about a process changes, not every
token round. A title that cannot be measured is reported when it starts and
when the reason changes; recovery is reported too, with how many rounds the
failure held. Repeated rounds are counted in the shutdown statistics as
``Runtime measurement reports: repeated=``. A quiet journal means the answer
did not change; each token still carries that round's coverage.

The line names the object by full path and says whether it is the process's
executable (token refused) or a mapped object (coverage partial). The path
stays in the log; the runtime image digest folds only the ``soname``.
