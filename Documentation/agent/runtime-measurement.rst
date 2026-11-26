.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=========================
Runtime image measurement
=========================

The agent measures the code a protected process runs: every file-backed
executable mapping of the process, each by a digest the kernel produces over
the file behind it, never by reading the process's memory. The result feeds
the registry digest a token carries for the process (:doc:`protection`) and
the coverage flags of the status and of every token. The code is
:ghsrc:`src/agent/runtime_image_measure.c`.

When it runs
============

Every ``GET_TOKEN`` round measures the whole protected set; the token keeps
the processes of the caller's instance (:doc:`tokens`). The status answer
counts coverage over the whole set, and keeps the count until the set
changes or a protected process maps code again.

An executable mapping a protected process makes, allowed or refused, also
measures that process again for the journal alone, at most once a second per
process (`Journal`_).

Enumeration
===========

The agent reads ``/proc/<pid>/maps`` and keeps every executable mapping with
an inode and a path; anonymous memory and regions such as ``[vdso]`` carry
no file and are skipped. Each backing inode counts once. At most
``LOTA_RUNTIME_IMAGE_MAX_MODULES`` (512) objects are taken, in address
order; the mappings past them are counted, left unmeasured, and mark the
registry ``LOTA_IPC_REGISTRY_TRUNCATED``.

Each object is opened through ``/proc/<pid>/map_files/<start>-<end>``, by its
range and never by the path ``maps`` prints, and must be a regular file.
After every object is open the agent reads ``maps`` a second time. An object
is the one enumerated when its range in the second read shows the same
device and inode as in the first, and the opened handle's inode is that
inode; otherwise it is unmeasured (``ESTALE``).

Both devices come from ``maps``. ``stat()`` reports a device of its own
choosing, and a filesystem with a device per subvolume, such as btrfs,
reports another one than ``maps`` does, so the two are never compared.

The process's executable is the opened object whose ``fstat()`` device and
inode equal a ``stat()`` of ``/proc/<pid>/exe``: two numbers of the same
kind. A process whose ``/proc/<pid>/exe`` does not stat is not measured, and
the failure names the link's target.

Digests
=======

An object is measured by the first of two roads that applies.

fs-verity
  ``FS_IOC_MEASURE_VERITY`` on the open handle. The digest is SHA-256 or
  SHA-512; another length is refused and named. The kernel fixes the content
  of a verity file, so the digest is cached under the file's device, inode,
  size and modification time.

Content hash
  With no fs-verity digest, the kernel hashes the file's content through
  ``bpf_ima_file_hash()``, on a filesystem this host serves itself: ext4,
  XFS, btrfs, overlayfs and tmpfs. A filesystem served by userspace or a
  peer, such as FUSE or a network mount, may hand the hash and the page
  fault different bytes and gets no content hash. The hash is taken only
  while nothing can write the file:

  * the process's executable, which the kernel keeps unwritable while it
    runs;
  * a mapped object the agent pins: the size and change time the kernel
    recorded at the mapping still match the file, no writer holds it, and
    the enforcement object then refuses every open of it for write. A pin
    lasts while a round reaches the object, and the end of a round releases
    the pins it leaves unreached. Renaming another file over a pinned one
    works and leaves another inode.

  The kernel answers only the agent, from a sleepable LSM hook on the open
  of the file (``lota_file_post_open_measure`` in
  :ghsrc:`src/bpf/lota_lsm.bpf.c`). The hash algorithm is the kernel's IMA
  hash; one other than SHA-256 or SHA-512 is refused. Content hashes are
  cached apart from fs-verity digests, under the same key. A token or status
  with any content-hashed object carries ``LOTA_STATUS_IMAGE_CONTENT_HASHED``:
  the digest is a read of the bytes while nothing may write them, not a
  property the kernel enforces.

Memory with no file behind it, an unlinked tmpfs or hugetlbfs object such as
a memfd, has no road: nothing can carry a digest for it.

Outcome
=======

An object that cannot be measured is left out of the digest and counted.
For the process's executable the answer differs:

* The executable measured: the measurement succeeds, with every other
  object either measured or counted as a gap.
* The executable not measured, or nothing measured at all: the measurement
  fails. A mapping that fails to open may be the executable, so its error
  is reported then.

A failed measurement of the caller's own process refuses the token with
``LOTA_IPC_ERR_UNMEASURABLE_SELF``, or with ``LOTA_IPC_ERR_INTERNAL`` when
the agent ran out of memory or descriptors. A failed measurement of another
protected process never refuses the caller, as any local program may ask for
protection; it is counted as a gap.

``LOTA_STATUS_IMAGE_FULLY_MEASURED`` is set when at least one process is
measured and no object of any of them is a gap: in a token over the
processes it carries, in the status over the whole set. It says how much
code the measurement accounts for; whether a gap matters is the relying
party's policy.

The fold
--------

The measured objects of one process also fold into an image digest
(:ghsrc:`include/lota_runtime_image_measure.h`)::

    SHA256("lota-runtime-image-measure:v1\0" || count ||
           for each object, in order:
               soname_len || soname || digest_len || digest)

The integers are 32-bit little-endian, and the domain string ends in its
NUL. The soname is the basename of the mapped path. Objects are sorted by
soname, then by digest length and digest, and a repeat of the same soname
and digest, one file at two paths, is folded once, so neither load order nor
search path changes the value. The journal prints the digest after an
event-driven measurement; tokens carry the registry digest instead.

Coverage on a host
==================

What a host provides decides how much of a process's code the measurement
covers.

* A title's own files carry fs-verity digests when whoever ships them
  enables fs-verity, for example with ``lota-install --verity-manifest``.
  Without one, an executable on one of the listed filesystems is content
  hashed; on another filesystem the token is refused.
* Shared libraries of a distribution that ships no fs-verity digests are
  measured by a content hash while the agent can pin them. A library some
  process holds open for write, or one changed after the mapping, stays a
  gap.
* Code mapped from memory with no file behind it is always a gap.

Journal
=======

For each protected process the agent writes a line when its answer
changes, not every round (:ghsrc:`src/agent/measure_report.h`):

* ``runtime image measurement failed for the requesting pid=N: …``, an
  error: the token is refused.
* ``runtime image measurement failed for pid=N, which is not the caller
  (pid=M); the token reports partial coverage: …``, a warning.
* ``runtime image measurement for pid=N covers X objects and misses Y: …``,
  a warning.
* ``runtime image measurement for pid=N covers every object it has
  mapped``, written when coverage returns.

The reason names the object by path, says whether it is the executable or a
mapped object, and why it has no digest. A line that replaces another ends
with how many further rounds the previous answer held. A process that
leaves the protected set is forgotten, so protecting it again is news.

An event-driven measurement logs ``event-driven re-measure: protected
pid=N image=<digest> (X objects measured, Y unmeasurable)``, or its failure.
When the event loop ends the agent logs ``Runtime measurement reports:
repeated=``, the repeats it left unwritten, and ``unremembered=``, the
lines written with no room to remember them.
