.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=====================================
What the agent reports under --bench
=====================================

``lota-bench`` (:doc:`lota-bench`) reads the cost of LOTA from outside,
through cgroup files. ``lota-agent --bench`` is the inside view: the daemon
writes what it costs, what its BPF programs cost and what the processes it
protects cost, to one file once a second. ``lota-bench`` reads that file in
its ``B`` and ``C`` runs.

``--bench`` changes no policy, mode, BPF program or map. It turns on the
kernel's count of the run time of BPF programs, and the status word and the
attestation report say that it is on. Sampling and writing the file every
interval is work of its own: the daemon uses more CPU time with ``--bench``
than without (:ghsrc:`src/agent/daemon_loop.c`).

Turning it on
=============

Pass ``--bench`` on the command line (:doc:`../agent/command-line`), or set
the key in ``/etc/lota/lota.conf`` (:doc:`../agent/configuration`):

.. code-block:: ini

   bench = true

The key takes ``true``, ``yes`` or ``1`` and ``false``, ``no`` or ``0``;
any other value fails the file with ``invalid bench '...' (use
true/false)``. It is read at startup only: a reload that changes it logs
``bench changes on the next start; keeping it on`` (or ``off``). On a host
where PCR 14 binds the agent, the next start is the next boot
(:doc:`../admin-guide/agent-update`).

At startup a daemon with ``--bench`` logs ``Bench: writing
/run/lota/bench.json every 1000 ms``. Without a ``lota`` group the packaged
``lota-agent.socket`` does not start, nor does the agent, which requires it;
a daemon started by hand logs ``Bench: group 'lota' not found,
/run/lota/bench.json is readable by root only``. When the kernel refuses to
count run time, the daemon logs ``Bench: BPF run time is not counted:``
with the reason. A daemon started without
``--bench`` removes a ``bench.json`` an earlier run left behind, and one
started with it removes the file at exit.

Where it shows
==============

A daemon running with ``--bench`` says so wherever its state is read
(:ghsrc:`src/agent/status_flags.h`, :ghsrc:`src/agent/report_flags.h`):

* the status word carries ``LOTA_STATUS_BENCH``, which a title sees as
  ``LOTA_FLAG_BENCH`` and ``lota_flags_to_string()`` prints as ``BENCH``;
* ``lota-agent --status`` lists ``BENCH`` among the flags;
* the attestation report carries ``LOTA_REPORT_FLAG_BENCH``, and the
  verifier logs ``agent runs with --bench`` for the round
  (:ghsrc:`src/verifier/verify/verify.go`).

The file
========

The snapshot is ``/run/lota/bench.json``, mode 0640, owned by root and the
``lota`` group. It is one JSON object on one line:

.. code-block:: text

   {"version":1,"seq":42,"uptime_ms":41003,"interval_ms":1000,"skipped":0,
    "agent":{"cpu_user_ns":...,"cpu_sys_ns":...,"minflt":...,"majflt":...,
             "rss_kb":...,"pss_kb":...,"uss_kb":...,
             "ctxt_vol":...,"ctxt_invol":...},
    "bpf":{"run_stats":true,"maps":17,"maps_memlock":...,"progs_dropped":0,
           "progs":[{"name":"lota_file_open","run_ns":...,"run_cnt":...},...]},
    "protected":{"count":1,"cpu_ns":...,"minflt":...,"majflt":...,
                 "rss_kb":...,"pss_kb":...,"pss_every_ms":5000}}

``seq``
   Counts snapshots since the daemon started; a reader that sees it stand
   still knows the daemon stopped writing. ``uptime_ms`` is the time since
   the daemon started writing.

``skipped``
   Snapshots that did not fit 8 KiB and were not written
   (:ghsrc:`src/agent/bench.h`).

``agent``
   The daemon's own figures from ``/proc/self``: its CPU time, page
   faults and voluntary and involuntary context switches since it
   started, and its resident, proportional and unique memory now.

``bpf``
   For each program of the daemon's BPF object whose counters can be
   read, its run time and run count as the kernel counts them;
   ``run_stats`` is ``false`` when the kernel refused to count run time,
   and the counts then stand still.
   ``maps`` is the number of maps and ``maps_memlock`` the memory they are
   charged for. At most 32 programs are listed; ``progs_dropped`` counts
   the programs past them and those whose counters cannot be read.

``protected``
   One sum over every process in the protected set: how many there are,
   their CPU time and page faults over the last interval, their resident
   memory now, and their proportional memory as of the last
   ``smaps_rollup``. That file walks every mapping of the title, so it is
   read every ``pss_every_ms`` only, and ``pss_kb`` is ``null`` until every
   process in the set has had one. A process first seen adds nothing to the
   interval counters, so a title protected mid-run is not charged its past.

``agent`` is ``null`` when ``/proc/self`` could not be read, ``bpf`` while
no BPF object is loaded, and ``protected`` when the protected set could not
be read; ``maps_memlock`` is ``null`` when a map's charge could not be
read.

What it does not do
===================

The file is readable by the ``lota`` group, so what it carries and how it
is written are both narrow (:ghsrc:`src/agent/bench.c`,
:ghsrc:`src/agent/bench_protected.c`):

* It names no process, PID, mapping, file or address of the protected set;
  that part of it is a single sum. A PID whose start time no longer
  matches the protected entry is another process and is not counted.
* The program names are the daemon's own, at most 31 characters, reduced
  to ``[A-Za-z0-9_.]``. The run counts do say how often each hook fired,
  which the group can see.
* It is written to ``.bench.tmp`` in ``/run/lota``, opened with ``O_EXCL``
  and ``O_NOFOLLOW`` after any old one is unlinked, given its group and
  mode through the descriptor, and renamed over the snapshot. A link
  planted at either name is replaced, never followed. The descriptor is
  closed after each write, and the daemon never reads the file back.
* Run-time counting is switched on with ``BPF_ENABLE_STATS``, which holds
  while the daemon keeps that descriptor and ends with it
  (:ghsrc:`src/agent/bench_bpf.c`); the ``kernel.bpf_stats_enabled``
  sysctl is not written.
* The file is ``lota_var_t``, like the rest of ``/run/lota``
  (:ghsrc:`selinux/lota.fc`).

A failed write is logged when its error changes, as ``Bench: cannot write
/run/lota/bench.json: ...`` with the reason, and ``Bench: writing
/run/lota/bench.json again`` when writing resumes.
