.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=====================================
What the agent reports under --bench
=====================================

``lota-bench`` (:doc:`lota-bench`) reads the cost of LOTA from outside,
through cgroup files. ``lota-agent --bench`` is the inside view: the
daemon writes what it costs, and what the processes it protects cost,
to one file once a second. The two answer different questions and can
run together.

``--bench`` adds observation only. The policy, the mode, the BPF
programs and the maps the agent loads are the same with and without it,
and a host running with it attests like any other, with the fact
recorded in the evidence.

Turning it on
=============

Either pass ``--bench`` on the command line or set it in
``/etc/lota/lota.conf``:

.. code-block:: ini

   bench = true

The key is read at startup only. ``systemctl reload lota-agent`` leaves
it as it was and logs ``bench changes on the next start``; on a host
where PCR 14 binds the agent, the next start is the next boot (see
:doc:`../operator/agent-update-reboot`). A daemon that starts without
it removes a ``bench.json`` an earlier run left behind.

Where it shows
==============

A daemon running with ``--bench`` says so everywhere its state is read:

* the status word carries ``LOTA_STATUS_BENCH``, which a title sees as
  ``LOTA_FLAG_BENCH`` and ``lota_flags_to_string()`` prints as
  ``BENCH``;
* the attestation report carries ``LOTA_REPORT_FLAG_BENCH``, and the
  verifier logs ``agent runs with --bench`` for the round;
* ``lota-agent --status`` lists ``BENCH`` among the flags.

``lota-agent --status`` sends ``GET_STATUS`` over the agent socket and
prints what any caller of the socket is told:

.. code-block:: console

   $ lota-agent --status
   Mode:         enforce
   Flags:        ATTESTED,TPM_OK,IOMMU_OK,BPF_LOADED,SECURE_BOOT,BENCH
   Attested:     2026-01-01 12:00:00 UTC
   Token until:  2026-01-01 12:01:30 UTC
   Attestations: 3 succeeded, 0 failed

It needs the socket's group, not root, and changes nothing. A bit this
build has no name for is printed in hex rather than dropped.

The file
========

The snapshot is ``/run/lota/bench.json``, mode ``0640``, owned by root
and the ``lota`` group. It is one JSON object on one line:

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
   Counts snapshots since the daemon started; a reader that sees it
   stand still knows the daemon stopped writing.

``skipped``
   Snapshots that did not fit the 8 KiB cap and were not written.

``agent``
   The daemon's own counters, cumulative since it started: CPU time,
   page faults, resident, proportional and unique memory, and voluntary
   and involuntary context switches.

``bpf``
   Each LSM program's run time and run count, as the kernel counts them,
   and the memory its maps are charged for. ``run_stats`` is ``false``
   when the kernel refused to count run time, and the counts then stand
   still.

``protected``
   One sum over every process in the protected set: how many there are,
   their CPU time and page faults over the last interval, their resident
   memory now, and their proportional memory as of the last
   ``smaps_rollup``, which is read every ``pss_every_ms`` only because it
   walks every mapping of the title. ``pss_kb`` is ``null`` until every
   process has had one.

Anything that could not be read is ``null``, never ``0``.

What it does not do
===================

The file is meant to be read by the ``lota`` group, so what it carries
and how it is written are both narrow:

* It names no process, PID, mapping, file or address of the protected
  set; that part of it is a single sum. A PID whose start time no longer
  matches the protected entry is another process and is not counted.
* The program names are the daemon's own, reduced to ``[A-Za-z0-9_.]``.
  The run counts do say how often each hook fired, which is visible to
  the group.
* It is written to ``.bench.tmp`` next to it, opened with ``O_EXCL`` and
  ``O_NOFOLLOW`` after any old one is unlinked, given its mode and owner
  through the descriptor, and renamed over the snapshot. A link planted
  at either name is replaced, never followed. The descriptor is closed
  after each write, and the daemon never reads the file back.
* Run-time counting is switched on with ``BPF_ENABLE_STATS``, which
  holds for as long as the daemon keeps that descriptor and ends with
  it; the ``kernel.bpf_stats_enabled`` sysctl is not written.
* It reads ``/proc`` of the protected set with the read access the
  agent already has; no new permission and no new SELinux type are
  involved, the file is ``lota_var_t`` like the rest of ``/run/lota``.

What it costs
=============

Measured on a laptop with a hardware TPM, the agent in enforce mode with
an empty protected set, over ten minutes each way:

.. list-table::
   :header-rows: 1

   * -
     - without ``--bench``
     - with ``--bench``
   * - agent CPU
     - 90 ms (0.015 % of a core)
     - 780 ms (0.13 % of a core)
   * - agent PSS
     - 8893 kB
     - 8919 kB

A snapshot costs about 1.2 ms of CPU. A Proton title held at 60 fps on
the same machine, played for five minutes each way, gives the same frame
times within the noise of two runs:

.. list-table::
   :header-rows: 1

   * -
     - without ``--bench``
     - with ``--bench``
   * - median
     - 16.62 ms
     - 16.62 ms
   * - p99
     - 17.56 ms
     - 17.67 ms
   * - 1% low
     - 35.50 ms
     - 35.15 ms
   * - stutters over twice the median
     - 14
     - 14
