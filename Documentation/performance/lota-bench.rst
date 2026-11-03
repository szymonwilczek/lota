.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=====================================
Measuring a game with ``lota-bench``
=====================================

``lota-bench`` (:ghsrc:`tools/lota-bench`) measures what LOTA costs a
player: it samples the cost of a running game and of the LOTA services
next to it, keeps the frame times MangoHud logged for the same run, and
writes both to files that can be shared and compared. It is a
contributor tool, built from the tree and not shipped in the packages.

Building
========

.. code-block:: console

   $ make lota-bench
   $ sudo make install-lota-bench                 # /usr/local/bin
   $ make install-lota-bench LOTA_BENCH_PREFIX=~/.local

Where the numbers come from
===========================

Every number is read from cgroup v2 files, never from ``/proc/<pid>``. A
protected title and the agent itself refuse every ptrace access from
outside, reads included, and the agent records each refusal; a meter
that read ``/proc/<pid>`` would show up in the agent's log as a process
trying to read the game. The cgroup files need no ptrace access and read
the same whether LOTA is stopped, running, or protecting the game.

Three sources are sampled:

``game``
   The cgroup the game runs in.

``lota-agent``, ``lota-attest``
   The cgroups of ``lota-agent.service`` and ``lota-attest.service``
   under ``system.slice``. They are looked up again at every sample, so
   a service stopped or started during a run shows as ``null`` in the
   samples it was absent from.

Each source carries the same fourteen metrics:

.. list-table::
   :header-rows: 1

   * - key
     - file
     - field
   * - ``cpu_usage_usec``
     - ``cpu.stat``
     - ``usage_usec``
   * - ``cpu_user_usec``
     - ``cpu.stat``
     - ``user_usec``
   * - ``cpu_system_usec``
     - ``cpu.stat``
     - ``system_usec``
   * - ``memory_current_bytes``
     - ``memory.current``
     - whole file
   * - ``memory_peak_bytes``
     - ``memory.peak``
     - whole file
   * - ``memory_anon_bytes``
     - ``memory.stat``
     - ``anon``
   * - ``memory_file_bytes``
     - ``memory.stat``
     - ``file``
   * - ``memory_kernel_bytes``
     - ``memory.stat``
     - ``kernel``
   * - ``pgfault``
     - ``memory.stat``
     - ``pgfault``
   * - ``pgmajfault``
     - ``memory.stat``
     - ``pgmajfault``
   * - ``io_read_bytes``
     - ``io.stat``
     - ``rbytes``, summed over devices
   * - ``io_write_bytes``
     - ``io.stat``
     - ``wbytes``, summed over devices
   * - ``io_read_ops``
     - ``io.stat``
     - ``rios``, summed over devices
   * - ``io_write_ops``
     - ``io.stat``
     - ``wios``, summed over devices

Counters are cumulative since the cgroup was created; a consumer takes
differences between samples. A metric whose file or field is missing
(a controller not enabled for the cgroup, a kernel without
``memory.peak``) is ``null``, never ``0``.

Frame times
===========

The cgroup files say what the game cost the machine; how smooth it ran
comes from MangoHud, which runs inside the game and logs one row per
frame. Because the log is written from inside, it reads the same whether
the game is protected or not. Turn logging on in the MangoHud
configuration or through ``MANGOHUD_CONFIG``:

.. code-block:: console

   $ MANGOHUD_CONFIG=output_folder=$HOME/mangologs,autostart_log=5,log_duration=600 \
         mangohud ./game

For a Steam title, put ``MANGOHUD_CONFIG=... mangohud %command%`` in the
launch options. ``log_interval`` must stay at its default of ``0``: with
an interval the log holds one row per interval, frame times between rows
are lost, and ``lota-bench`` refuses the log. The log is summarised with:

.. code-block:: console

   $ lota-bench frames ~/mangologs/game_<date>.csv
   .../game_<date>.csv: 107912 frames in 600.004 s
     mean             5.560 ms    179.9 fps
     median           5.561 ms    179.8 fps
     p99              5.663 ms    176.6 fps
     p99.9            5.811 ms    172.1 fps
     1% low           5.743 ms    174.1 fps
     0.1% low         5.811 ms    172.1 fps
     max              9.904 ms    101.0 fps
     stutters  0 frames over twice the median

Only the ``frametime`` and ``elapsed`` columns are read, found by name
in the column row; the description of the machine MangoHud writes above
that row is skipped and never copied. Frame times are kept in
microseconds, truncating the rest.

``p99`` and ``p99.9``
   The nearest-rank percentiles: the frame time that 99% (99.9%) of
   frames are at or under. These are what MangoHud's own summary calls
   the 1% and 0.1% minimum fps.

``1% low`` and ``0.1% low``
   The mean of the slowest 1% (0.1%) of frames, at least one frame. A
   handful of long frames moves these where it barely moves a
   percentile.

``stutters``
   Frames longer than twice the median.

A log is refused when no row among its first 16 names the
``frametime`` and ``elapsed`` columns, when a row has a different number
of columns than that row, when a frame time is not a plain decimal
number of milliseconds or ``elapsed`` goes back, or when the frames
cover less than half of the time the log spans, which is what a log
with an interval looks like. A refusal names the line.

The files of a session
======================

A session lives in one directory and is made of three kinds of file:
``plan.json`` says what is measured and on what machine, each
``run-NN.json`` holds one run, and ``result.json`` joins the plan and
every run once the last run is in. A summary is a result without its
samples, small enough to paste into an issue. Each file is one JSON
object that starts with the same three keys:

.. code-block:: text

   {
     "schema_version": 1,
     "tool": "lota-bench",
     "kind": "plan",
     ...
   }

``schema_version`` is ``1``; a change a reader of version 1 would
misread raises it. ``kind`` is ``plan``, ``run``, ``result`` or
``summary`` and comes before every key it governs.

The plan
--------

.. code-block:: text

   "version": "1.0.0",
   "machine": {"cpu_model": "Example CPU 8-Core", "cpu_threads": 16,
               "memory_bytes": 34359738368,
               "gpus": [{"vendor_id": 4098, "device_id": 1,
                         "name": "Example GPU", "driver": "example"}],
               "kernel": "6.0.0", "distro": "example 1",
               "tpm": "tpm_example", "selinux": "enforcing"},
   "game": {"title": "Example Title", "proton": "9.0",
            "version": null, "settings": "high, 1440p"},
   "rounds": 3,
   "duration_s": 300,
   "interval_ms": 1000

``version``
   The ``lota-bench`` that wrote the plan.

``machine``
   What the numbers depend on: the CPU model and its thread count, the
   memory, up to four GPUs by PCI id with the name ``pci.ids`` gives
   them and the driver bound to them, the kernel release, the
   distribution as ``ID VERSION_ID`` from ``os-release``, the driver of
   the TPM (``none`` without one) and the SELinux mode.

``game``
   The title, and the Proton, game version and settings it ran with.
   Only the title is required.

``rounds``, ``duration_s``, ``interval_ms``
   A session is a warm-up run followed by ``rounds`` rounds of one run
   in each configuration (``A``, ``B``, ``C``), 2 to 10 rounds. Each run
   samples for ``duration_s`` seconds, 10 to 3600, every
   ``interval_ms`` milliseconds, 100 to 60000. A run holds at most 14400
   samples and a session at most 43200, so a plan that would plan more
   is refused.

A run
-----

.. code-block:: text

   "run": {"index": 3, "config": "C", "warmup": false,
           "mode": "enforce", "agent_bench": true,
           "power": {"governor": "performance", "profile": null,
                     "supply": "ac"},
    "samples": [
     {"t_ms": 0, "game": {"cpu_usage_usec": 10, ...},
      "lota-agent": {...}, "lota-attest": null},
     {"t_ms": 1000, ...}
    ],
    "sample_count": 300, "wall_ms": 300004, "end": "duration",
    "totals": {"game": {"cpu_usec": ..., "memory_max_bytes": ...,
                        "pgfault": ..., "pgmajfault": ...,
                        "io_read_bytes": ..., "io_write_bytes": ...},
               "lota-agent": {...}, "lota-attest": null},
    "agent": {"bpf_run_ns": ..., "bpf_run_cnt": ...,
              "maps_memlock_bytes": ..., "protected_max": 1},
    "frames": {"frames": 107912, "total_us": ..., "mean_us": ...,
               "median_us": ..., "p99_us": ..., "p999_us": ...,
               "low_1pct_us": ..., "low_01pct_us": ..., "max_us": ...,
               "stutters": 0},
    "self": {"cpu_user_usec": 1, "cpu_system_usec": 2,
             "max_rss_bytes": 3}}

``index``, ``config``, ``warmup``
   Run 0 is the warm-up, in ``A``; run ``i`` after it is in ``A``,
   ``B`` and ``C`` in turn.

``mode``, ``agent_bench``
   The agent's mode as its status reports it, ``none`` while it is
   stopped, and whether it runs with ``--bench``.

``power``
   The CPU frequency governor, the platform profile and whether the
   machine ran on ``ac`` or ``battery`` (``unknown`` when it cannot
   tell).

``samples``
   One sample every ``interval_ms``. ``t_ms`` is milliseconds since the
   first sample and strictly increases. Each source is ``null`` while
   its cgroup is absent, or an object holding every metric.

``end``
   Why sampling stopped: ``duration``, ``game-gone`` or ``sample-cap``.
   An ``interrupted`` run is not kept.

``totals``
   Each source over the whole run: the CPU time and the faults and I/O
   it accrued, and the highest ``memory.current``. A source whose cgroup
   was never there is ``null``.

``agent``
   From the snapshots the agent writes under ``--bench``: the time and
   runs of its BPF programs during the run, the memory its BPF maps
   lock, and the most processes it protected at once. ``null`` when no
   snapshot could be read.

``frames``
   The MangoHud log of the run, summarised as ``lota-bench frames``
   does, in microseconds; ``null`` without a log.

``self``
   The sampler's own user and system CPU time and peak resident set.

In ``result.json`` each run is an element of ``runs`` in the same form;
a summary leaves out every ``samples``.

Text
----

Apart from the names of the fixed sets above, a file carries text in a
few named fields only: the machine's, the game's and the power
settings'. Each is cleaned when it is read: printable ASCII only, with
``/``, ``\`` and ``"`` turned into ``_``, blanks collapsed and trimmed,
at most 64 characters. No path, host name, user name, process name or
command line is ever written, which is what makes a file safe to attach
to a public issue or pull request.

Validating a file
=================

.. code-block:: console

   $ lota-bench validate result.json
   result.json: valid result, 10 runs of Example Title

``validate`` accepts exactly what ``lota-bench`` writes and nothing
more: every key known and present once, every name one of its fixed
set, every text field as cleaning leaves it, every number an unsigned
64-bit integer, nothing after the object, and the file at most 64 MiB.
A session must also add up: as many runs as its rounds make, each in
its place and in the configuration that place calls for, and each
showing the state of LOTA that configuration stands for. An ``A`` run
saw no agent, a ``B`` or ``C`` run saw it running, a ``C`` run with
agent figures protected at least one process and a ``B`` run none. A
refusal names the byte offset of the first problem:

.. code-block:: console

   $ lota-bench validate edited.json
   edited.json: invalid: offset 57: unknown key "path"

Because the validator is what stands between a contributed file and the
tree, it is fuzzed: ``make fuzz-bench-result`` builds the harness, which
also checks that no accepted input carries a ``/`` or a ``\``. The
MangoHud log reader has its own harness, ``make fuzz-bench-frames``.
