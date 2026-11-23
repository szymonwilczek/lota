.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=====================================
Measuring a game with ``lota-bench``
=====================================

``lota-bench`` (:ghsrc:`tools/lota-bench`) measures what LOTA costs a
player: it samples the cost of a running game and of the LOTA services
next to it, and writes the samples to a result file that can be shared
and compared, and it summarises the frame times MangoHud logged for the
same run. It is a contributor tool, built from the tree and not
shipped in the packages.

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
   The cgroup given with ``--cgroup``. For a game started through
   systemd (a Steam or desktop launcher usually runs it in an
   ``app-*.scope``), ``systemctl --user show -p ControlGroup <unit>``
   prints it; that form, with its leading ``/``, is accepted as it is.
   A path under ``/sys/fs/cgroup`` is accepted too. The cgroup root is
   refused: it is the whole machine, not a game.

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

Sampling
========

.. code-block:: console

   $ lota-bench sample --cgroup /user.slice/.../app-game.scope \
         --output run.json --interval-ms 1000 --duration-s 600

The run ends when the duration runs out, when the game's cgroup goes
away, or on Ctrl+C; the first sample is always taken. Samples are spaced
on an absolute monotonic clock, so a slow sample does not shift the
ones after it. The sampler runs at nice 10 with idle I/O priority and
records its own cost in the result, so its share of the machine is
visible rather than hidden in the game's numbers.

The output file is created exclusively and is never overwritten. A run
that fails before the result is complete removes the file, so a result
file on disk is always a finished run.

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

The result file
===============

A result is one JSON object. ``schema_version`` is ``1``; a change a
reader of version 1 would misread raises it.

.. code-block:: text

   {
     "schema_version": 1,
     "tool": "lota-bench",
     "interval_ms": 1000,
     "samples": [
       {"t_ms": 0, "game": {"cpu_usage_usec": 10, ...},
        "lota-agent": {...}, "lota-attest": null},
       {"t_ms": 1000, ...}
     ],
     "end": "game-gone",
     "self": {"cpu_user_usec": 1, "cpu_system_usec": 2,
              "max_rss_bytes": 3}
   }

``interval_ms``
   The requested spacing, 100 to 60000.

``samples``
   One to 14400 samples. ``t_ms`` is milliseconds since the first sample
   and strictly increases. Each source is ``null`` or an object holding
   every metric.

``end``
   Why the run stopped: ``duration``, ``interrupted``, ``game-gone`` or
   ``sample-cap``.

``self``
   The sampler's own user and system CPU time and peak resident set.

The file holds numbers and a fixed set of strings only. It carries no
path, no host name, no user name and no process name, which is what
makes it safe to attach to a public issue or pull request.

Validating a result
===================

.. code-block:: console

   $ lota-bench validate run.json
   run.json: valid, 600 samples every 1000 ms (duration)

``validate`` accepts exactly what ``sample`` writes and nothing more:
every key known and present once, every string one of the fixed set,
printable ASCII with no escapes and at most 64 characters, every number
an unsigned 64-bit integer, nothing after the result object, and the
file at most 64 MiB. A refusal names the byte offset of the first
problem:

.. code-block:: console

   $ lota-bench validate edited.json
   edited.json: invalid: offset 57: unknown key "path"

Because the validator is what stands between a contributed file and the
tree, it is fuzzed: ``make fuzz-bench-result`` builds the harness, which
also checks that no accepted input carries a ``/`` or a ``\``. The
MangoHud log reader has its own harness, ``make fuzz-bench-frames``.
