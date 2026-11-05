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
   The transient scope ``lota-bench-game.scope`` the game's launch
   options start it in (see `Running a session`_), under the user's
   ``app.slice``. It is found by name, so no PID of the game is ever
   looked up.

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
are lost, and ``lota-bench`` refuses the log. ``log_duration`` can end
the title along with the log, so save before it runs out. ``steam
-applaunch`` starts the launcher of a title that has one, and the launch
options wrap that launcher; start such a title from the Steam window and
pick the entry without it. The log is summarised with:

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

Running a session
=================

A session measures one title in three configurations:

``A``
   LOTA stopped: no agent, no attestation.

``B``
   The agent running, the title not protected.

``C``
   The agent running and protecting the title through
   ``lota-proton-hook``.

It is a warm-up run in ``A`` followed by rounds of ``A``, ``B`` and
``C``, so drift over the session (a warming machine, a filling shader
cache) falls on every configuration alike. Moving between
configurations can take a reboot, so ``lota-bench run`` takes one run a
call and keeps the session in a directory. The first call names the
title and starts it:

.. code-block:: console

   $ lota-bench run ~/bench/example --game "Example Title" --proton 9.0 \
         --settings "high, 1440p"
   The session begins in /home/user/bench/example: 7 runs of 300 s.
   Run 0 of 6, configuration A (warm-up). Set the game's launch options to:

     MANGOHUD_CONFIG=output_folder=/home/user/bench/example,autostart_log=30,log_duration=300 systemd-run --user --scope --unit=lota-bench-game mangohud %command%

   start it, and be in the game within 30 s, when the frame log starts;
   play as you would for 300 s from there.
   Waiting for the game; Ctrl+C gives up.

``--rounds`` (default 3), ``--duration-s`` (default 300),
``--settle-s`` (default 30) and ``--interval-ms`` (default 1000) set the
rest of the plan. A loading screen makes the tail of the frame times
noise, so the frame log starts ``--settle-s`` after the game; the
cgroups measure the whole run, so what starting the game costs still
counts. ``--proton``,
``--game-version`` and ``--settings`` only describe the run. Every later
call is ``lota-bench run DIR`` alone and takes the next run the plan
calls for; options given to a session that has begun are refused. The
directory's full path goes into ``MANGOHUD_CONFIG`` and the launch
options, so it may hold only letters, digits and ``/ . _ - +``.

The first launch after a reboot finds a cold page cache and an agent in
its first attestation rounds, and moving to ``B`` is where a reboot
falls, so a run taken there would charge that cost to ``B`` alone. The session
keeps the boot it last ran in, in ``boot_id``. A call in another boot
is a warm-up: it goes as a run does, in the configuration of the next
run, and keeps nothing. The next call takes that run.

Each call first checks that LOTA is where the run needs it and, when it
is not, says how to get it there and exits:

.. code-block:: console

   $ sudo systemctl stop lota-attest lota-agent.socket lota-agent    # A
   $ sudo systemctl start lota-agent.socket lota-agent               # B, C

The socket is stopped with the agent because the agent is socket
activated: any client, ``lota-bench`` included, would start it again.
In ``A`` ``lota-bench`` never touches the socket. Where PCR 14 binds the
agent, stopping it spends the boot's commitment, and the agent refuses
to start again until a reboot, which also brings attestation back; on
such a host every run in ``B`` that follows an ``A`` begins with a
reboot. In ``B`` and ``C`` the agent's status is read from the
socket, which takes membership of the ``lota`` group; the agent's
figures need it to run with ``--bench`` (``BENCH`` among the flags
``lota-agent --status`` prints), and a run without them says so. For
``C`` the printed launch options carry ``lota-proton-hook`` in front of
``mangohud``; without ``--bench`` nothing tells whether the title was
in fact protected.

Once the scope appears the run is sampled for ``settle_s`` and
``duration_s`` seconds together,
then ``lota-bench`` asks to quit the game and waits for the scope to go.
``lota-bench`` runs as the user, at nice 10 and idle I/O priority, and
reads nothing but cgroup files, the agent's snapshot and its own
directory. A run is not kept, and the next call takes it again, when:

- the game quits before they are up, or Ctrl+C stops the run;
- LOTA left the state of the configuration during the run: the agent
  or attestation ran in ``A``, or the agent went away in ``B`` or
  ``C``;
- a ``C`` run with agent figures protected nothing, which means
  ``lota-proton-hook`` is missing from the launch options, or a ``B``
  run protected the title.

A call also refuses to go on while a ``lota-bench-game.scope`` is still
running, and when the machine described in the plan changed (another
kernel, GPU or driver): a session compares like with like, so that
takes a new session.

The run's MangoHud log is the newest ``.csv`` in the directory written
since the game started; it is summarised into the run and kept as
``frames-NN.csv``. Without one the run has no frame times. Each file is
written aside, read back by the same validator as ``lota-bench
validate``, and only then given its name, so a session directory never
holds a half-written file. After the last run the same call joins the
plan and every run into ``result.json``, and the session is complete.

Reading a session
=================

``lota-bench report`` reads a result or a summary and sets the three
configurations side by side:

.. code-block:: console

   $ lota-bench report ~/bench/example/result.json
   Example Title: 3 rounds of A B C, 300 s a run after 30 s to settle
   ...
                                        A               B               C         B-A         C-A
   frame time median ms          6.94 ±0.02      6.95 ±0.01      6.97 ±0.03     +0.01 ~     +0.03 ~
   game CPU %                   182.4 ±1.3      183.0 ±0.9      183.6 ±1.1       +0.6 ~      +1.2 ~
   lota-agent CPU %              0.00 ±0.00      0.08 ±0.01      0.11 ±0.01     +0.08       +0.11
   ...

Every row is one figure of a run, and for each configuration the median
of its runs, the warm-up left out. A median rather than a mean lets one
disturbed run (an update in the background, a shader compiled late)
pass without moving the figure. The ``±`` is half the range of those
runs: how far apart runs of the same configuration already are. A
difference from ``A`` no larger than the two spreads together is marked
``~``, noise: the session cannot tell it from the runs disagreeing among
themselves, and more rounds are what would.

``frame time median``, ``p99``, ``1% low``, in ms
   From the run's MangoHud log, as ``lota-bench frames`` defines them.
   Lower is better.

``game CPU``, ``lota-agent CPU``, ``lota-attest CPU``, in %
   The CPU time the cgroup accrued over the run, as a share of one CPU:
   ``cpu_usec / (wall_ms * 10)``. A game busy on two CPUs shows
   ``200``. The services stopped in ``A`` count as ``0``, and so does
   attestation while it is not running.

``game memory``, ``lota-agent memory``, in MiB
   The highest ``memory.current`` of the run.

``BPF programs``, in µs/s
   The time the agent's BPF programs ran during the run, for every
   second of it: ``bpf_run_ns / wall_ms``. It needs the agent under
   ``--bench``, which turns on the counting
   (:doc:`agent-bench`). The time is spent in the processes the hooks
   run in, the game's among them, so it is already part of their CPU
   time rather than added to it.

A figure some runs of a configuration lack is marked ``*``, one none of
them has is ``-``. When the power settings (governor, platform profile,
supply) changed across the session, the report says so: runs under
different settings do not compare.

Sharing a session
-----------------

``lota-bench issue`` prints the body of an issue for a result or a
summary: the report in a ``text`` block, then the session's summary in a
``lota-bench`` block, which is what a reader of the issue or a script
takes the figures from:

.. code-block:: console

   $ lota-bench issue ~/bench/example/result.json > issue.md

The summary is read back by the validator before anything is printed,
so the block holds only what ``lota-bench validate`` accepts, and the
whole body must fit the 65536 characters an issue holds; a session of
the most rounds takes about half of that.

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
   "settle_s": 30,
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

``rounds``, ``settle_s``, ``duration_s``, ``interval_ms``
   A session is a warm-up run followed by ``rounds`` rounds of one run
   in each configuration (``A``, ``B``, ``C``), 2 to 10 rounds. Each run
   samples for ``settle_s`` seconds, 1 to 600, in which the frame log
   does not run, and then ``duration_s`` seconds, 10 to 3600, every
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
    "sample_count": 330, "wall_ms": 330004, "end": "duration",
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
