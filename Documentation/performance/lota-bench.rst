.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=====================================
Measuring a game with ``lota-bench``
=====================================

``lota-bench`` (:ghsrc:`tools/lota-bench`) measures what LOTA costs a
running game. It samples the game and the LOTA services from their cgroups,
keeps the frame times MangoHud logged for the same run, and writes the
session to files that can be attached to an issue and compared.

Building
========

.. code-block:: console

   $ make lota-bench
   $ sudo make install-lota-bench
   $ make install-lota-bench LOTA_BENCH_PREFIX=~/.local

The binary is ``build/lota-bench``. ``install-lota-bench`` copies it to
``bin/`` under ``LOTA_BENCH_PREFIX``, default ``/usr/local``. No package
ships it.

Commands
========

``lota-bench run DIR [options]``
  Takes the next run of the session in DIR (`Running a session`_).

``lota-bench report FILE``
  Sets the configurations of a result or a summary side by side
  (`Reading a session`_).

``lota-bench issue FILE``
  Prints the report and the summary as the body of an issue
  (`Sharing a session`_).

``lota-bench validate FILE``
  Checks a plan, run, result or summary file (`Validating a file`_).

``lota-bench frames LOG``
  Summarises the frame times of a MangoHud log (`Frame times`_).

``lota-bench --version``, ``--help``, ``-h``
  Print the version or the usage and exit with 0.

A missing or unknown command, a wrong number of arguments and a bad or
out-of-range option exit with 2; any other failure exits with 1.

Where the numbers come from
===========================

The game and the LOTA services are measured through cgroup v2 files;
``lota-bench`` looks up no PID and reads nothing under ``/proc/<pid>``.
The agent refuses a read of its own ``/proc`` and of a protected title's
from outside the title's instance (:ghsrc:`src/bpf/lota_lsm.bpf.c`), so a
meter that read them would fail on the very configuration it measures. A
cgroup file reads the same whether LOTA is stopped, running or protecting
the game.

Three sources are sampled:

``game``
   The transient scope ``lota-bench-game.scope`` that the game's launch
   options start it in, under ``app.slice`` of the user's manager, or
   straight under the manager where systemd puts it there. It is found by
   name.

``lota-agent``, ``lota-attest``
   The cgroups of ``lota-agent.service`` and ``lota-attest.service``
   under ``system.slice``. They are looked up again at every sample, so a
   service that is not running is ``null`` in that sample.

Each source carries fourteen metrics:

.. list-table::
   :header-rows: 1

   * - Key
     - File
     - Field
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

The counters are cumulative since the cgroup was created. A metric whose
file or field is missing, a controller not enabled for the cgroup or a
kernel without ``memory.peak``, is ``null``. An empty ``io.stat`` is a
cgroup that has done no I/O, and its four metrics are ``0``.

Frame times
===========

The cgroups say what the game cost the machine; how smoothly it ran comes
from MangoHud, which runs inside the game and logs a row per frame. The
log is written from inside the game, so it reads the same whether the game
is protected or not. Logging is set in the MangoHud configuration or in
``MANGOHUD_CONFIG``:

.. code-block:: console

   $ MANGOHUD_CONFIG=output_folder=$HOME/mangologs,autostart_log=5,log_duration=600 \
         mangohud ./game

``lota-bench run`` prints the launch options that set it for a session. A
log is summarised with:

.. code-block:: console

   $ lota-bench frames mangologs/example.csv
   mangologs/example.csv: 107912 frames in 600.004 s
     mean             5.560 ms    179.9 fps
     median           5.561 ms    179.8 fps
     p99              5.663 ms    176.6 fps
     p99.9            5.811 ms    172.1 fps
     1% low           5.743 ms    174.1 fps
     0.1% low         5.811 ms    172.1 fps
     max              9.904 ms    101.0 fps
     stutters  0 frames over twice the median

The header row is the first of the first 16 lines that names a
``frametime`` and an ``elapsed`` column; the lines above it, where MangoHud
describes the machine, are skipped and never copied. Only those two
columns are read. ``frametime`` is in milliseconds and kept in
microseconds, the rest truncated; ``elapsed`` is in nanoseconds.

``p99`` and ``p99.9``
   The nearest-rank percentiles: the frame time that 99 % (99.9 %) of
   frames are at or under.

``1% low`` and ``0.1% low``
   The mean of the slowest 1 % (0.1 %) of frames, at least one frame. A
   few long frames move these where they barely move a percentile.

``stutters``
   Frames longer than twice the median.

The log is refused, with the line named, when no header row is found, when
a row has more or fewer columns than the header, when a frame time is not
a decimal number of milliseconds or ``elapsed`` not a whole number of
nanoseconds, when ``elapsed`` goes back, or when it holds no frame. A log
whose frame times add up to less than half of the time ``elapsed`` spans
is refused too: it is logged once per ``log_interval``, not once per
frame, and the message says to set ``log_interval=0``. A log is at most
1 GiB and 4 194 304 frames (:ghsrc:`tools/lota-bench/frames.h`).

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

It is a warm-up run in ``A`` followed by rounds of ``A``, ``B`` and ``C``,
so drift over the session, a warming machine or a filling shader cache,
falls on every configuration alike. Moving between configurations can take
a reboot, so ``lota-bench run`` takes one run a call and keeps the session
in a directory. The first call names the title and starts the warm-up:

.. code-block:: console

   $ lota-bench run ~/bench/example --game "Example Title" --proton 9.0 \
         --settings "high, 1440p"
   The session begins in /home/user/bench/example: 10 runs of 60 s.
   Run 0 of 9, configuration A (warm-up). Set the game's launch options to:

     MANGOHUD_CONFIG=output_folder=/home/user/bench/example,autostart_log=30,log_duration=60 systemd-run --user --scope --unit=lota-bench-game mangohud %command%

   start it, and be in the game within 30 s, when the frame log starts;
   play as you would for 60 s from there.
   Waiting for the game; Ctrl+C gives up.

The options that start a session:

``--game TITLE``
  The title. Required.

``--proton V``, ``--game-version V``, ``--settings TEXT``
  Describe the run and change nothing in it.

``--rounds N``
  Rounds of ``A``, ``B`` and ``C``, 2 to 10, default 3.

``--settle-s N``
  Seconds from the game's start to the frame log, 1 to 600, default 30. A
  loading screen makes the tail of the frame times noise, so the frame log
  starts after it; the cgroups sample from the start, so what starting the
  game costs still counts.

``--duration-s N``
  Seconds of the frame log, 10 to 3600, default 60.

``--interval-ms N``
  The sampling interval, 100 to 60000 milliseconds, default 1000.

``run --help`` lists them and exits with 0.

A run samples ``settle-s`` plus ``duration-s`` seconds; it holds at most
14 400 samples and a session at most 43 200, and a plan past either is
refused with a hint to lengthen ``--interval-ms``. Every later call is
``lota-bench run DIR`` alone and takes the next run the plan calls for;
options given to a directory that holds a session are refused. The
directory is created with mode 0755, less the umask. Its full path goes into
``MANGOHUD_CONFIG`` and the launch options, so it may hold only letters,
digits and ``/ . _ - +``.

LOTA in each configuration
--------------------------

Each call first checks that LOTA is where the run needs it, by the
presence of the units' cgroups, and when it is not, prints how to get it
there and exits with 1:

.. code-block:: console

   $ sudo systemctl stop lota-attest lota-agent.socket lota-agent    # A
   $ sudo systemctl start lota-agent.socket lota-agent               # B, C

The socket goes with the agent because the agent is socket activated: any
client, ``lota-bench`` included, would start it again. In ``A``,
``lota-bench`` never connects to the socket. Where PCR 14 binds the agent,
an agent stopped once does not start again until a reboot; on such a host
every ``B`` run that follows an ``A`` run begins with a reboot.

In ``B`` and ``C`` the agent's status is read from its socket, which takes
membership of the ``lota`` group. The agent's figures need the agent to
run with ``--bench`` (:doc:`agent-bench`), shown as ``BENCH`` among the
flags ``lota-agent --status`` prints; without it the run has no agent
figures, and ``lota-bench`` says so. For ``C`` the printed launch options
put ``lota-proton-hook`` in front of ``mangohud``.

A call also refuses to go on while a ``lota-bench-game.scope`` is still
running, and when the machine changed since the plan was written: another
CPU model or thread count, another set of GPUs or GPU drivers, another
kernel release, distribution, TPM driver or SELinux mode. A session
compares like with like, so that takes a new session.

After a reboot
--------------

The first launch after a reboot finds a cold page cache and an agent in
its first attestation rounds, and the move to ``B`` is where a reboot
falls, so a run taken there would charge that cost to ``B`` alone. The
session keeps the boot it last ran in, in ``boot_id``. A call in another
boot, past run 0, is a warm-up: it goes as the next run goes, in its
configuration, and keeps nothing. The call after it takes that run.

A run
-----

Once the scope appears, ``lota-bench`` samples it for ``settle-s`` plus
``duration-s`` seconds, at nice 10 and idle I/O priority. In ``B`` and
``C`` it also reads the agent's snapshot at every sample. It then prints
``Run N is measured. Quit the game.`` and waits for the scope to go.

A run is not kept, and the next call takes it again, when:

- the game quits before the time is up, or ``SIGINT`` or ``SIGTERM`` stops
  the run;
- the agent or attestation ran during an ``A`` run, or the agent was not
  running in every sample of a ``B`` or ``C`` run;
- a ``C`` run with agent figures protected nothing, which means
  ``lota-proton-hook`` is missing from the launch options, or a ``B`` run
  protected the title.

The run's MangoHud log is the newest ``.csv`` in the session directory
written since the game started. It is summarised into the run and kept as
``frames-NN.csv``; without one the run has no frame times. Each file is
written aside, read back by the validator of ``lota-bench validate``, and
only then given its name, so a session directory never holds a
half-written file. After the last run the same call joins the plan and
every run into ``result.json``, and the session is complete; a call on a
complete session says so and exits with 0.

Reading a session
=================

``lota-bench report`` reads a result or a summary:

.. code-block:: console

   $ lota-bench report ~/bench/example/result.json
   Example Title: 3 rounds of A B C, 60 s a run after 30 s to settle

     proton     9.0
     settings   high, 1440p
     cpu        Example CPU 8-Core
     gpu        Example GPU
     kernel     6.0.0
     distro     example 1
     tpm        tpm_example
     selinux    enforcing
     lota-bench 1.0.0
     agent      enforce

                                        A               B               C         B-A         C-A
   frame time median ms        6.94 ±0.02      6.95 ±0.01      6.97 ±0.03     +0.01 ~     +0.03 ~
   frame time p99 ms           8.12 ±0.10      8.15 ±0.07      8.21 ±0.12     +0.03 ~     +0.09 ~
   frame time 1% low ms        9.40 ±0.21      9.44 ±0.18      9.52 ±0.25     +0.04 ~     +0.12 ~
   game CPU %                  182.4 ±1.3      183.0 ±0.9      183.6 ±1.1      +0.6 ~      +1.2 ~
   game memory MiB               4210 ±12         4214 ±9        4219 ±15        +4 ~        +9 ~
   lota-agent CPU %            0.00 ±0.00      0.08 ±0.01      0.11 ±0.01     +0.08       +0.11
   lota-attest CPU %           0.00 ±0.00      0.01 ±0.00      0.01 ±0.00     +0.01       +0.01
   lota-agent memory MiB         0.0 ±0.0       18.2 ±0.3       41.6 ±1.2     +18.2       +41.6
   BPF programs us/s             0.0 ±0.0      310.5 ±8.2      402.7 ±9.9    +310.5      +402.7

   Each figure is the median of the configuration's runs, warm-up left out,
   ± half their range. ~ marks a difference within the two spreads: noise.

Each figure is the median of a configuration's runs, the warm-up left out,
so one disturbed run, an update in the background or a shader compiled
late, does not move it. The ``±`` is half the range of those runs: how far
apart runs of one configuration already are. A difference from ``A`` no
larger than the two spreads together is marked ``~``, noise: the session
cannot tell it from the runs disagreeing among themselves, and more rounds
are what would.

``frame time median``, ``p99``, ``1% low``, in ms
   From the run's MangoHud log, as ``lota-bench frames`` defines them.
   Lower is better. A game held to the display's refresh by vsync keeps its
   frame time on the refresh interval while the CPU has room; for such a
   game the CPU rows give the cost, and the frame times show that nothing
   got worse.

``game CPU``, ``lota-agent CPU``, ``lota-attest CPU``, in %
   The CPU time the cgroup accrued over the run, as a share of one CPU:
   ``cpu_usec / (wall_ms * 10)``. A game busy on two CPUs shows ``200``.
   Both services count as ``0`` in ``A``, and attestation as ``0`` in a
   run where it did not run.

``game memory``, ``lota-agent memory``, in MiB
   The highest ``memory.current`` of the run; the agent's is ``0`` in
   ``A``. The agent's figure in ``C`` counts the page cache of the game's
   files it reads to hash them, which the kernel takes back under
   pressure; ``file`` in the unit's ``memory.stat`` tells it from
   ``anon``.

``BPF programs``, in us/s
   The time the agent's BPF programs ran during the run, per second of it:
   ``bpf_run_ns / wall_ms``. It needs the agent under ``--bench``, and is
   ``0`` in ``A``. The programs run in the processes their hooks fire in,
   the game's among them, so the time is part of their CPU time, not
   added to it.

A figure some runs of a configuration lack is marked ``*``, and one none
of them has is ``-``. The ``agent`` line lists the agent modes of the
``B`` and ``C`` runs, with ``, some runs without --bench`` when that is so.
When a run ran under other power settings than run 0, another CPU
governor, platform profile or power supply, the report ends with
``Run N ran under other power settings than run 0; the session is not
comparable run to run.``

Sharing a session
-----------------

``lota-bench issue`` prints the body of an issue for a result or a
summary: the report in a ``text`` block, then the session's summary in a
``lota-bench`` block, which is what a reader of the issue or a script
takes the figures from:

.. code-block:: console

   $ lota-bench issue ~/bench/example/result.json > issue.md

The summary is read back by the validator before anything is printed, so
the block holds only what ``lota-bench validate`` accepts. The body is at
most 65 536 bytes (:ghsrc:`tools/lota-bench/report.h`); a longer one is
refused.

The files of a session
======================

A session directory holds ``plan.json``, what is measured and on what
machine; ``run-NN.json``, one per run; ``result.json``, the plan and every
run once the last run is in; ``boot_id``; and the kept frame logs. A
summary is a result without its samples, small enough to paste into an
issue. Each JSON file is one object that starts with the same three keys:

.. code-block:: text

   {
     "schema_version": 1,
     "tool": "lota-bench",
     "kind": "plan",
     ...
   }

``kind`` is ``plan``, ``run``, ``result`` or ``summary``, and comes before
every key after it.

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
   "duration_s": 60,
   "interval_ms": 1000

``version``
   The ``lota-bench`` that wrote the plan.

``machine``
   The CPU model and thread count from ``/proc/cpuinfo``, the memory from
   ``/proc/meminfo``, up to four GPUs by PCI id with the name ``pci.ids``
   gives them and the driver bound to them, the kernel release, the
   distribution as ``ID VERSION_ID`` from ``os-release``, the driver of
   ``tpm0`` (``none`` without one) and the SELinux mode.

``game``
   The title, and the Proton, game version and settings it ran with. Only
   the title is required.

``rounds``, ``settle_s``, ``duration_s``, ``interval_ms``
   The options of the first call, with their ranges.

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
    "sample_count": 91, "wall_ms": 90004, "end": "duration",
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
   Run 0 is the warm-up, in ``A``; the runs after it are in ``A``, ``B``
   and ``C`` in turn.

``mode``, ``agent_bench``
   The agent's mode as its status reports it, ``none`` in ``A``, and
   whether it runs with ``--bench``.

``power``
   The CPU frequency governor of ``cpu0``, the ACPI platform profile, and
   whether the machine ran on ``ac`` or ``battery``, ``unknown`` when it
   cannot tell.

``samples``
   One sample every ``interval_ms``. ``t_ms`` is milliseconds since the
   first sample and increases. Each source is ``null`` while its cgroup is
   absent, or an object holding every metric.

``end``
   Why sampling stopped: ``duration``, or ``sample-cap`` at 14 400
   samples. A ``game-gone`` or ``interrupted`` run is not kept.

``totals``
   Each source over the whole run: the CPU time, faults and I/O accrued
   between samples, and the highest ``memory.current``. A cgroup that
   appears after the first sample, or whose counter goes back, counts in
   full from then. A source whose cgroup was never there is ``null``.

``agent``
   From the agent's snapshots: the time and runs of its BPF programs
   between the first and the last snapshot of the run, the most memory its
   BPF maps locked, and the most processes it protected at once. ``null``
   when no snapshot could be read or the agent ran without ``--bench``.

``frames``
   The run's MangoHud log, summarised as ``lota-bench frames`` does, in
   microseconds; ``null`` without a log.

``self``
   The sampler's own user and system CPU time and peak resident set.

In ``result.json`` each run is an element of ``runs`` in the same form; a
summary leaves out every ``samples``.

Text
----

Apart from the names of the fixed sets above, a file carries text only in
the machine's, the game's and the power settings' fields and in
``version``. Each is cleaned when it is read: printable ASCII only, with
``/``, ``\`` and ``"`` turned into ``_``, blanks collapsed and trimmed, at
most 64 bytes (:ghsrc:`tools/lota-bench/field.c`). No path, host name,
user name, process name or command line is written, which is what makes a
file fit to attach to a public issue.

Validating a file
=================

.. code-block:: console

   $ lota-bench validate result.json
   result.json: valid result, 10 runs of Example Title

``validate`` accepts what ``lota-bench`` writes and nothing more: every
key known and present once, every name one of its fixed set, every text
field as cleaning leaves it, every number an unsigned integer, nothing
after the object, and the file at most 64 MiB. A session must also add
up: as many runs as its rounds make, each in its place and in the
configuration that place calls for, ``sample_count`` matching the samples,
and each run showing the state of LOTA its configuration stands for. An
``A`` run had no agent, a ``B`` or ``C`` run had it running, a ``C`` run
with agent figures protected at least one process and a ``B`` run none. A
refusal names the byte offset of the first problem:

.. code-block:: console

   $ lota-bench validate edited.json
   edited.json: invalid: offset 57: unknown key "path"

The validator is what stands between a contributed file and the tree, so
it is fuzzed: ``make fuzz-bench-result`` builds the harness, which also
checks that no accepted input carries a ``/`` or a ``\``
(:ghsrc:`fuzz/fuzz_bench_result.c`). The MangoHud log reader has its own,
``make fuzz-bench-frames``.
