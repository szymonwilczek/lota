.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==========================
Installing LOTA on your PC
==========================

A game you play, or one you want to play, asks your PC to prove it is running
the software it says it is. LOTA is the part on your side that does the
proving. This page walks through installing it from the beginning. It assumes
nothing: every term is explained where it first appears, and every command is
one line to copy.

You need a Linux PC, about half an hour, and one or two restarts.

.. note::

   Neither package repository below is published, so their ``dnf`` commands
   do not work yet. Until one of them is, the route onto a PC is
   :ref:`building the packages from source <player-from-source>`. Everything
   after that section is the same either way.

.. contents:: On this page
   :local:
   :depth: 1

What leaves your PC
===================

Before any of it: LOTA does not read your files, your messages, your browser
or anything you type. What it sends is a short statement, signed by a chip on
your motherboard, that says three things.

* **How this PC booted.** Not what is on it -- a set of numbers that the
  firmware and the boot loader record as the machine starts. They change if
  the kernel is replaced; they say nothing about your documents.
* **Which programs asked to be protected.** A game that uses LOTA asks for
  itself to be protected while it runs. The statement carries the identity of
  those programs and nothing about the rest.
* **When the statement stops being valid.** They are short-lived on purpose.

It is not a permanent identifier of you. Each publisher gets its own key on
your machine, so two publishers cannot compare notes and work out that the two
PCs are one PC.

Nothing is sent while you are not playing. LOTA reports to a publisher only
while a game of theirs is running, and stops when you close it. A PC sitting
at the desktop with LOTA installed reports to nobody.

You can remove it at any time; :ref:`the last section <player-removing>` says
how.

Will my PC work?
================

Three things have to be true, and every one of them is a firmware feature your
PC either has or does not. Check before installing anything -- these commands
only read::

    [ -d /sys/firmware/efi ] && echo UEFI || echo BIOS
    ls /dev/tpmrm0
    mokutil --sb-state

On a PC that is ready, they answer like this::

    UEFI
    crw-------. 1 root root 252, 65536 /dev/tpmrm0
    SecureBoot enabled

If any of the three answers differently, the PC is not ready *yet*. Every case
is covered under :ref:`player-when-it-stops` below, with what to do about it.
Two of them are settings you can change; one of them is not.

Installing the package
======================

LOTA is packaged for Fedora and for RHEL-compatible distributions (Rocky,
Alma). Pick either channel -- they ship the same thing, built two ways.

**The project's COPR repository**, rebuilt from source for each Fedora
release::

    sudo dnf copr enable szymon-wilczek/lota
    sudo dnf install lota-agent

**The project's own signed repository**, which serves pre-built packages::

    sudo dnf config-manager --add-repo https://lota.example/rpm/lota.repo
    sudo rpm --import https://lota.example/rpm/RPM-GPG-KEY-lota
    sudo dnf install lota-agent

Either way ``dnf`` refuses anything the project's key did not sign, so a
tampered package does not install.

Installing the package does not switch LOTA on. It puts the files in place;
the next section does the rest.

.. _player-from-source:

Building it yourself
--------------------

Where neither repository is reachable, the same files are built from the
source tree. It needs the build tools, and the build takes a few minutes on a
laptop::

    sudo dnf install git make gcc clang llvm golang bpftool \
        libbpf-devel openssl-devel tpm2-tss-devel libseccomp-devel \
        systemd-devel dbus-devel SDL2-devel libcurl-devel \
        elfutils-libelf-devel zlib-devel selinux-policy-devel
    git clone https://github.com/szymonwilczek/lota
    cd lota
    make all

LOTA ships a kernel component that it refuses to load unless somebody signed
it, and building it yourself makes you that somebody. Generate a key, sign
with it, install::

    ./build/lota-agent --gen-signing-key $HOME/lota-enforcement
    make sign-bpf SIGNING_KEY=$HOME/lota-enforcement.key \
        SIGNING_PUBKEY=$HOME/lota-enforcement.pub
    sudo make install SIGNING_PUBKEY=$HOME/lota-enforcement.pub

The two commands say what they wrote::

    Generated Ed25519 keypair:
      Private key: /home/you/lota-enforcement.key
      Public key:  /home/you/lota-enforcement.pub

    Signed: build/lota_lsm.bpf.o
    Signature: build/lota_lsm.bpf.o.sig

The private half is yours and stays on this PC. The public half is installed
beside the component, and the agent checks the signature against it every time
it starts -- which is why the path is passed to the install as well.

This route puts the files in place and changes nothing else, exactly as
``dnf install`` does. The next section is the rest, either way.

Finishing the install
=====================

One command drives the rest::

    sudo lota-install

It works in 13 steps. Before each one it says what it is about to change
and why, and waits for you to agree. Nothing is changed silently, and you can
stop at any step.

Some of the steps need a restart to take effect, because the parts they
switch on run during boot and cannot be started in a machine that is already
up. The installer says so when it reaches one, and running ``sudo
lota-install`` again after the restart picks up where it left off, not starting
over.

To see where things stand without changing anything, ask for a report::

    sudo lota-install --status

It prints every step and what it found::

    [lota-install] LOTA Guided Install <version>
    [lota-install] Hardware-rooted attestation for this host
    [lota-install] stage 1/13: Preflight: Hardware and Host Requirements
    [lota-install]   already satisfied: Preflight: Hardware and Host
        Requirements - TPM 2.0 present, Secure Boot on, tooling found
    [...]
    [lota-install] stage 13/13: Self-check & summary
    [lota-install]   already satisfied: Self-check & summary - Ready: floor
        satisfied, agent binary immutable, service running, and no publisher
        named yet - the certificate arrives when a title first asks.

    0 of 13 stages need work.

(Each stage prints on one long line; the indented continuations above are
wrapped to fit this page.)

**"0 of 13 stages need work" is the finish line.** Your PC is installed.

Note what the last line says: *no publisher named yet*. That is expected, and
the next section explains it.

.. _player-when-it-stops:

When it stops and asks for something
====================================

The installer stops, not guess. It prints ``BLOCKED`` followed by what
it found and what to do. These are the ones a real PC runs into.

Secure Boot is turned off
-------------------------

The most common one. Secure Boot is the firmware feature that makes your PC
refuse to boot a kernel nobody signed; LOTA cannot stand in for it, and there
is no way around it::

    [lota-install]   BLOCKED: Preflight: Hardware and Host Requirements -
    Secure Boot is off. It is a firmware setting, so LOTA cannot turn it on
    for you -- and it cannot be worked around either: Secure Boot is the
    machine-independent anchor a verifier uses to conclude the kernel it is
    talking to is the one the distribution signed. The firmware to change is
    the one on this <your PC's make and model>. Run 'systemctl reboot
    --firmware-setup' to reboot straight into firmware setup; this firmware
    accepts that request. [...] The setting is called Secure Boot and usually
    sits under a Security or Boot heading; set it to Enabled, save, and re-run
    lota-install. Turning it on keeps distribution kernels bootable; only
    modules built locally (DKMS, akmods) need their key enrolled once with
    'mokutil --import'.

The message names your own machine and the route into its firmware, because
the menu differs between makes and even between two revisions of one model.
Follow what it prints rather than a guide written for somebody else's PC.

Turning Secure Boot on does not stop your distribution's kernels from booting.
The one thing it affects is a driver you built yourself -- a graphics driver
installed outside the distribution's packages is the usual case -- which needs
its key enrolled once, with the ``mokutil --import`` the message names.

There is no TPM, or it is switched off
--------------------------------------

The TPM is a small chip (or a feature of your processor) that holds the key
your PC signs with. Without one there is nothing to sign with::

    [lota-install]   BLOCKED: Preflight: Hardware and Host Requirements - No
    TPM 2.0 device (/dev/tpmrm0). Enable the TPM (Intel PTT / AMD fTPM /
    discrete) in firmware setup. LOTA's hardware root of trust cannot exist
    without it.

Most PCs sold in the last decade have one, and it is often *on* by default.
It is in the same firmware setup as the Secure Boot setting above,
usually under Security, named PTT on Intel boards and fTPM on AMD boards. Turn
it on, save, and run ``sudo lota-install`` again.

If the firmware has no such setting at all, the machine genuinely does not
have one, and nothing on this page will make it work. That is the end of the
road for that PC, but thank you for your interest in the project.

The PC boots in the old BIOS mode
---------------------------------

Not a setting LOTA can fix from inside the running system::

    [lota-install]   BLOCKED: Preflight: Hardware and Host Requirements - This
    host booted via legacy BIOS/CSM, not UEFI. BIOS is unsupported: it
    measures neither the firmware and Secure Boot state the verifier pins nor
    an EFI variable the event log can carry, so the initramfs helper, the
    agent and the verifier each refuse such a host. Switch the firmware to
    UEFI mode and reinstall.

Read that last sentence carefully: **reinstall**. A system installed in BIOS
mode does not start booting in UEFI mode because the firmware setting changed
-- the disk is laid out differently. Switching the firmware to UEFI and
reinstalling the distribution is what it takes, and that erases the disk.

It is a real dead end for an existing install, and worth knowing before you
spend an evening on it. Nothing else on this page helps here.

The kernel needs boot settings it does not have yet
---------------------------------------------------

Step 6 checks that the running kernel enforces a floor: signed drivers, kernel
lockdown, and file integrity checking. If it does not, the installer offers to
add the missing boot parameters for you, explains that they take effect at the
next boot and that removing them undoes it, and waits for you to agree.

Say yes and restart. There is nothing to type and nothing to undo afterwards.

It says a restart is needed
---------------------------

It means it. The boot-time parts of LOTA -- the early lock on the measurement
a game will read, and the kernel settings above -- exist to run before
anything else on the machine does, so they cannot be switched on from inside a
system that is already running.

Restart, then run ``sudo lota-install`` again. It resumes at the first step
that still needs work; the ones already done stay done.

Games that run through Steam
============================

This is the one step that asks you to type something into a game, and it
applies to any game launched through Steam -- every Proton (Windows) title and
most native Linux ones. Steam runs games inside a container that cannot see
LOTA unless it is told to.

Run this from your normal user account, **not** with ``sudo``::

    lota-steam-setup

It checks everything on the way and then prints the exact line to use::

    === Steam Launch Options ===

      Paste this string into the game's Properties ->
      General -> Launch options:

        LOTA_HOOK_LOG_LEVEL=info lota-proton-hook %command%

    [OK]   All checks passed.  LOTA Steam integration is ready.

Copy it from your own terminal rather than from this page, because the check
above it is the part that matters: it tells you whether this account has a
socket to reach at all.

In Steam, right-click the game, choose **Properties**, and paste the line into
**Launch options** as a single line. Repeat for each game that uses LOTA.

If it tells you a restart is needed first, that is the per-account setup:
``lota-steam-setup --register-uid`` records the account that needs a socket,
the agent reads that when it starts, and it takes effect at the next boot. The
command says so before it changes anything.

Is it actually working?
=======================

After the install, and before you have played anything, your PC will say it is
**not attested**, and that is correct. LOTA reports to a publisher only while
one of their games is running. A PC at the desktop reports to nobody -- that
is the privacy property from the top of this page, not a broken install.

So the check has two halves.

**Is the service running?** ::

    systemctl is-active lota-agent

::

    active

**Is it reaching a game?** With the game running, from your own account::

    lota-steam-setup --verify

It reports the socket as ready only when this account can actually open it,
and prints who owns it when it cannot -- which is the answer for an account
that is not in the ``lota`` group.

For a Steam game specifically, the bridge writes its state to a file you can
read while the game is up::

    cat "$XDG_RUNTIME_DIR/lota-hook/lota-status"

::

    LOTA_ATTESTED=1
    LOTA_OFFLINE=0
    LOTA_FLAGS=0x0000001f
    LOTA_VALID_UNTIL=1789908913
    LOTA_ATTEST_COUNT=60
    LOTA_FAIL_COUNT=1
    LOTA_UPDATED=1789908848
    LOTA_PID=10093
    LOTA_PROTECTED=0

Two of those lines are the answer. ``LOTA_ATTESTED=1`` means the game is
getting what it asked for. ``LOTA_OFFLINE=1`` means the bridge cannot reach
the agent -- check the service above, and check that the launch options were
pasted into *this* game. The file is left behind when the game exits, so read
``LOTA_UPDATED`` (a Unix timestamp) before trusting what it says.

If a game still refuses to start, the thing to send its support is what those
commands print. It tells them in one line whether the problem is on your PC or
on theirs.

.. _player-removing:

Pausing and removing it
=======================

**Pausing** is deliberately awkward, and the reason is worth a sentence.
LOTA's job is to be impossible for a cheat to switch off mid-game, so it
cannot be stopped the ordinary way, and starting it again takes a restart::

    sudo lota-install --pause

or::

    sudo lota-agent --shutdown

It explains itself before doing anything, and does nothing if you answer
``q``::

    [lota-install] Pausing stops the agent through its own graceful path
    ('lota-agent --shutdown'). systemd cannot stop the agent - the anti-tamper
    hook blocks that - so this dedicated path is the only clean way down.
    [lota-install] On the way down the agent poisons its TPM measurement slot
    (PCR 14) on purpose, so this boot can no longer attest. That is the
    security contract, not a fault: resuming therefore needs a reboot (see
    --resume).
    [lota-install] Pause the agent now? [Enter to continue, q to quit]

Starting it again is ``sudo lota-install --resume``, which offers to reboot
and defaults to not doing it. A paused PC boots and works normally; the agent
just refuses to run until the restart, so nothing else takes over the machine
in the meantime.

**Removing** it is the ordinary uninstall::

    sudo dnf remove lota-agent

The boot parameters the installer added stay behind. They are standard kernel
settings, they harm nothing on their own, and editing them out is a separate
job you can leave alone. The per-publisher keys live under ``/var/lib/lota``
and go with the package.

Where to next
=============

* Every detail of the 13 steps, for somebody who wants to read ahead:
  :doc:`the guided install reference <../operator/player-install>`.
* What a publisher receives and what they can do with it:
  :ghsrc:`examples/anticheat-integration.rst`.
* What LOTA is defending against, in full:
  :doc:`the threat model <../security/threat-model>`.

And if a sentence here still does not land
==========================================

Select this whole page, copy it, and paste it into whichever chat assistant
you already use, with your question underneath. The page is written to survive
that: it says what the tool does, what it refuses, and what it prints, so an
assistant reading it has everything it needs to explain a step in whatever
words work better for you -- or to translate the lot into your language.

Two things worth keeping in mind. Whatever you paste goes to whoever runs that
assistant, so paste the page freely and think twice about the output of your
own terminal. And an assistant will sound just as confident when it invents a
command as when it repeats one from here -- if the two disagree, this page and
the installer's own words are the ones that were run on real hardware.
