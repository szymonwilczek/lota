.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==========
Publishers
==========

A publisher is whoever a title on the host plays for: a game studio, or the
operator of a fleet. The host answers to each publisher with an attestation
key of its own, certified by that publisher's CA, and, when the publisher
runs a verifier, with reports to it. A publisher is configured as a
``[profile "name"]`` section of the configuration (:doc:`configuration`) and
stored under ``/var/lib/lota/profiles/<id>/`` (:doc:`index`).

Identity
========

A publisher's identity is the lowercase hex SHA-256 of the
SubjectPublicKeyInfo of its CA trust anchor, the file the profile's
``ca_cert`` names; only the first certificate in the file counts
(:ghsrc:`src/agent/profile.h`). The section name is a label for the operator
and carries no meaning to the agent. A publisher moving its CA to another
address keeps its identity, and two publishers on one host name do not
collide.

The identity names the profile directory, ``--allow-publisher``,
``--forget-publisher`` and ``--reenroll --publisher``, and a title selects a
publisher by it (:doc:`ipc`).

An anchor that is no CA certificate, such as a server's TLS certificate,
works, and ``--add-publisher`` warns about it: re-issuing that certificate
over another key derives a second identity, and the first keeps its key and
its TPM slot until it is forgotten.

Adding a publisher
==================

``lota-agent --add-publisher HOST --ca-cert ANCHOR`` appends a profile to the
configuration (:doc:`command-line`). With ``--server`` the profile reports to
that verifier; without it the profile is token-only. ``--reporting`` sets
``reporting``, default ``session``, and ``--publisher-name`` the label,
default ``publisher-`` followed by the first 16 characters of the identity.

The command refuses, and writes nothing:

* an anchor it cannot read;
* a label the parser would refuse, or one another publisher holds;
* a ninth publisher;
* a configuration that does not parse as it stands;
* a result that does not parse when read back.

An anchor already configured, under any label or path, is reported and
nothing is written. So is a configured profile of the same CA host and port
whose anchor cannot be read, as it may be the same publisher. The rest of
the file is copied through unchanged.

Both agent units run with a private ``/tmp``, so an anchor under ``/tmp`` or
``/var/tmp`` is invisible to them and the profile loads without an identity.
The command warns about such a path; ``/etc/lota/`` is the place for an
anchor.

``--add-publisher`` records no consent. A running daemon and ``--attest``
loop learn of the profile on reload:

.. code-block:: sh

   sudo systemctl try-reload-or-restart lota-agent lota-attest

Until then the daemon refuses a title that selects the publisher, and the
loop does not report to it.

Consent
=======

The agent enrolls with a publisher only after somebody at the host has agreed
to answer to it. Agreement is the ``consent`` file in the profile directory,
mode 0600, holding the time and the uid that recorded it
(:ghsrc:`src/agent/profile.c`). Two commands write it:

``lota-agent --allow-publisher ID``
  Records consent for the identity, before any enrollment and with no
  configuration needed. It prints what the publisher can read from the host
  and how to take the consent back.

``lota-agent --enroll``
  Records consent for the anchor it enrolls against, then enrolls.

Without consent the loop does not enroll the publisher and logs the
``--allow-publisher`` command to run, and it does not re-enroll the
publisher unattended either. A title that selects the publisher is refused
with ``LOTA_IPC_ERR_CONSENT_REQUIRED``, so the title can show the person at
the host a screen to agree on.

Enrollment
==========

Enrollment gets the publisher's AIK certified by its CA; the exchange is in
:doc:`tpm`. It runs in one of two ways.

At runtime
  The ``--attest`` loop enrolls a profile that has consent, names a CA and
  has no enrollment record: when its round reaches the profile, and at the
  next exchange with the daemon after a title selects it. It presents no
  enrollment token. A failed attempt backs off, and the other publishers
  keep their cadence. A profile whose record exists but does not read is
  never enrolled over; the loop names the file to restore.

With ``--enroll``
  The operator enrolls against ``--ca-server`` and ``--ca-cert``, and can
  present a token with ``--enroll-token-file``. A CA that requires a token
  is enrolled with this way.

Both write ``enroll_state.dat``: the CA endpoint the enrollment reached, the
anchor, the pin and the token. From then on the record, not the
configuration, says where renewal goes. When the profile names another CA
endpoint than the record, the loop logs once the ``--enroll`` command that
moves it.

The loop renews a certificate that has entered the last third of its
lifetime, at the recorded endpoint and with the recorded token; it presents
the anchor the configuration names, or the recorded one when the
configuration names none. A failed renewal backs off, and the unit status
names the publisher and the time left.

``lota-agent --reenroll --publisher ID`` enrolls one publisher again with its
recorded endpoint; ``--ca-server``, ``--ca-port`` and ``--ca-cert`` move it to
another, recorded once the CA certifies the key. ``--reenroll`` alone
re-enrolls every publisher whose certificate names another key than the one
at its handle, and exits 1 when one fails or cannot be checked.

Reporting
=========

The loop reports to a publisher's verifier on that profile's interval and
signs the report with that publisher's AIK. Each publisher has its own
failure backoff, so one unreachable verifier delays no other.

``reporting = session``
  The default. The loop reports to the publisher only while a title bound
  to it is connected to the daemon. When the last such connection closes,
  reporting stops and the publisher's verdict on the host is dropped.

``reporting = continuous``
  The loop reports all the time, as a fleet the operator owns needs.

A profile with ``verifier = none`` is token-only: nothing is reported to the
publisher, and the host holds no verdict of theirs. Its tokens carry
``LOTA_STATUS_TOKEN_ONLY`` and never ``LOTA_STATUS_ATTESTED``, and the
publisher's backend verifies them.

Enforcement, the PCR 14 commitment, enrollment and renewal never wait for a
session; only the report does.

A title that selects a publisher gets tokens signed with that publisher's
AIK and reads that publisher's verdict alone (:doc:`tokens`). A title that
names no publisher gets tokens signed with the AIK of the only profile, or
the host AIK with none; with more than one profile its ``GET_TOKEN`` is
refused (:doc:`ipc`). It reads the host-wide verdict: attested while every
publisher that holds a verdict is satisfied, valid until the earliest of
their windows. A session-gated
publisher with no session and a token-only one hold no verdict and count
neither way; with no verdict at all the host is not attested. When every
profile is token-only, the host-wide answer carries
``LOTA_STATUS_TOKEN_ONLY``.

A title that names no publisher opens no session, so on a host where every
profile is session-gated it reads not attested until a title that names one
runs.

Selecting a publisher
---------------------

A title selects a publisher by its identity at connect. The daemon answers:

``LOTA_IPC_ERR_UNKNOWN_PROFILE``
  No loaded profile has that identity: it is not configured, it is added
  after the daemon last read the file, or its anchor cannot be read.

``LOTA_IPC_ERR_CONSENT_REQUIRED``
  Nobody at the host agreed to the publisher.

``LOTA_IPC_ERR_NO_KEY_SLOT``
  The publisher holds no attestation key yet and no handle is free for one.

Otherwise the connection is bound. A publisher never enrolled with is
enrolled by the loop, and the connection reads not attested until that
completes.

Key slots
=========

Every publisher's AIK is a persistent TPM object at its own handle, in the
range ``0x81010010`` to ``0x81010017``; the host answers to at most eight
publishers with a key. The handle is recorded in the profile's
``aik_handle`` file, never derived from the profile's place in the
configuration, so removing one profile moves no other onto another
publisher's key.

A handle in the range is free when no profile records it and the TPM holds
no object at it. A handle that holds an object no profile records, left by a
removed profile or another program, is never evicted by the agent and costs
a slot until somebody removes the object. A TPM with little non-volatile
memory can run out of persistent space below eight (:doc:`tpm`).

Listing
=======

``lota-agent --list-publishers`` lists every profile directory, including
those that hold a consent record alone; consent creates the directory and
nothing removes it but ``--forget-publisher``. For each it prints:

* the time of consent, or that the agent does not enroll the publisher on
  its own without it;
* the CA endpoint it enrolled with, ``not yet``, or that the record does not
  read, with the file and the ``--reenroll`` command;
* the AIK handle and the certificate's remaining validity;
* the state of the AIK authorization files (:doc:`tpm`);
* ``BROKEN`` when the key at the handle is not the one the certificate
  names;
* ``SUPERSEDED`` when the anchor it pinned derives another identity, so
  nothing reaches the profile while it holds its key and slot.

It ends with the keys held, the TPM's persistent objects and capacity, the
free handles of the range, and each handle that holds a key no profile
records.

Forgetting
==========

``lota-agent --forget-publisher ID`` evicts the publisher's attestation key
and deletes its profile directory, consent included. It refuses an identity
the host holds no directory for.

Before evicting, the agent derives the publisher's key again and checks that
the object at the recorded handle is that key. An object that is another
one is left alone: the publisher is forgotten, and the command says the slot
stays taken. When the check or the eviction fails, nothing is deleted.

Forgetting does not remove the profile from the configuration, and it does
not change the key the publisher would get. The AIK is a primary key of the
owner hierarchy whose template carries the publisher's identity
(:ghsrc:`src/agent/tpm.c`), so a publisher agreed to again gets the same
public key back until the TPM's owner hierarchy is cleared. Keys of two
publishers differ, and neither links to the other.
