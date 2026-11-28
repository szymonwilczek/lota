.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============
Userspace API
=============

These pages describe what a game, its server and an anti-cheat use from
LOTA: the C libraries, documented from their headers under ``include/``,
and the Go module.

* :doc:`stability` -- what an integrator may build against, and what a change to
  it costs.
* :doc:`gaming` -- the client library of a game process.
* :doc:`server` -- token verification on the relying party.
* :doc:`anticheat` -- heartbeat sessions and their verification.
* :doc:`wine-hook` -- attestation files for a title under Wine or Proton.
* :doc:`go-sdk` -- token and boot evidence verification in Go.

.. toctree::
   :hidden:

   stability
   gaming
   server
   anticheat
   wine-hook
   go-sdk
