.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============
Userspace API
=============

* :doc:`Public API and ABI surface <stability>` -- what an integrator may
  build against, and what a change to it costs.
* :doc:`Gaming SDK <gaming>` -- the client library of a game process.
* :doc:`Server SDK <server>` -- token verification on the relying party.
* :doc:`Anti-cheat SDK <anticheat>` -- heartbeat sessions and their
  verification.
* :doc:`Wine hook <wine-hook>` -- attestation files for a title under Wine
  or Proton.

.. toctree::
   :hidden:

   stability
   gaming
   server
   anticheat
   wine-hook
