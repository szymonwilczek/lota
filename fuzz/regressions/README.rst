.. SPDX-License-Identifier: MIT

=========================
C fuzz target reproducers
=========================

One directory per make target (``fuzz-config/``, ...), holding inputs that
once made it fail, named after what they caught. ``make fuzz-regress`` replays
them; a file that still fails fails the run. Commit a reproducer before its
fix; see ``Documentation/contributor/development/testing-policy.rst``.
