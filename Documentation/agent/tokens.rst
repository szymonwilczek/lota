.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

======
Tokens
======

GET_TOKEN rate limits
=====================

Every ``GET_TOKEN`` costs a fresh TPM quote, so the agent limits how fast
they can be asked for. The limits are two, and they measure different things
(``TOKEN_RATE_LIMIT_PER_SESSION`` and ``TOKEN_RATE_LIMIT`` in
``src/agent/ipc.h``).

The **session budget** is what one title may spend. A connection is a
session, and a title holds one, so the budget is held on the connection and
dies with it. It is sized so no realistic heartbeat reaches it.

The **uid ceiling** is the bound on how much of the TPM one user may consume.
It has to hold several sessions at once, because on a player's machine every
title runs as the same uid: a ceiling sized for one title throttles the second
game for what the first one spent.

``GET_BOOT_EVIDENCE`` reads the TPM and the event log, so it is charged to the
uid ceiling too.

Both are needed. Without the session budget one title can spend the whole uid
allowance; without the uid ceiling a caller opens connections until the TPM is
saturated. Three ``_Static_assert``\ s in ``ipc.h`` keep the relationship
honest: the session budget must exceed the reference heartbeat rate, the uid
ceiling must cover at least two sessions, and the session budget must stay
the tighter of the two. Changing either constant without the other fails the
build rather than starving a title at runtime.

At the uid ceiling of one token a second, tokens occupy the TPM about 5% of
the time at the 48 ms per token measured on the validation host, and about
17% at the ~171 ms per quote also recorded there. The reference 5-second
heartbeat costs about 1%. The limits are sized against the slower figure.
:doc:`tpm` carries both measurements and the
method.

Attestation token quote binding
===============================

The token's TPM quote signs one 32-byte value, its ``extraData``, and that
value is what ties every other field in the token to the signature:

.. code-block:: text

   extraData = SHA256(valid_until || flags || pcr_mask || nonce ||
                      policy_digest || runtime_protect_digest ||
                      stopped_ms)

Integers are little-endian. Three implementations must agree on it byte for
byte: the agent that builds the quote
(``include/lota_token_quote_nonce.h``), the C verifier
(``lota_server_verify_token()`` in ``src/sdk/lota_server.c``) and the Go one
(``ComputeTokenQuoteNonce`` in ``sdk/server/verify.go``). A field that is not
in this digest is *not* signed, however trustworthy it looks in the struct,
so adding one to the token means adding it here in all three places.

A relying party should call one of the two verifiers rather than
reimplement the binding.

Both also apply the same freshness window, and that is the second thing
they must agree on. The token carries an expiry and no issue time, so
``valid_until`` is the only temporal anchor: an agent on the default
attestation interval mints a token expiring one interval from now, and both
verifiers refuse one whose expiry is further ahead than
``LOTA_SERVER_MAX_TOKEN_AGE_SEC`` plus ``LOTA_SERVER_MAX_CLOCK_SKEW_SEC``
(``DefaultMaxTokenAge`` and ``MaxClockSkew`` in Go). Raising the agent's
``attest_interval`` above that window makes every token it mints
unverifiable, so the two move together. A relying party that wants a
tighter bound than the window applies it to the verified ``valid_until``
itself.
