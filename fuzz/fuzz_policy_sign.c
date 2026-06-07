// SPDX-License-Identifier: MIT
//
// Fuzz the Ed25519 policy signature verifier.
//
// policy_verify_buffer() (and the policy_verify_file() that wraps it) is the
// gate that decides whether a signed startup policy or a compiled BPF object is
// authentic. Both the object bytes and the detached signature come off disk and
// may be attacker-supplied, so the verifier must reject every forged or
// truncated signature without misbehaving -- and must accept a genuine one.
//
// Fresh keypair is generated once; each run feeds attacker-controlled data
// and a 64-byte signature through the real verify path, then signs the same
// data and asserts the round-trip verifies (a real signature must never be
// rejected, a near-miss never accepted).
//
// Build:
//   clang -fsanitize=fuzzer,address -g -O1 \
//     fuzz/fuzz_policy_sign.c src/agent/policy_sign.c \
//     -o build/fuzz-policy-sign -lcrypto
//
// Run:
//   ./build/fuzz-policy-sign -max_len=65536
//
// Copyright (C) 2026 Szymon Wilczek

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/agent/policy_sign.h"

static char g_priv_path[] = "/tmp/lota-policy-fuzz-priv-XXXXXX";
static char g_pub_path[] = "/tmp/lota-policy-fuzz-pub-XXXXXX";

int LLVMFuzzerInitialize(int *argc, char ***argv);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	int fd;

	(void)argc;
	(void)argv;

	/* materialize unique paths, then let the generator own the contents */
	fd = mkstemp(g_priv_path);
	if (fd >= 0)
		close(fd);
	fd = mkstemp(g_pub_path);
	if (fd >= 0)
		close(fd);

	if (policy_sign_generate_keypair(g_priv_path, g_pub_path) != 0)
		abort(); /* cannot fuzz the verifier without a key */

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t sig[POLICY_SIG_SIZE];
	const uint8_t *msg;
	size_t msg_len;

	if (size > LOTA_MAX_SIGNED_OBJECT_SIZE)
		return 0;

	/*
	 * carve a fuzzer-chosen signature off the front so the verifier sees a
	 * hostile signature over hostile data; the rest is the signed message
	 */
	if (size >= POLICY_SIG_SIZE) {
		memcpy(sig, data, POLICY_SIG_SIZE);
		msg = data + POLICY_SIG_SIZE;
		msg_len = size - POLICY_SIG_SIZE;
	} else {
		memset(sig, 0, sizeof(sig));
		msg = data;
		msg_len = size;
	}

	policy_verify_buffer(msg, msg_len, g_pub_path, sig);

	/* round-trip: genuine signature over the same data must verify */
	if (policy_sign_buffer(msg, msg_len, g_priv_path, sig) == 0) {
		if (policy_verify_buffer(msg, msg_len, g_pub_path, sig) != 0)
			abort();

		/* single-bit flip must be rejected */
		sig[0] ^= 1;
		if (policy_verify_buffer(msg, msg_len, g_pub_path, sig) == 0)
			abort();
	}

	return 0;
}
