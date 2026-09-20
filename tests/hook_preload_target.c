/* SPDX-License-Identifier: MIT */
/*
 * Executable the shell tests preload the Wine/Proton hook into
 *
 * The hook does its work in its constructor, so the program it is loaded
 * into only has to start and exit; this one does nothing else.
 *
 * A system binary would do the same in a plain build, but not under
 * SANITIZE. The hook's objects are then instrumented and call into the
 * sanitizer runtime, while the shared object does not carry that runtime:
 * the runtime belongs to the executable. clang links it statically into
 * the program alone, and gcc's libasan refuses to start unless it comes
 * first in the link map. Preloaded into /bin/true the hook fails to load
 * on an undefined __asan_* or __tsan_* symbol and never runs, so its
 * checks fail under every sanitizer job without exercising the hook.
 *
 * This program is built with the hook's CFLAGS and so carries the same
 * runtime, or none in a plain build. A test puts the shared runtimes it
 * links ahead of the hook in LD_PRELOAD, which keeps gcc's runtime first;
 * clang's static runtime needs nothing.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

int main(void)
{
	return 0;
}
