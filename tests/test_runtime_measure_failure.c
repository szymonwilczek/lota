/* SPDX-License-Identifier: MIT */
/*
 * LOTA runtime image measurement failures - Unit Tests
 *
 * Refused measurement is the one message an integrator reads while bringing title up,
 * so these tests pin what it says: which object stopped the measurement,
 * and which of the two measurable-object cases it is.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../src/agent/runtime_image_measure.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                        \
	do {                                              \
		tests_run++;                              \
		printf("  [%2d] %-55s", tests_run, name); \
	} while (0)

#define PASS()                    \
	do {                      \
		tests_passed++;   \
		printf("PASS\n"); \
	} while (0)

#define FAIL(reason)                           \
	do {                                   \
		printf("FAIL (%s)\n", reason); \
	} while (0)

static void make_failure_at(struct lota_runtime_measure_failure *f,
			    const char *soname, const char *path, int role,
			    uint32_t reported_len, int err)
{
	memset(f, 0, sizeof(*f));
	if (soname)
		snprintf(f->soname, sizeof(f->soname), "%s", soname);
	if (path)
		snprintf(f->path, sizeof(f->path), "%s", path);
	f->role = role;
	f->ino = 4242;
	f->reported_len = reported_len;
	f->err = err;
}

static void make_failure(struct lota_runtime_measure_failure *f,
			 const char *soname, uint32_t reported_len, int err)
{
	char path[LOTA_RT_MAP_PATH_MAX];

	if (!soname) {
		make_failure_at(f, NULL, NULL, LOTA_RT_ROLE_UNKNOWN,
				reported_len, err);
		return;
	}

	snprintf(path, sizeof(path), "/usr/lib64/%s", soname);
	make_failure_at(f, soname, path, LOTA_RT_ROLE_MAPPED_OBJECT,
			reported_len, err);
}

int main(void)
{
	struct lota_runtime_measure_failure f;
	char buf[512];

	printf("Runtime image measurement failure tests:\n");

	TEST("an object without fs-verity is named");
	make_failure(&f, "libcurl.so.4", 0, ENODATA);
	lota_rt_failure_reason(&f, -ENODATA, buf, sizeof(buf));
	if (strstr(buf, "libcurl.so.4") && strstr(buf, "no fs-verity digest"))
		PASS();
	else
		FAIL(buf);

	TEST("an unsupported digest length names both sizes");
	make_failure(&f, "libfoo.so.1", 48, EINVAL);
	lota_rt_failure_reason(&f, -EINVAL, buf, sizeof(buf));
	if (strstr(buf, "libfoo.so.1") && strstr(buf, "48-byte") &&
	    strstr(buf, "SHA-256") && strstr(buf, "SHA-512"))
		PASS();
	else
		FAIL(buf);

	TEST("any other errno still names the object");
	make_failure(&f, "libbar.so.2", 0, EACCES);
	lota_rt_failure_reason(&f, -EACCES, buf, sizeof(buf));
	if (strstr(buf, "libbar.so.2") && strstr(buf, strerror(EACCES)))
		PASS();
	else
		FAIL(buf);

	TEST("a failure before any object renders the errno alone");
	make_failure(&f, NULL, 0, ESRCH);
	lota_rt_failure_reason(&f, -ESRCH, buf, sizeof(buf));
	if (strcmp(buf, strerror(ESRCH)) == 0)
		PASS();
	else
		FAIL(buf);

	TEST("a NULL failure renders the errno alone");
	lota_rt_failure_reason(NULL, -ENOMEM, buf, sizeof(buf));
	if (strcmp(buf, strerror(ENOMEM)) == 0)
		PASS();
	else
		FAIL(buf);

	TEST("a positive errno reads the same as a negative one");
	make_failure(&f, "libcurl.so.4", 0, ENODATA);
	lota_rt_failure_reason(&f, ENODATA, buf, sizeof(buf));
	if (strstr(buf, "no fs-verity digest"))
		PASS();
	else
		FAIL(buf);

	/* The full path says which copy of a name needs fs-verity */
	TEST("a failing object is named by path");
	make_failure_at(&f, "ld-linux-x86-64.so.2",
			"/usr/lib64/ld-linux-x86-64.so.2",
			LOTA_RT_ROLE_MAPPED_OBJECT, 0, ENODATA);
	lota_rt_failure_reason(&f, -ENODATA, buf, sizeof(buf));
	if (strstr(buf, "/usr/lib64/ld-linux-x86-64.so.2"))
		PASS();
	else
		FAIL(buf);

	TEST("two copies of one name read as different objects");
	{
		char other[256];

		make_failure_at(&f, "ld-linux-x86-64.so.2",
				"/usr/lib64/ld-linux-x86-64.so.2",
				LOTA_RT_ROLE_MAPPED_OBJECT, 0, ENODATA);
		lota_rt_failure_reason(&f, -ENODATA, buf, sizeof(buf));
		make_failure_at(&f, "ld-linux-x86-64.so.2",
				"/home/player/.steam/runtime/"
				"ld-linux-x86-64.so.2",
				LOTA_RT_ROLE_MAPPED_OBJECT, 0, ENODATA);
		lota_rt_failure_reason(&f, -ENODATA, other, sizeof(other));
		if (strcmp(buf, other) != 0)
			PASS();
		else
			FAIL(buf);
	}

	/* The role says whether the token was refused or only marked partial */
	TEST("the caller's own executable is named as such");
	make_failure_at(&f, "cs2", "/games/csgo/game/bin/linuxsteamrt64/cs2",
			LOTA_RT_ROLE_EXECUTABLE, 0, ENODATA);
	lota_rt_failure_reason(&f, -ENODATA, buf, sizeof(buf));
	if (strstr(buf, "own executable") &&
	    strstr(buf, "/games/csgo/game/bin/linuxsteamrt64/cs2"))
		PASS();
	else
		FAIL(buf);

	TEST("an object the process mapped is named as such");
	make_failure_at(&f, "libsteam_api.so", "/games/csgo/libsteam_api.so",
			LOTA_RT_ROLE_MAPPED_OBJECT, 0, ENODATA);
	lota_rt_failure_reason(&f, -ENODATA, buf, sizeof(buf));
	if (strstr(buf, "mapped") && !strstr(buf, "own executable"))
		PASS();
	else
		FAIL(buf);

	TEST("an unopened mapping claims neither role");
	make_failure_at(&f, "libmystery.so", "/opt/x/libmystery.so",
			LOTA_RT_ROLE_UNKNOWN, 0, EACCES);
	lota_rt_failure_reason(&f, -EACCES, buf, sizeof(buf));
	if (strstr(buf, "/opt/x/libmystery.so") &&
	    !strstr(buf, "own executable") && !strstr(buf, "mapped"))
		PASS();
	else
		FAIL(buf);

	TEST("an unsupported digest length still names the path and the role");
	make_failure_at(&f, "cs2", "/games/csgo/game/bin/linuxsteamrt64/cs2",
			LOTA_RT_ROLE_EXECUTABLE, 48, EINVAL);
	lota_rt_failure_reason(&f, -EINVAL, buf, sizeof(buf));
	if (strstr(buf, "/games/csgo/game/bin/linuxsteamrt64/cs2") &&
	    strstr(buf, "own executable") && strstr(buf, "48-byte"))
		PASS();
	else
		FAIL(buf);

	TEST("a failure with no path falls back to the object's name");
	make_failure_at(&f, "libcurl.so.4", NULL, LOTA_RT_ROLE_UNKNOWN, 0,
			ENODATA);
	lota_rt_failure_reason(&f, -ENODATA, buf, sizeof(buf));
	if (strstr(buf, "libcurl.so.4") && strstr(buf, "no fs-verity digest"))
		PASS();
	else
		FAIL(buf);

	/*
	 * Coverage is the relying party's call, but two properties are the host's:
	 * something was measured, and the process's own executable is part of it.
	 */
	{
		struct lota_runtime_measure_coverage cov;

		TEST("full coverage is issuable");
		cov.measured = 37;
		cov.unmeasurable = 0;
		if (lota_rt_coverage_verdict(&cov, 1) == 0)
			PASS();
		else
			FAIL("refused a complete measurement");

		TEST("partial coverage is issuable");
		cov.measured = 3;
		cov.unmeasurable = 34;
		if (lota_rt_coverage_verdict(&cov, 1) == 0)
			PASS();
		else
			FAIL("refused a partial measurement");

		TEST("nothing measured is refused");
		cov.measured = 0;
		cov.unmeasurable = 37;
		if (lota_rt_coverage_verdict(&cov, 0) == -ENODATA)
			PASS();
		else
			FAIL("issued an empty measurement");

		TEST("an unmeasurable executable is refused");
		cov.measured = 36;
		cov.unmeasurable = 1;
		if (lota_rt_coverage_verdict(&cov, 0) == -ENODATA)
			PASS();
		else
			FAIL("issued without the title's own code");

		TEST("a NULL coverage is refused");
		if (lota_rt_coverage_verdict(NULL, 1) == -EINVAL)
			PASS();
		else
			FAIL("accepted NULL coverage");
	}

	TEST("a short buffer is still NUL-terminated");
	char small[16];
	make_failure(&f, "libcurl.so.4", 0, ENODATA);
	lota_rt_failure_reason(&f, -ENODATA, small, sizeof(small));
	if (small[sizeof(small) - 1] == '\0' && strlen(small) < sizeof(small))
		PASS();
	else
		FAIL("overran the buffer");

	printf("\n%d/%d runtime measurement failure tests passed\n",
	       tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
