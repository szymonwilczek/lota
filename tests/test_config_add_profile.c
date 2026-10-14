/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for appending a publisher profile to lota.conf.
 *
 * Player buys second game and the game's installer has to register its publisher.
 * Hand-editing config file is not something to ask of them, and an installer
 * that rewrites the file wholesale would drop whatever the operator put there.
 *
 * So the append is a text operation with rules: it never touches what is already
 * in the file, it is idempotent, it refuses to put two publishers under one name,
 * and it stops at the profile cap rather than writing file parser will later reject.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/agent/config.h"

static int g_failures;

/* the text the writer produced, read back the way the agent reads it at the next
 * start: a section that does not load is a host that does not come up */
static int loads_back(const char *text)
{
	char path[] = "/tmp/lota_add_profile_XXXXXX";
	struct lota_config *cfg;
	size_t len = strlen(text);
	int fd = mkstemp(path);
	int rc;

	if (fd < 0)
		return -errno;
	if (write(fd, text, len) != (ssize_t)len) {
		close(fd);
		unlink(path);
		return -EIO;
	}
	close(fd);

	cfg = config_new();
	if (!cfg) {
		unlink(path);
		return -ENOMEM;
	}
	rc = config_load(cfg, path);
	config_free(cfg);
	unlink(path);
	return rc;
}

/* how many publishers a file on disk holds, the way the agent counts them
 * at the next start; negative when the file does not load at all */
static int profiles_in_file(const char *path)
{
	struct lota_config *cfg = config_new();
	int rc;

	if (!cfg)
		return -ENOMEM;
	rc = config_load(cfg, path);
	if (rc == 0)
		rc = cfg->profile_count;
	config_free(cfg);
	return rc;
}

static int write_file(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	FILE *f;

	if (fd < 0)
		return -errno;
	f = fdopen(fd, "w");
	if (!f) {
		int err = errno;

		close(fd);
		return -err;
	}
	fputs(text, f);
	return fclose(f) == 0 ? 0 : -EIO;
}

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

static struct lota_profile mkprofile(const char *name, const char *ca,
				     const char *anchor, const char *verifier)
{
	struct lota_profile p;

	memset(&p, 0, sizeof(p));
	snprintf(p.name, sizeof(p.name), "%s", name);
	snprintf(p.ca, sizeof(p.ca), "%s", ca);
	p.ca_port = 8444;
	snprintf(p.ca_cert, sizeof(p.ca_cert), "%s", anchor);
	snprintf(p.verifier, sizeof(p.verifier), "%s", verifier);
	p.verifier_port = 8443;
	p.session_gated = true;
	return p;
}

int main(void)
{
	char out[16384];
	struct lota_profile p, q;
	int rc;

	printf("=== lota.conf profile append tests ===\n\n");

	p = mkprofile("studio-a", "ca.studio-a.example",
		      "/etc/lota/studio-a.pem", "verifier.studio-a.example");

	{
		const char *base = "attest_interval = 60\n";

		rc = config_profile_append_text(base, &p, out, sizeof(out));
		CHECK(rc == 1, "a first profile is appended");
		CHECK(strstr(out, "attest_interval = 60") != NULL,
		      "what was already in the file is left alone");
		CHECK(strstr(out, "[profile \"studio-a\"]") != NULL,
		      "the section header names the publisher");
		CHECK(strstr(out, "ca_cert = /etc/lota/studio-a.pem") != NULL,
		      "the trust anchor is written");
	}

	{
		/* installer runs twice, or the game is reinstalled */
		char once[16384];

		config_profile_append_text("attest_interval = 60\n", &p, once,
					   sizeof(once));
		rc = config_profile_append_text(once, &p, out, sizeof(out));
		CHECK(rc == 0, "appending the same publisher again is a no-op");
	}

	{
		/* the same publisher under a different label is still the same publisher:
		 * it resolves to one profile directory and one AIK,
		 * so a second section would burn a slot and attest twice to the same place */
		char once[16384];
		struct lota_profile same;

		config_profile_append_text("", &p, once, sizeof(once));
		same = mkprofile("studio-a-again", "ca.studio-a.example",
				 "/etc/lota/studio-a.pem",
				 "verifier.studio-a.example");
		rc = config_profile_append_text(once, &same, out, sizeof(out));
		CHECK(rc == 0,
		      "the same anchor under a different label is a no-op");
	}

	{
		/* two publishers cannot share a name:
		 * the name is how operator reads the file,
		 * and the second would shadow the first */
		char once[16384];

		config_profile_append_text("", &p, once, sizeof(once));
		q = mkprofile("studio-a", "ca.other.example",
			      "/etc/lota/other.pem", "verifier.other.example");
		rc = config_profile_append_text(once, &q, out, sizeof(out));
		CHECK(rc == -EEXIST,
		      "a different publisher under an existing name is refused");
	}

	{
		/* the publisher who runs no verifier:
		 * their backend checks the tokens their titles fetch, so nothing
		 * is reported from this machine and the section has to say so.
		 * the parser refuses a port for a verifier declared absent,
		 * so a writer that emits one produces a file the host cannot load
		 * -- the port carried by the profile is not the operator naming
		 * a target, it is the default nobody chose */
		struct lota_profile t;

		t = mkprofile("studio-b", "ca.studio-b.example",
			      "/etc/lota/studio-b.pem", "");
		t.verifier_port = 9443;

		rc = config_profile_append_text("mode = enforce\n", &t, out,
						sizeof(out));
		CHECK(rc == 1, "a publisher with no verifier is appended");
		CHECK(strstr(out, "verifier = none") != NULL,
		      "the section says the publisher runs no verifier");
		CHECK(strstr(out, "verifier_port") == NULL,
		      "no port is written for a verifier declared absent");
		CHECK(loads_back(out) == 0,
		      "the section the writer produced loads back");
	}

	{
		/* stop at the cap rather than writing file the parser
		 * will reject on the next start */
		char acc[16384];
		char next[16384];
		int i;

		snprintf(acc, sizeof(acc), "%s", "");
		for (i = 0; i < LOTA_CONFIG_MAX_PROFILES; i++) {
			char nm[32];
			char anchor[64];
			struct lota_profile f;

			/* distinct publishers need distinct anchors:
			 * the anchor is the identity, so eight sections sharing
			 * one would be one publisher eight times */
			snprintf(nm, sizeof(nm), "pub%d", i);
			snprintf(anchor, sizeof(anchor), "/etc/lota/pub%d.pem",
				 i);
			f = mkprofile(nm, "ca.example", anchor, "v.example");
			rc = config_profile_append_text(acc, &f, next,
							sizeof(next));
			if (rc != 1)
				break;
			snprintf(acc, sizeof(acc), "%s", next);
		}
		CHECK(i == LOTA_CONFIG_MAX_PROFILES,
		      "the cap is reached, not exceeded");

		{
			struct lota_profile f =
				mkprofile("one-too-many", "ca.example",
					  "/etc/lota/a.pem", "v.example");

			rc = config_profile_append_text(acc, &f, next,
							sizeof(next));
			CHECK(rc == -E2BIG,
			      "the profile past the cap is refused");
		}
	}

	{
		char small[64];

		rc = config_profile_append_text("attest_interval = 60\n", &p,
						small, sizeof(small));
		CHECK(rc == -EOVERFLOW,
		      "a buffer too small is refused rather than truncated");
	}

	/*
	 * The label is text somebody else chose -- an installer's argument,
	 * a store page's studio name -- and the header the writer builds around
	 * it is terminated by a quote. A label carrying one closes the section
	 * the writer meant and opens another, so the file the parser reads back
	 * is not the file the writer described: the settings land on a forged
	 * profile and the whole configuration stops loading.
	 */
	{
		const char *base = "attest_interval = 60\n";
		struct lota_profile forged;

		forged = mkprofile("evil\"]\n[profile \"injected",
				   "ca.studio-a.example",
				   "/etc/lota/studio-a.pem",
				   "verifier.studio-a.example");
		rc = config_profile_append_text(base, &forged, out,
						sizeof(out));
		CHECK(rc == -EILSEQ,
		      "a label carrying a quote and a newline is refused");

		forged = mkprofile("say \"cheese\"", "ca.studio-a.example",
				   "/etc/lota/studio-a.pem",
				   "verifier.studio-a.example");
		rc = config_profile_append_text(base, &forged, out,
						sizeof(out));
		CHECK(rc == -EILSEQ, "a label carrying a quote is refused");

		forged = mkprofile("two\nlines", "ca.studio-a.example",
				   "/etc/lota/studio-a.pem",
				   "verifier.studio-a.example");
		rc = config_profile_append_text(base, &forged, out,
						sizeof(out));
		CHECK(rc == -EILSEQ,
		      "a label carrying a control character is refused");

		forged = mkprofile("", "ca.studio-a.example",
				   "/etc/lota/studio-a.pem",
				   "verifier.studio-a.example");
		rc = config_profile_append_text(base, &forged, out,
						sizeof(out));
		CHECK(rc == -EINVAL, "a profile with no label is refused");
	}

	/*
	 * The same hole in every other field the writer interpolates: a newline
	 * in a host forges a key inside the section rather than a section,
	 * which the parser then accepts -- a publisher pointed at another verifier,
	 * written by a label nobody read.
	 */
	{
		const char *base = "attest_interval = 60\n";
		struct lota_profile forged;

		forged = mkprofile("studio-c",
				   "ca.studio-c.example\nverifier = "
				   "attacker.example",
				   "/etc/lota/studio-c.pem",
				   "verifier.studio-c.example");
		rc = config_profile_append_text(base, &forged, out,
						sizeof(out));
		CHECK(rc == -EILSEQ, "a CA host carrying a newline is refused");

		forged = mkprofile("studio-c", "ca.studio-c.example",
				   "/etc/lota/studio-c.pem",
				   "v.example\nreporting = continuous");
		rc = config_profile_append_text(base, &forged, out,
						sizeof(out));
		CHECK(rc == -EILSEQ,
		      "a verifier host carrying a newline is refused");

		forged = mkprofile("studio-c", "ca.studio-c.example",
				   "/etc/lota/c.pem\nmode = permissive",
				   "verifier.studio-c.example");
		rc = config_profile_append_text(base, &forged, out,
						sizeof(out));
		CHECK(rc == -EILSEQ,
		      "a trust anchor carrying a newline is refused");

		/* the parser refuses a relative ca_cert, so the writer cannot
		 * emit one either */
		forged = mkprofile("studio-c", "ca.studio-c.example",
				   "studio-c.pem", "verifier.studio-c.example");
		rc = config_profile_append_text(base, &forged, out,
						sizeof(out));
		CHECK(rc == -EILSEQ,
		      "a trust anchor that is not an absolute path is refused");
	}

	/*
	 * The text rules answer for the fields the writer interpolates
	 * and nothing else. What is already in the file is copied through
	 * untouched, so a file that had stopped parsing -- a hand edit,
	 * a package that half-replaced it, an earlier version of this writer
	 * -- is appended to and renamed into place, and the verb reports
	 * the publisher added. The host then comes up with no configuration
	 * at all.
	 * So the writer reads the result back before it replaces the live file.
	 */
	{
		char path[] = "/tmp/lota_add_profile_file_XXXXXX";
		int fd = mkstemp(path);

		CHECK(fd >= 0, "a temporary configuration file is created");
		if (fd >= 0) {
			char tmp_path[PATH_MAX];

			close(fd);

			/* a section the parser refuses: a profile with no ca */
			CHECK(write_file(path,
					 "[profile \"half-written\"]\n") == 0,
			      "a configuration that does not parse is staged");
			CHECK(profiles_in_file(path) < 0,
			      "the staged configuration does not load");

			rc = config_profile_append(path, &p);
			CHECK(rc == -EBADMSG,
			      "appending to a configuration that does not parse is refused");
			CHECK(profiles_in_file(path) < 0,
			      "the refusal left the file as it was");

			snprintf(tmp_path, sizeof(tmp_path), "%s.new", path);
			CHECK(access(tmp_path, F_OK) != 0,
			      "the refused replacement is not left behind");

			/* the ordinary path still writes, and what it wrote is
			 * what the next start reads */
			CHECK(write_file(path, "attest_interval = 60\n") == 0,
			      "a loadable configuration is staged");
			rc = config_profile_append(path, &p);
			CHECK(rc == 1, "the publisher is appended to the file");
			CHECK(profiles_in_file(path) == 1,
			      "the file the writer left holds the publisher");

			unlink(path);
			unlink(tmp_path);
		}
	}

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
