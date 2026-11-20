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
#include <sys/stat.h>
#include <unistd.h>

#include "../src/agent/config.h"

#include "test.h"

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

static int stat_open(const char *path, struct stat *st)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	int rc;

	if (fd < 0)
		return -1;
	rc = fstat(fd, st);
	close(fd);
	return rc;
}

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

	test_begin("config add profile");

	p = mkprofile("studio-a", "ca.studio-a.example",
		      "/etc/lota/studio-a.pem", "verifier.studio-a.example");

	{
		const char *base = "attest_interval = 60\n";

		rc = config_profile_append_text(base, &p, out, sizeof(out));
		TEST("a first profile is appended");
		if (rc != 1)
			FAIL("expected: rc == 1");
		TEST("what was already in the file is left alone");
		if (strstr(out, "attest_interval = 60") == NULL)
			FAIL("expected: strstr(out, \"attest_interval = 60\") != NULL");
		TEST("the section header names the publisher");
		if (strstr(out, "[profile \"studio-a\"]") == NULL)
			FAIL("expected: strstr(out, \"[profile \\\"studio-a\\\"]\") "
			     "!= NULL");
		TEST("the trust anchor is written");
		if (strstr(out, "ca_cert = /etc/lota/studio-a.pem") == NULL)
			FAIL("expected: strstr(out, \"ca_cert = "
			     "/etc/lota/studio-a.pem\") != NULL");
	}

	{
		/* installer runs twice, or the game is reinstalled */
		char once[16384];

		config_profile_append_text("attest_interval = 60\n", &p, once,
					   sizeof(once));
		rc = config_profile_append_text(once, &p, out, sizeof(out));
		TEST("appending the same publisher again is a no-op");
		if (rc != 0)
			FAIL("expected: rc == 0");
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
		TEST("the same anchor under a different label is a no-op");
		if (rc != 0)
			FAIL("expected: rc == 0");
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
		TEST("a different publisher under an existing name is refused");
		if (rc != -EEXIST)
			FAIL("expected: rc == -EEXIST");
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
		TEST("a publisher with no verifier is appended");
		if (rc != 1)
			FAIL("expected: rc == 1");
		TEST("the section says the publisher runs no verifier");
		if (strstr(out, "verifier = none") == NULL)
			FAIL("expected: strstr(out, \"verifier = none\") != NULL");
		TEST("no port is written for a verifier declared absent");
		if (strstr(out, "verifier_port") != NULL)
			FAIL("expected: strstr(out, \"verifier_port\") == NULL");
		TEST("the section the writer produced loads back");
		if (loads_back(out) != 0)
			FAIL("expected: loads_back(out) == 0");
	}

	{
		/* every field at its longest still writes a file that loads */
		char path[] = "/tmp/lota_add_profile_XXXXXX";
		struct lota_profile w;
		size_t len;
		int fd;

		w = mkprofile("studio-w", "", "", "");
		memset(w.name, 'w', sizeof(w.name) - 1);
		memset(w.ca, 'c', sizeof(w.ca) - 1);
		memset(w.verifier, 'v', sizeof(w.verifier) - 1);
		memset(w.pin_sha256, 'a', 64);
		w.attest_interval = 240;
		len = LOTA_CONFIG_MAX_LINE - 2 - strlen("ca_cert = ");
		w.ca_cert[0] = '/';
		memset(w.ca_cert + 1, 'a', len - 1);
		w.ca_cert[len] = '\0';

		fd = mkstemp(path);
		TEST("a scratch config is created");
		if (fd < 0)
			FAIL("expected: fd >= 0");
		if (fd >= 0) {
			close(fd);
			rc = config_profile_append(path, &w);
			TEST("a section with every field full fits");
			if (rc != 1)
				FAIL("expected: rc == 1");
			TEST("the full section loads back");
			if (profiles_in_file(path) != 1)
				FAIL("expected: profiles_in_file(path) == 1");
			unlink(path);
		}
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
		TEST("the cap is reached, not exceeded");
		if (i != LOTA_CONFIG_MAX_PROFILES)
			FAIL("expected: i == LOTA_CONFIG_MAX_PROFILES");

		{
			struct lota_profile f =
				mkprofile("one-too-many", "ca.example",
					  "/etc/lota/a.pem", "v.example");

			rc = config_profile_append_text(acc, &f, next,
							sizeof(next));
			TEST("the profile past the cap is refused");
			if (rc != -E2BIG)
				FAIL("expected: rc == -E2BIG");
		}
	}

	{
		/* the file is read the way the agent reads it: only a parsed
		 * profile names a publisher or takes a slot */
		const char *bases[] = {
			"[profile \"old\"]\nca = ca.old.example\n"
			"ca_cert = /etc/lota/studio-a.pem.old\n"
			"verifier = v.old.example\n",
			"# ca_cert = /etc/lota/studio-a.pem\n",
			"ca_cert = /etc/lota/studio-a.pem\n",
			"# [profile \"studio-a\"]\n",
		};
		static const char *const what[] = {
			"a longer anchor path is another publisher",
			"a commented ca_cert is no publisher",
			"the top-level ca_cert is no publisher",
			"a commented section takes no name or slot",
		};
		char acc[16384];
		char next[16384];
		size_t i;
		int n;

		for (i = 0; i < sizeof(bases) / sizeof(bases[0]); i++) {
			rc = config_profile_append_text(bases[i], &p, out,
							sizeof(out));
			TEST(what[i]);
			if (!(rc == 1 && loads_back(out) == 0))
				FAIL("expected: rc == 1 && loads_back(out) == 0");
		}

		rc = config_profile_append_text(
			"[profile \"other\"]\nca=ca.other.example\n"
			"ca_cert=/etc/lota/studio-a.pem\nverifier=v.example\n",
			&p, out, sizeof(out));
		TEST("ca_cert= with no spaces names the publisher");
		if (rc != 0)
			FAIL("expected: rc == 0");

		rc = config_profile_append_text(
			"[ profile \"studio-a\"]\nca = ca.other.example\n"
			"ca_cert = /etc/lota/other.pem\nverifier = v.example\n",
			&p, out, sizeof(out));
		TEST("a spaced header still holds the publisher's name");
		if (rc != -EEXIST)
			FAIL("expected: rc == -EEXIST");

		acc[0] = '\0';
		for (n = 0; n < LOTA_CONFIG_MAX_PROFILES; n++) {
			size_t len = strlen(acc);

			snprintf(acc + len, sizeof(acc) - len,
				 "[ profile \"p%d\"]\nca = ca.example\n"
				 "ca_cert = /etc/lota/p%d.pem\n"
				 "verifier = v.example\n",
				 n, n);
		}
		rc = config_profile_append_text(acc, &p, out, sizeof(out));
		TEST("spaced headers count toward the cap");
		if (rc != -E2BIG)
			FAIL("expected: rc == -E2BIG");

		rc = config_profile_append_text("not a key line\n", &p, out,
						sizeof(out));
		TEST("a text that does not parse is refused");
		if (rc != -EBADMSG)
			FAIL("expected: rc == -EBADMSG");

		/* the shipped example: its commented sections are not
		 * profiles */
		{
			FILE *f = fopen("configs/lota.conf.example", "re");
			size_t len = 0;

			TEST("the example configuration is read");
			if (f == NULL)
				FAIL("expected: f != NULL");
			if (f) {
				len = fread(acc, 1, sizeof(acc) - 1, f);
				fclose(f);
			}
			acc[len] = '\0';
			for (n = 0; n < 3; n++) {
				char nm[32];
				char anchor[64];
				struct lota_profile e;

				snprintf(nm, sizeof(nm), "publisher-%c",
					 'a' + n);
				snprintf(anchor, sizeof(anchor),
					 "/etc/lota/own-%d.pem", n);
				e = mkprofile(nm, "ca.example", anchor,
					      "v.example");
				rc = config_profile_append_text(acc, &e, next,
								sizeof(next));
				if (rc != 1)
					break;
				snprintf(acc, sizeof(acc), "%s", next);
			}
			TEST("three publishers are added to the example");
			if (!(n == 3 && loads_back(acc) == 0))
				FAIL("expected: n == 3 && loads_back(acc) == 0");
		}
	}

	{
		/* a verifier host spelled none is the token-only key to the
		 * parser, so the writer refuses it with or without a port */
		static const int ports[] = { 8443, 9000 };
		struct lota_profile n;
		size_t i;

		for (i = 0; i < sizeof(ports) / sizeof(ports[0]); i++) {
			n = mkprofile("studio-n", "ca.studio-n.example",
				      "/etc/lota/studio-n.pem", "none");
			n.verifier_port = ports[i];
			rc = config_profile_append_text("", &n, out,
							sizeof(out));
			TEST("a verifier host named none is refused");
			if (rc != -EILSEQ)
				FAIL("expected: rc == -EILSEQ");
		}
	}

	{
		/* a port after the host is not split off: it would reach the
		 * resolver as part of the name */
		struct lota_profile h;

		h = mkprofile("studio-h", "ca.studio-h.example:9999",
			      "/etc/lota/studio-h.pem", "v.example");
		rc = config_profile_append_text("", &h, out, sizeof(out));
		TEST("a CA host with a port is refused");
		if (rc != -EILSEQ)
			FAIL("expected: rc == -EILSEQ");

		h = mkprofile("studio-h", "ca.studio-h.example",
			      "/etc/lota/studio-h.pem", "v.example:9000");
		rc = config_profile_append_text("", &h, out, sizeof(out));
		TEST("a verifier host with a port is refused");
		if (rc != -EILSEQ)
			FAIL("expected: rc == -EILSEQ");

		h = mkprofile("studio-h", "[fd00::1]:9999",
			      "/etc/lota/studio-h.pem", "fd00::2");
		rc = config_profile_append_text("", &h, out, sizeof(out));
		TEST("a bracketed CA host is refused");
		if (rc != -EILSEQ)
			FAIL("expected: rc == -EILSEQ");

		h = mkprofile("studio-h", "fd00::1", "/etc/lota/studio-h.pem",
			      "[fd00::2]:9000");
		rc = config_profile_append_text("", &h, out, sizeof(out));
		TEST("a bracketed verifier host is refused");
		if (rc != -EILSEQ)
			FAIL("expected: rc == -EILSEQ");

		h = mkprofile("studio-h", "fd00::1", "/etc/lota/studio-h.pem",
			      "fd00::2");
		rc = config_profile_append_text("", &h, out, sizeof(out));
		TEST("IPv6 literals are written");
		if (!(rc == 1 && loads_back(out) == 0))
			FAIL("expected: rc == 1 && loads_back(out) == 0");
	}

	{
		char small[64];

		rc = config_profile_append_text("attest_interval = 60\n", &p,
						small, sizeof(small));
		TEST("a buffer too small is refused rather than truncated");
		if (rc != -EOVERFLOW)
			FAIL("expected: rc == -EOVERFLOW");
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
		TEST("a label carrying a quote and a newline is refused");
		if (rc != -EILSEQ)
			FAIL("expected: rc == -EILSEQ");

		forged = mkprofile("say \"cheese\"", "ca.studio-a.example",
				   "/etc/lota/studio-a.pem",
				   "verifier.studio-a.example");
		rc = config_profile_append_text(base, &forged, out,
						sizeof(out));
		TEST("a label carrying a quote is refused");
		if (rc != -EILSEQ)
			FAIL("expected: rc == -EILSEQ");

		forged = mkprofile("two\nlines", "ca.studio-a.example",
				   "/etc/lota/studio-a.pem",
				   "verifier.studio-a.example");
		rc = config_profile_append_text(base, &forged, out,
						sizeof(out));
		TEST("a label carrying a control character is refused");
		if (rc != -EILSEQ)
			FAIL("expected: rc == -EILSEQ");

		forged = mkprofile("", "ca.studio-a.example",
				   "/etc/lota/studio-a.pem",
				   "verifier.studio-a.example");
		rc = config_profile_append_text(base, &forged, out,
						sizeof(out));
		TEST("a profile with no label is refused");
		if (rc != -EINVAL)
			FAIL("expected: rc == -EINVAL");
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
		TEST("a CA host carrying a newline is refused");
		if (rc != -EILSEQ)
			FAIL("expected: rc == -EILSEQ");

		forged = mkprofile("studio-c", "ca.studio-c.example",
				   "/etc/lota/studio-c.pem",
				   "v.example\nreporting = continuous");
		rc = config_profile_append_text(base, &forged, out,
						sizeof(out));
		TEST("a verifier host carrying a newline is refused");
		if (rc != -EILSEQ)
			FAIL("expected: rc == -EILSEQ");

		forged = mkprofile("studio-c", "ca.studio-c.example",
				   "/etc/lota/c.pem\nmode = permissive",
				   "verifier.studio-c.example");
		rc = config_profile_append_text(base, &forged, out,
						sizeof(out));
		TEST("a trust anchor carrying a newline is refused");
		if (rc != -EILSEQ)
			FAIL("expected: rc == -EILSEQ");

		/* the parser refuses a relative ca_cert, so the writer cannot
		 * emit one either */
		forged = mkprofile("studio-c", "ca.studio-c.example",
				   "studio-c.pem", "verifier.studio-c.example");
		rc = config_profile_append_text(base, &forged, out,
						sizeof(out));
		TEST("a trust anchor that is not an absolute path is refused");
		if (rc != -EILSEQ)
			FAIL("expected: rc == -EILSEQ");
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

		TEST("a temporary configuration file is created");
		if (fd < 0)
			FAIL("expected: fd >= 0");
		if (fd >= 0) {
			char tmp_path[PATH_MAX];

			close(fd);

			/* a section the parser refuses: a profile with no ca */
			TEST("a configuration that does not parse is staged");
			if (write_file(path, "[profile \"half-written\"]\n") !=
			    0)
				FAIL("expected: write_file(path, \"[profile "
				     "\\\"half-written\\\"]\\n\") == 0");
			TEST("the staged configuration does not load");
			if (profiles_in_file(path) >= 0)
				FAIL("expected: profiles_in_file(path) < 0");

			rc = config_profile_append(path, &p);
			TEST("appending to a configuration that does not parse is refused");
			if (rc != -EBADMSG)
				FAIL("expected: rc == -EBADMSG");
			TEST("the refusal left the file as it was");
			if (profiles_in_file(path) >= 0)
				FAIL("expected: profiles_in_file(path) < 0");

			snprintf(tmp_path, sizeof(tmp_path), "%s.new", path);
			TEST("the refused replacement is not left behind");
			if (access(tmp_path, F_OK) == 0)
				FAIL("expected: access(tmp_path, F_OK) != 0");

			/* the ordinary path still writes, and what it wrote is
			 * what the next start reads */
			TEST("a loadable configuration is staged");
			if (write_file(path, "attest_interval = 60\n") != 0)
				FAIL("expected: write_file(path, \"attest_interval = 60\\n\") "
				     "== 0");
			rc = config_profile_append(path, &p);
			TEST("the publisher is appended to the file");
			if (rc != 1)
				FAIL("expected: rc == 1");
			TEST("the file the writer left holds the publisher");
			if (profiles_in_file(path) != 1)
				FAIL("expected: profiles_in_file(path) == 1");

			/* the replacement keeps the live file's mode and owner,
			 * and a stale replacement does not stand in the way */
			{
				struct lota_profile r = mkprofile(
					"studio-r", "ca.studio-r.example",
					"/etc/lota/studio-r.pem",
					"verifier.studio-r.example");
				struct lota_profile t = mkprofile(
					"studio-t", "ca.studio-t.example",
					"/etc/lota/studio-t.pem",
					"verifier.studio-t.example");
				struct stat st;

				TEST("the live file is made 0600");
				if (chmod(path, 0600) != 0)
					FAIL("expected: chmod(path, 0600) == 0");
				rc = config_profile_append(path, &r);
				TEST("the replaced file keeps 0600 and owner");
				if (!(rc == 1 && stat_open(path, &st) == 0 &&
				      (st.st_mode & 07777) == 0600 &&
				      st.st_uid == geteuid()))
					FAIL("expected: rc == 1 && stat_open(path, &st) == 0 && "
					     "(st.st_mode & 07777) == 0600 && st.st_uid == geteuid()");

				TEST("a stale 0664 .new is staged");
				if (!(write_file(tmp_path, "stale\n") == 0 &&
				      chmod(tmp_path, 0664) == 0))
					FAIL("expected: write_file(tmp_path, \"stale\\n\") == 0 && "
					     "chmod(tmp_path, 0664) == 0");
				rc = config_profile_append(path, &t);
				TEST("a stale .new does not block it");
				if (!(rc == 1 && profiles_in_file(path) == 3))
					FAIL("expected: rc == 1 && profiles_in_file(path) == 3");

				unlink(path);
				rc = config_profile_append(path, &r);
				TEST("a file created from nothing is 0644");
				if (!(rc == 1 && stat_open(path, &st) == 0 &&
				      (st.st_mode & 07777) == 0644))
					FAIL("expected: rc == 1 && stat_open(path, &st) == 0 && "
					     "(st.st_mode & 07777) == 0644");
			}

			unlink(path);
			unlink(tmp_path);
		}
	}

	return test_end();
}
