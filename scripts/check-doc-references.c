/* SPDX-License-Identifier: MIT */
/*
 * Check that comments and pages name things that exist.
 *
 * Run from the top of the tree.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <ctype.h>
#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int failed;

#define FAIL(msg)                                                   \
	do {                                                        \
		fprintf(stderr, "check-doc-references: %s\n", msg); \
		failed = 1;                                         \
	} while (0)

static void rstrip(char *line)
{
	size_t n = strlen(line);

	while (n && isspace((unsigned char)line[n - 1]))
		line[--n] = '\0';
}

/*
 * The monitoring API reads one credential header, Authorization: Bearer
 * (src/verifier/server/api.go::extractBearerToken), so a page that hands
 * a reader an API key in any other header hands them a request that authenticates
 * nothing. On an instance with no key configured the reader endpoints are public,
 * so the wrong header still answers 200 and hides that it was never read;
 * the moment a key is configured every copy of it is a 401.
 */
static bool has_suffix(const char *name, const char *suffix)
{
	size_t n = strlen(name);
	size_t s = strlen(suffix);

	return n >= s && strcmp(name + n - s, suffix) == 0;
}

#define SYMBOL_MAX 80
#define SYMBOLS_MAX 4096

/* LOTA_ tokens in code (string literals included, for getenv()) and comments */
static char code_symbols[SYMBOLS_MAX][SYMBOL_MAX];
static size_t code_symbol_count;
static char comment_symbols[SYMBOLS_MAX][SYMBOL_MAX];
static char comment_sources[SYMBOLS_MAX][160];
static size_t comment_symbol_count;

static bool symbol_seen(const char table[][SYMBOL_MAX], size_t count,
			const char *name)
{
	size_t i;

	for (i = 0; i < count; i++)
		if (strcmp(table[i], name) == 0)
			return true;
	return false;
}

/* A trailing underscore names a family (LOTA_ERR_), not a symbol */
static bool symbol_is_a_name(const char *tok)
{
	size_t len = strlen(tok);

	return len > 5 && tok[len - 1] != '_';
}

static void remember_symbol(char table[][SYMBOL_MAX], size_t *count,
			    const char *tok)
{
	if (*count >= SYMBOLS_MAX || symbol_seen(table, *count, tok))
		return;
	snprintf(table[*count], SYMBOL_MAX, "%s", tok);
	(*count)++;
}

static void remember_mention(const char *tok, const char *path)
{
	if (symbol_seen(comment_symbols, comment_symbol_count, tok))
		return;
	if (comment_symbol_count >= SYMBOLS_MAX)
		return;
	snprintf(comment_sources[comment_symbol_count],
		 sizeof(comment_sources[0]), "%s", path);
	remember_symbol(comment_symbols, &comment_symbol_count, tok);
}

static void keep_symbol(const char *tok, bool in_comment, const char *path)
{
	if (strncmp(tok, "LOTA_", 5) != 0 || !symbol_is_a_name(tok))
		return;
	if (in_comment)
		remember_mention(tok, path);
	else
		remember_symbol(code_symbols, &code_symbol_count, tok);
}

/* Collect LOTA_ tokens from code and from comments; literals count as code */
static void scan_source(const char *path)
{
	enum {
		CODE,
		BLOCK,
		LINE,
		STRING,
		CHARLIT
	} state = CODE;
	FILE *fp = fopen(path, "re");
	char tok[SYMBOL_MAX];
	size_t tok_len = 0;
	bool tok_in_comment = false;
	int c;

	if (!fp)
		return;

	while ((c = fgetc(fp)) != EOF) {
		bool in_comment = (state == BLOCK || state == LINE);

		if (isalnum(c) || c == '_') {
			if (tok_len == 0)
				tok_in_comment = in_comment;
			if (tok_len < sizeof(tok) - 1)
				tok[tok_len++] = (char)c;
			continue;
		}
		if (tok_len) {
			tok[tok_len] = '\0';
			keep_symbol(tok, tok_in_comment, path);
			tok_len = 0;
		}

		switch (state) {
		case CODE:
			if (c == '/') {
				int next = fgetc(fp);

				if (next == '*')
					state = BLOCK;
				else if (next == '/')
					state = LINE;
				else if (next != EOF)
					ungetc(next, fp);
			} else if (c == '"') {
				state = STRING;
			} else if (c == '\'') {
				state = CHARLIT;
			}
			break;
		case BLOCK:
			if (c == '*') {
				int next = fgetc(fp);

				if (next == '/')
					state = CODE;
				else if (next != EOF)
					ungetc(next, fp);
			}
			break;
		case LINE:
			if (c == '\n')
				state = CODE;
			break;
		case STRING:
		case CHARLIT:
			if (c == '\\')
				(void)fgetc(fp);
			else if ((state == STRING && c == '"') ||
				 (state == CHARLIT && c == '\''))
				state = CODE;
			break;
		}
	}
	if (tok_len) {
		tok[tok_len] = '\0';
		keep_symbol(tok, tok_in_comment, path);
	}
	fclose(fp);
}

static void sources_under(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *ent;

	if (!d)
		return;

	while ((ent = readdir(d)) != NULL) {
		char path[512];

		if (ent->d_name[0] == '.')
			continue;

		snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
		if (ent->d_type == DT_DIR) {
			sources_under(path);
			continue;
		}
		if (has_suffix(ent->d_name, ".c") ||
		    has_suffix(ent->d_name, ".h"))
			scan_source(path);
	}
	closedir(d);
}

/*
 * A comment naming a symbol the tree lacks fails silently: the reader sets
 * it and nothing changes. Renames cause it, so every comment is checked.
 */
static void check_comment_symbols(void)
{
	static const char *const roots[] = { "src", "include", "tests",
					     "examples" };
	size_t i;

	for (i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
		sources_under(roots[i]);

	if (!code_symbol_count || !comment_symbol_count) {
		FAIL("no sources were read");
		return;
	}

	for (i = 0; i < comment_symbol_count; i++) {
		char msg[512];

		if (symbol_seen(code_symbols, code_symbol_count,
				comment_symbols[i]))
			continue;

		snprintf(msg, sizeof(msg),
			 "%.160s names %.80s, which the tree does not define",
			 comment_sources[i], comment_symbols[i]);
		FAIL(msg);
		return;
	}
}

#define PAGE_SYMBOLS_MAX 1024

/* LOTA_ tokens the pages name, and those the tree spells outside its prose */
static char tree_symbols[SYMBOLS_MAX][SYMBOL_MAX];
static size_t tree_symbol_count;
static char page_symbols[PAGE_SYMBOLS_MAX][SYMBOL_MAX];
static char page_sources[PAGE_SYMBOLS_MAX][160];
static size_t page_symbol_count;

static void remember_page_mention(const char *tok, const char *path)
{
	if (symbol_seen(page_symbols, page_symbol_count, tok))
		return;
	if (page_symbol_count >= PAGE_SYMBOLS_MAX)
		return;
	snprintf(page_sources[page_symbol_count], sizeof(page_sources[0]), "%s",
		 path);
	snprintf(page_symbols[page_symbol_count], SYMBOL_MAX, "%s", tok);
	page_symbol_count++;
}

static void keep_tree_symbol(const char *tok, bool on_a_page, const char *path)
{
	if (strncmp(tok, "LOTA_", 5) != 0 || !symbol_is_a_name(tok))
		return;
	if (on_a_page)
		remember_page_mention(tok, path);
	else
		remember_symbol(tree_symbols, &tree_symbol_count, tok);
}

/* Pages and build files are flat text: every LOTA_ token counts */
static void scan_flat(const char *path, bool on_a_page)
{
	FILE *fp = fopen(path, "re");
	char tok[SYMBOL_MAX];
	size_t tok_len = 0;
	int c;

	if (!fp)
		return;

	while ((c = fgetc(fp)) != EOF) {
		if (isalnum(c) || c == '_') {
			if (tok_len < sizeof(tok) - 1)
				tok[tok_len++] = (char)c;
			continue;
		}
		if (tok_len) {
			tok[tok_len] = '\0';
			keep_tree_symbol(tok, on_a_page, path);
			tok_len = 0;
		}
	}
	if (tok_len) {
		tok[tok_len] = '\0';
		keep_tree_symbol(tok, on_a_page, path);
	}
	fclose(fp);
}

/* generated output and unshipped notes */
static bool walk_skips(const char *name)
{
	return strcmp(name, "build") == 0 || strcmp(name, "docs") == 0;
}

static void texts_under(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *ent;

	if (!d)
		return;

	while ((ent = readdir(d)) != NULL) {
		char path[512];
		bool on_a_page;

		if (ent->d_name[0] == '.' || walk_skips(ent->d_name))
			continue;

		if (dir[0] == '.' && dir[1] == '\0')
			snprintf(path, sizeof(path), "%s", ent->d_name);
		else
			snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);

		if (ent->d_type == DT_DIR) {
			texts_under(path);
			continue;
		}
		on_a_page = has_suffix(ent->d_name, ".rst") ||
			    has_suffix(ent->d_name, ".md");
		scan_flat(path, on_a_page);
	}
	closedir(d);
}

/* A page naming a symbol the tree lacks sends its reader after nothing */
static void check_page_symbols(void)
{
	size_t i;

	texts_under(".");

	if (!tree_symbol_count || !page_symbol_count) {
		FAIL("no pages were read");
		return;
	}

	for (i = 0; i < page_symbol_count; i++) {
		char msg[512];

		if (symbol_seen(tree_symbols, tree_symbol_count,
				page_symbols[i]))
			continue;

		snprintf(msg, sizeof(msg),
			 "%.160s names %.80s, which the tree does not define",
			 page_sources[i], page_symbols[i]);
		FAIL(msg);
		return;
	}
}

#define PACKAGES_MAX 16
#define PACKAGE_NAME_MAX 64
#define PACKAGE_BINS_MAX 8
#define PACKAGE_DEPS_MAX 8

struct package {
	char name[PACKAGE_NAME_MAX];
	char bins[PACKAGE_BINS_MAX][PACKAGE_NAME_MAX];
	size_t bin_count;
	char deps[PACKAGE_DEPS_MAX][PACKAGE_NAME_MAX];
	size_t dep_count;
};

static struct package packages[PACKAGES_MAX];
static size_t package_count;
static char install_offender[512];

/* yaml scalar or list item up to the first space */
static void first_word(const char *src, char *dst, size_t dst_size)
{
	size_t i;

	for (i = 0; i < dst_size - 1 && src[i] && src[i] != ' '; i++)
		dst[i] = src[i];
	dst[i] = '\0';
}

/* One nfpm manifest: name, /usr/bin commands, lota- dependencies */
static void read_manifest(const char *dir, const char *file)
{
	char path[512];
	char line[1024];
	struct package *pkg;
	FILE *fp;
	bool in_depends = false;

	if (package_count == PACKAGES_MAX)
		return;
	snprintf(path, sizeof(path), "%s/packaging/nfpm/%s", dir, file);
	fp = fopen(path, "re");
	if (!fp)
		return;

	pkg = &packages[package_count++];
	memset(pkg, 0, sizeof(*pkg));

	while (fgets(line, sizeof(line), fp)) {
		const char *p = line;
		const char *dst;

		rstrip(line);
		if (strncmp(line, "name: ", 6) == 0) {
			first_word(line + 6, pkg->name, sizeof(pkg->name));
			continue;
		}

		while (*p == ' ' || *p == '\t')
			p++;
		if (strcmp(p, "depends:") == 0) {
			in_depends = true;
			continue;
		}
		if (in_depends) {
			/* comments and blank lines do not end the list */
			if (*p == '#' || *p == '\0')
				continue;
			if (*p != '-') {
				in_depends = false;
			} else {
				p++;
				while (*p == ' ')
					p++;
				if (strncmp(p, "lota-", 5) == 0 &&
				    pkg->dep_count < PACKAGE_DEPS_MAX)
					first_word(p,
						   pkg->deps[pkg->dep_count++],
						   PACKAGE_NAME_MAX);
				continue;
			}
		}

		dst = strstr(line, "dst: /usr/bin/");
		if (dst && pkg->bin_count < PACKAGE_BINS_MAX)
			first_word(dst + strlen("dst: /usr/bin/"),
				   pkg->bins[pkg->bin_count++],
				   PACKAGE_NAME_MAX);
	}
	fclose(fp);
}

static struct package *package_named(const char *name)
{
	size_t i;

	for (i = 0; i < package_count; i++)
		if (strcmp(packages[i].name, name) == 0)
			return &packages[i];
	return NULL;
}

static bool package_ships(const struct package *pkg, const char *cmd)
{
	size_t i;

	for (i = 0; i < pkg->bin_count; i++)
		if (strcmp(pkg->bins[i], cmd) == 0)
			return true;
	return false;
}

/* Does any package this tree builds ship `cmd`? */
static bool tree_ships_command(const char *cmd)
{
	size_t i;

	for (i = 0; i < package_count; i++)
		if (package_ships(&packages[i], cmd))
			return true;
	return false;
}

/* An install brings the dependency closure; depth bounded by package count */
static bool install_reaches(const char *name, const char *cmd, size_t depth)
{
	const struct package *pkg = package_named(name);
	size_t i;

	if (!pkg || depth > package_count)
		return false;
	if (package_ships(pkg, cmd))
		return true;
	for (i = 0; i < pkg->dep_count; i++)
		if (install_reaches(pkg->deps[i], cmd, depth + 1))
			return true;
	return false;
}

/* Program an indented line runs, past sudo and VAR=value; else prose */
static bool command_word(const char *line, char *out, size_t out_size)
{
	const char *p = line;
	size_t n = 0;

	if (*p != ' ' && *p != '\t')
		return false;
	while (*p == ' ' || *p == '\t')
		p++;

	while (*p) {
		const char *sp = strchr(p, ' ');

		if (strncmp(p, "sudo ", 5) == 0)
			p += 5;
		else if (sp && memchr(p, '=', (size_t)(sp - p)))
			p = sp + 1;
		else
			break;
		while (*p == ' ')
			p++;
	}

	while ((islower((unsigned char)*p) || isdigit((unsigned char)*p) ||
		*p == '-') &&
	       n < out_size - 1)
		out[n++] = *p++;
	out[n] = '\0';
	return n > 0;
}

/* False at the first command the page runs that its installs do not ship */
static bool page_commands_are_installed(const char *path)
{
	char installs[4][PACKAGE_NAME_MAX];
	size_t install_count = 0;
	char line[1024];
	FILE *fp = fopen(path, "re");

	if (!fp)
		return true;

	while (fgets(line, sizeof(line), fp)) {
		char cmd[PACKAGE_NAME_MAX];
		size_t i;

		rstrip(line);

		if (strstr(line, "dnf install")) {
			const char *p = strstr(line, "lota-");

			if (p && install_count < 4)
				first_word(p, installs[install_count++],
					   PACKAGE_NAME_MAX);
			continue;
		}

		/* nothing to hold the page to until it has named a package */
		if (!install_count)
			continue;
		if (!command_word(line, cmd, sizeof(cmd)))
			continue;
		if (strncmp(cmd, "lota-", 5) != 0 || !tree_ships_command(cmd))
			continue;

		for (i = 0; i < install_count; i++)
			if (install_reaches(installs[i], cmd, 0))
				break;
		if (i == install_count) {
			snprintf(
				install_offender, sizeof(install_offender),
				"%.200s runs %.60s, which %.60s does not install",
				path, cmd, installs[0]);
			fclose(fp);
			return false;
		}
	}
	fclose(fp);
	return true;
}

static bool commands_under(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *ent;
	bool ok = true;

	if (!d)
		return true;

	while (ok && (ent = readdir(d)) != NULL) {
		char path[512];

		if (ent->d_name[0] == '.' || strcmp(ent->d_name, "_build") == 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
		if (ent->d_type == DT_DIR) {
			ok = commands_under(path);
			continue;
		}
		if (has_suffix(ent->d_name, ".rst") ||
		    has_suffix(ent->d_name, ".md"))
			ok = page_commands_are_installed(path);
	}
	closedir(d);
	return ok;
}

/* Every command a page runs comes with the packages the same page installs */
static void check_page_commands(void)
{
	static const char *const manifests[] = {
		"lota-agent.yaml",     "lota-sdk.yaml",
		"lota-sdk-devel.yaml", "lota-verifier.yaml",
		"lota-attest-ca.yaml",
	};
	static const char *const roots[] = { "Documentation", "examples" };
	size_t i;

	package_count = 0;
	for (i = 0; i < sizeof(manifests) / sizeof(manifests[0]); i++)
		read_manifest(".", manifests[i]);

	if (package_count != sizeof(manifests) / sizeof(manifests[0])) {
		FAIL("no package manifests were read");
		return;
	}

	for (i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
		if (!commands_under(roots[i])) {
			FAIL(install_offender);
			return;
		}
	}
}

int main(void)
{
	check_comment_symbols();
	check_page_symbols();
	check_page_commands();

	if (failed)
		return 1;

	printf("check-doc-references: clean\n");
	return 0;
}
