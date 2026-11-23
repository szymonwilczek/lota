/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "machine.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *const bench_selinux_names[BSE_COUNT] = {
	[BSE_DISABLED] = "disabled",
	[BSE_PERMISSIVE] = "permissive",
	[BSE_ENFORCING] = "enforcing",
};

const char *const bench_supply_names[BSU_COUNT] = {
	[BSU_UNKNOWN] = "unknown",
	[BSU_AC] = "ac",
	[BSU_BATTERY] = "battery",
};

/* the first line of a small file, without its newline; -1 when unreadable */
static int read_line(int root, const char *path, char *buf, size_t cap)
{
	ssize_t n;
	int fd;

	fd = openat(root, path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, cap - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	buf[strcspn(buf, "\n")] = '\0';
	return (int)strlen(buf);
}

static FILE *open_stream(int root, const char *path)
{
	FILE *f;
	int fd;

	fd = openat(root, path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	f = fdopen(fd, "r");
	if (!f)
		close(fd);
	return f;
}

static void set_str(struct bench_field *f, const char *s)
{
	bench_field_set(f, s, strlen(s));
}

/* the value after "key<blanks>:" on @line, or NULL */
static const char *colon_value(const char *line, const char *key)
{
	size_t n = strlen(key);

	if (strncmp(line, key, n) != 0)
		return NULL;
	line += n;
	line += strspn(line, " \t");
	if (*line != ':')
		return NULL;
	line++;
	return line + strspn(line, " \t");
}

static void read_cpu(int root, struct bench_machine *m)
{
	char line[512];
	const char *v;
	FILE *f;

	f = open_stream(root, "proc/cpuinfo");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		line[strcspn(line, "\n")] = '\0';
		if (colon_value(line, "processor"))
			m->cpu_threads++;
		else if (!m->cpu_model.set &&
			 (v = colon_value(line, "model name")))
			set_str(&m->cpu_model, v);
	}
	fclose(f);
}

static void read_memory(int root, struct bench_machine *m)
{
	char line[256];
	const char *v;
	FILE *f;

	f = open_stream(root, "proc/meminfo");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		v = colon_value(line, "MemTotal");
		if (v) {
			m->memory_bytes = strtoull(v, NULL, 10) * 1024;
			break;
		}
	}
	fclose(f);
}

/* KEY=value or KEY="value" from os-release, unquoted into @out */
static int os_release_value(const char *line, const char *key, char *out,
			    size_t cap)
{
	size_t n = strlen(key), len;

	if (strncmp(line, key, n) != 0 || line[n] != '=')
		return 0;
	line += n + 1;
	len = strcspn(line, "\n");
	if (len && (line[0] == '"' || line[0] == '\'')) {
		line++;
		len--;
		if (len && (line[len - 1] == '"' || line[len - 1] == '\''))
			len--;
	}
	if (len >= cap)
		len = cap - 1;
	memcpy(out, line, len);
	out[len] = '\0';
	return 1;
}

static void read_distro(int root, struct bench_machine *m)
{
	char line[256], id[80] = "", ver[80] = "", both[176];
	FILE *f;

	f = open_stream(root, "etc/os-release");
	if (!f)
		f = open_stream(root, "usr/lib/os-release");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (!os_release_value(line, "ID", id, sizeof(id)))
			os_release_value(line, "VERSION_ID", ver, sizeof(ver));
	}
	fclose(f);
	snprintf(both, sizeof(both), "%s %s", id, ver);
	set_str(&m->distro, both);
}

/* the last component of the link at @path, into @f */
static int link_name(int root, const char *path, struct bench_field *f)
{
	char target[512];
	const char *base;
	ssize_t n;

	n = readlinkat(root, path, target, sizeof(target) - 1);
	if (n <= 0)
		return -1;
	target[n] = '\0';
	base = strrchr(target, '/');
	set_str(f, base ? base + 1 : target);
	return f->set ? 0 : -1;
}

static void read_tpm(int root, struct bench_machine *m)
{
	char target[512];
	ssize_t n;

	if (link_name(root, "sys/class/tpm/tpm0/device/driver", &m->tpm) == 0)
		return;
	n = readlinkat(root, "sys/class/tpm/tpm0", target, sizeof(target) - 1);
	if (n <= 0) {
		set_str(&m->tpm, "none");
		return;
	}
	target[n] = '\0';
	/* a proxied software TPM has no bus device */
	set_str(&m->tpm, strstr(target, "/virtual/") ? "virtual" : "unknown");
}

static void read_selinux(int root, struct bench_machine *m)
{
	char v[8];

	if (read_line(root, "sys/fs/selinux/enforce", v, sizeof(v)) < 0)
		m->selinux = BSE_DISABLED;
	else
		m->selinux = strcmp(v, "1") == 0 ? BSE_ENFORCING :
						   BSE_PERMISSIVE;
}

static int hex4(const char *s, uint32_t *out)
{
	uint32_t v = 0;

	for (int i = 0; i < 4; i++) {
		char c = s[i];

		v <<= 4;
		if (c >= '0' && c <= '9')
			v |= (uint32_t)(c - '0');
		else if (c >= 'a' && c <= 'f')
			v |= (uint32_t)(c - 'a' + 10);
		else if (c >= 'A' && c <= 'F')
			v |= (uint32_t)(c - 'A' + 10);
		else
			return -1;
	}
	*out = v;
	return 0;
}

/*
 * pci.ids lists each vendor at column 0 and its devices below it after one
 * tab, as "<4 hex>  <name>"; subsystems have two tabs and are skipped
 */
static void pci_name(int root, struct bench_gpu *g)
{
	bool in_vendor = false, whole = true;
	char line[512];
	uint32_t id;
	FILE *f;

	f = open_stream(root, BENCH_PCI_IDS);
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		bool cont = !whole;
		size_t n = strcspn(line, "\n");

		/* the tail of a line longer than @line is not a line */
		whole = line[n] == '\n';
		line[n] = '\0';
		if (cont || line[0] == '#' || line[0] == '\0')
			continue;
		if (line[0] != '\t') {
			if (in_vendor)
				break;
			in_vendor = hex4(line, &id) == 0 && line[4] == ' ' &&
				    id == g->vendor_id;
			continue;
		}
		if (in_vendor && line[1] != '\t' && hex4(line + 1, &id) == 0 &&
		    line[5] == ' ' && id == g->device_id) {
			set_str(&g->name, line + 6);
			break;
		}
	}
	fclose(f);
}

static int read_hex_id(int root, const char *path, uint32_t *out)
{
	char v[16], *end;
	unsigned long n;

	if (read_line(root, path, v, sizeof(v)) <= 0)
		return -1;
	n = strtoul(v, &end, 16);
	if (*end || n > 0xffff)
		return -1;
	*out = (uint32_t)n;
	return 0;
}

static int cmp_uint(const void *a, const void *b)
{
	unsigned int x = *(const unsigned int *)a;
	unsigned int y = *(const unsigned int *)b;

	return x < y ? -1 : x > y;
}

/* the N of every sys/class/drm/cardN, in order; connectors are skipped */
static size_t drm_cards(int root, unsigned int *cards, size_t cap)
{
	struct dirent *de;
	size_t n = 0;
	DIR *d;
	int fd;

	fd = openat(root, "sys/class/drm", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	d = fdopendir(fd);
	if (!d) {
		close(fd);
		return 0;
	}
	while ((de = readdir(d)) && n < cap) {
		const char *p = de->d_name;
		char *end;
		unsigned long v;

		if (strncmp(p, "card", 4) != 0 || p[4] < '0' || p[4] > '9')
			continue;
		v = strtoul(p + 4, &end, 10);
		if (*end || v > 255)
			continue;
		cards[n++] = (unsigned int)v;
	}
	closedir(d);
	qsort(cards, n, sizeof(cards[0]), cmp_uint);
	return n;
}

static void read_gpus(int root, struct bench_machine *m)
{
	unsigned int cards[32];
	size_t n = drm_cards(root, cards, 32);

	for (size_t i = 0; i < n && m->ngpus < BENCH_MAX_GPUS; i++) {
		struct bench_gpu *g = &m->gpu[m->ngpus];
		char path[64];

		memset(g, 0, sizeof(*g));
		snprintf(path, sizeof(path),
			 "sys/class/drm/card%u/device/vendor", cards[i]);
		if (read_hex_id(root, path, &g->vendor_id))
			continue;
		snprintf(path, sizeof(path),
			 "sys/class/drm/card%u/device/device", cards[i]);
		if (read_hex_id(root, path, &g->device_id))
			continue;
		snprintf(path, sizeof(path),
			 "sys/class/drm/card%u/device/driver", cards[i]);
		link_name(root, path, &g->driver);
		pci_name(root, g);
		m->ngpus++;
	}
}

void bench_machine_read(int root, struct bench_machine *m)
{
	char v[128];

	memset(m, 0, sizeof(*m));
	read_cpu(root, m);
	read_memory(root, m);
	read_gpus(root, m);
	if (read_line(root, "proc/sys/kernel/osrelease", v, sizeof(v)) > 0)
		set_str(&m->kernel, v);
	read_distro(root, m);
	read_tpm(root, m);
	read_selinux(root, m);
}

static bool field_eq(const struct bench_field *a, const struct bench_field *b)
{
	return a->set == b->set && strcmp(a->s, b->s) == 0;
}

const char *bench_machine_diff(const struct bench_machine *a,
			       const struct bench_machine *b)
{
	if (!field_eq(&a->cpu_model, &b->cpu_model) ||
	    a->cpu_threads != b->cpu_threads)
		return "CPU";
	if (a->ngpus != b->ngpus)
		return "GPU";
	for (unsigned int i = 0; i < a->ngpus; i++) {
		const struct bench_gpu *x = &a->gpu[i], *y = &b->gpu[i];

		if (x->vendor_id != y->vendor_id ||
		    x->device_id != y->device_id ||
		    !field_eq(&x->name, &y->name) ||
		    !field_eq(&x->driver, &y->driver))
			return "GPU";
	}
	if (!field_eq(&a->kernel, &b->kernel))
		return "kernel";
	if (!field_eq(&a->distro, &b->distro))
		return "distribution";
	if (!field_eq(&a->tpm, &b->tpm))
		return "TPM";
	if (a->selinux != b->selinux)
		return "SELinux mode";
	return NULL;
}

static enum bench_supply read_supply(int root)
{
	enum bench_supply s = BSU_UNKNOWN;
	struct dirent *de;
	DIR *d;
	int fd;

	fd = openat(root, "sys/class/power_supply",
		    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return BSU_UNKNOWN;
	d = fdopendir(fd);
	if (!d) {
		close(fd);
		return BSU_UNKNOWN;
	}
	while ((de = readdir(d))) {
		char path[320], type[32], v[32];

		if (de->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "sys/class/power_supply/%s/type",
			 de->d_name);
		if (read_line(root, path, type, sizeof(type)) <= 0)
			continue;
		if (strcmp(type, "Battery") == 0) {
			snprintf(path, sizeof(path),
				 "sys/class/power_supply/%s/status",
				 de->d_name);
			if (read_line(root, path, v, sizeof(v)) <= 0)
				continue;
			if (strcmp(v, "Discharging") == 0) {
				s = BSU_BATTERY;
				break;
			}
			s = BSU_AC;
		} else if (strcmp(type, "Mains") == 0) {
			snprintf(path, sizeof(path),
				 "sys/class/power_supply/%s/online",
				 de->d_name);
			if (read_line(root, path, v, sizeof(v)) > 0 &&
			    strcmp(v, "1") == 0)
				s = BSU_AC;
		}
	}
	closedir(d);
	return s;
}

void bench_power_read(int root, struct bench_power *p)
{
	char v[128];

	memset(p, 0, sizeof(*p));
	if (read_line(root,
		      "sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", v,
		      sizeof(v)) > 0)
		set_str(&p->governor, v);
	if (read_line(root, "sys/firmware/acpi/platform_profile", v,
		      sizeof(v)) > 0)
		set_str(&p->profile, v);
	p->supply = read_supply(root);
}
