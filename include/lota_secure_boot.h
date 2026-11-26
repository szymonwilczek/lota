/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * UEFI Secure Boot state as the EFI stub hands it to the kernel.
 *
 * SecureBoot set to 1 is not enough: the stub reports Secure Boot off in
 * setup mode, and when shim's MokSBStateRT is 1 without NON_VOLATILE
 * (shim validation disabled), and the kernel then honours ima_appraise=.
 */
#ifndef LOTA_SECURE_BOOT_H
#define LOTA_SECURE_BOOT_H

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#define LOTA_EFIVARS_DIR "/sys/firmware/efi/efivars"
#define LOTA_EFIVAR_SECURE_BOOT \
	"SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
#define LOTA_EFIVAR_SETUP_MODE "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"
#define LOTA_EFIVAR_MOK_SB_STATE \
	"MokSBStateRT-605dab50-e046-4300-abb6-3dd810dd8b23"

enum lota_secure_boot {
	LOTA_SECURE_BOOT_OFF = 0,
	LOTA_SECURE_BOOT_ON = 1,
	LOTA_SECURE_BOOT_SETUP_MODE = 2,
	LOTA_SECURE_BOOT_SHIM_INSECURE = 3,
};

/**
 * lota_secure_boot_judge() - Secure Boot state from three efivarfs reads.
 * @sb:        SecureBoot, 4 bytes of attributes then the value.
 * @sb_len:    bytes read into @sb, or a negative errno.
 * @setup:     SetupMode, same layout.
 * @setup_len: bytes read into @setup, or a negative errno.
 * @mok:       shim's MokSBStateRT, same layout.
 * @mok_len:   bytes read into @mok, or a negative errno.
 *
 * A short or unread SetupMode or MokSBStateRT counts as not set, as in the
 * stub.
 *
 * Return: enum lota_secure_boot, -EIO for a short @sb, or a negative @sb_len.
 */
static inline int lota_secure_boot_judge(const uint8_t *sb, ssize_t sb_len,
					 const uint8_t *setup,
					 ssize_t setup_len, const uint8_t *mok,
					 ssize_t mok_len)
{
	if (sb_len < 0)
		return (int)sb_len;
	if (sb_len < 5)
		return -EIO;
	if (sb[4] != 1)
		return LOTA_SECURE_BOOT_OFF;
	if (setup_len >= 5 && setup[4] == 1)
		return LOTA_SECURE_BOOT_SETUP_MODE;
	if (mok_len >= 5 && !(mok[0] & 0x1) && mok[4] == 1)
		return LOTA_SECURE_BOOT_SHIM_INSECURE;
	return LOTA_SECURE_BOOT_ON;
}

/* the attributes and first value byte of efivar @name in @dir, or -errno */
static inline ssize_t lota_efivar_read(const char *dir, const char *name,
				       uint8_t buf[5])
{
	char path[PATH_MAX];
	ssize_t n;
	int fd;

	if (snprintf(path, sizeof(path), "%s/%s", dir, name) >=
	    (int)sizeof(path))
		return -ENAMETOOLONG;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	n = read(fd, buf, 5);
	if (n < 0)
		n = -errno;
	close(fd);
	return n;
}

/**
 * lota_secure_boot_read() - lota_secure_boot_judge() over efivarfs.
 * @dir: efivarfs mount, LOTA_EFIVARS_DIR on the booted host.
 *
 * Return: as for lota_secure_boot_judge().
 */
static inline int lota_secure_boot_read(const char *dir)
{
	uint8_t sb[5] = { 0 };
	uint8_t setup[5] = { 0 };
	uint8_t mok[5] = { 0 };
	ssize_t sb_len = lota_efivar_read(dir, LOTA_EFIVAR_SECURE_BOOT, sb);
	ssize_t setup_len =
		lota_efivar_read(dir, LOTA_EFIVAR_SETUP_MODE, setup);
	ssize_t mok_len = lota_efivar_read(dir, LOTA_EFIVAR_MOK_SB_STATE, mok);

	return lota_secure_boot_judge(sb, sb_len, setup, setup_len, mok,
				      mok_len);
}

#endif /* LOTA_SECURE_BOOT_H */
