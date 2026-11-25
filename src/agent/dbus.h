/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - D-Bus Interface
 *
 * org.lota.Agent1 on the system bus: the daemon's state read-only, beside
 * the Unix socket.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_DBUS_H
#define LOTA_AGENT_DBUS_H

#include <stdbool.h>
#include <stdint.h>

struct ipc_context;

#define LOTA_DBUS_BUS_NAME "org.lota.Agent1"
#define LOTA_DBUS_OBJECT_PATH "/org/lota/Agent1"
#define LOTA_DBUS_INTERFACE "org.lota.Agent1"

struct dbus_context;

/**
 * dbus_init() - Register the object and claim the bus name.
 * @ipc: Context whose state the bus exposes.
 *
 * Return: the context, or NULL; a bus failure is also logged.
 */
struct dbus_context *dbus_init(struct ipc_context *ipc);

/**
 * dbus_get_fd() - The bus connection fd, for epoll.
 * @ctx: Context, or NULL.
 *
 * Return: the fd, -1 for a NULL @ctx, or a negative errno.
 */
int dbus_get_fd(struct dbus_context *ctx);

/**
 * dbus_process() - Handle every pending bus message.
 * @ctx: Context.
 * @timeout_us: Then wait up to this long for more; 0 does not wait.
 *
 * Return: 0, or a negative errno; an interrupted wait is 0.
 */
int dbus_process(struct dbus_context *ctx, uint64_t timeout_us);

/**
 * dbus_emit_status_changed() - Emit StatusChanged and the status properties.
 * @ctx: Context, or NULL.
 * @flags: The signal's argument.
 */
void dbus_emit_status_changed(struct dbus_context *ctx, uint32_t flags);

/**
 * dbus_emit_attestation_result() - Emit AttestationResult and the round's
 * properties.
 * @ctx: Context, or NULL.
 * @success: The round passed.
 */
void dbus_emit_attestation_result(struct dbus_context *ctx, bool success);

/**
 * dbus_emit_mode_changed() - Emit ModeChanged and the Mode property.
 * @ctx: Context, or NULL.
 * @mode: lota_mode value.
 */
void dbus_emit_mode_changed(struct dbus_context *ctx, uint8_t mode);

/**
 * dbus_status_word() - The status word GetStatus() and StatusFlags answer.
 * @ipc: Context, or NULL for 0.
 *
 * Return: ipc_host_status_flags().
 */
uint32_t dbus_status_word(const struct ipc_context *ipc);

/**
 * dbus_version_string() - What the Version property answers.
 *
 * Return: LOTA_BUILD_VERSION_STRING.
 */
const char *dbus_version_string(void);

/**
 * dbus_cleanup() - Release the bus name and free the context.
 * @ctx: Context, or NULL.
 */
void dbus_cleanup(struct dbus_context *ctx);

#endif /* LOTA_AGENT_DBUS_H */
