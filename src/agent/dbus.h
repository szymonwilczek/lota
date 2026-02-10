/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - D-Bus Interface
 *
 * Exposes org.lota.Agent1 on the system bus as an alternative
 * to the Unix socket IPC protocol. Desktop environments and
 * non-game tooling can use D-Bus instead of the binary socket protocol.
 *
 * Bus name:   org.lota.Agent1
 * Object:     /org/lota/Agent1
 * Interface:  org.lota.Agent1
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

/*
 * dbus_init - Claim bus name and register object on system bus.
 * @ipc: IPC context whose state is exposed read-only via D-Bus.
 *
 * Returns: Allocated context on success, NULL on failure.
 *          Error details are printed to stderr.
 */
struct dbus_context *dbus_init(struct ipc_context *ipc);

/*
 * dbus_get_fd - Return the bus connection fd for external poll.
 *
 * Returns: fd >= 0, or -1 if context is NULL / not connected.
 */
int dbus_get_fd(struct dbus_context *ctx);

/*
 * dbus_process - Drive the sd-bus event loop.
 * @ctx: D-Bus context.
 * @timeout_us: Max time to wait in microseconds (0 = non-blocking).
 *
 * Returns: 0 on success, negative errno on fatal error.
 */
int dbus_process(struct dbus_context *ctx, uint64_t timeout_us);

/*
 * dbus_emit_status_changed - Emit StatusChanged signal.
 * @ctx:   D-Bus context.
 * @flags: New LOTA_STATUS_* bitmask.
 */
void dbus_emit_status_changed(struct dbus_context *ctx, uint32_t flags);

/*
 * dbus_emit_attestation_result - Emit AttestationResult signal.
 * @ctx:     D-Bus context.
 * @success: true if attestation passed.
 */
void dbus_emit_attestation_result(struct dbus_context *ctx, bool success);

/*
 * dbus_emit_mode_changed - Emit ModeChanged signal.
 * @ctx:  D-Bus context.
 * @mode: New lota_mode value.
 */
void dbus_emit_mode_changed(struct dbus_context *ctx, uint8_t mode);

/*
 * dbus_cleanup - Release bus name and free context.
 * @ctx: Context from dbus_init (NULL-safe).
 */
void dbus_cleanup(struct dbus_context *ctx);

#endif /* LOTA_AGENT_DBUS_H */
