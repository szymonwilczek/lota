/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - D-Bus Interface
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "dbus.h"

#ifndef LOTA_BUILD_VERSION_STRING
#error "LOTA_BUILD_VERSION_STRING must be defined at build time"
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <systemd/sd-bus.h>
#include <unistd.h>
#include <systemd/sd-bus-protocol.h>
#include <systemd/sd-bus-vtable.h>
#include <time.h>

#include "../../include/lota.h"
#include "../../include/lota_ipc.h"
#include "ipc.h"
#include "journal.h"

struct dbus_context {
	sd_bus *bus;
	sd_bus_slot *slot;
	struct ipc_context *ipc;
};

static const char *mode_string(uint8_t mode)
{
	switch (mode) {
	case LOTA_MODE_MONITOR:
		return "monitor";
	case LOTA_MODE_ENFORCE:
		return "enforce";
	default:
		return "unknown";
	}
}

uint32_t dbus_status_word(const struct ipc_context *ipc)
{
	if (!ipc)
		return 0;

	/* a bus connection names no publisher: the host-wide word */
	return ipc_host_status_flags(ipc);
}

static int prop_get_status_flags(sd_bus *bus, const char *path,
				 const char *interface, const char *property,
				 sd_bus_message *reply, void *userdata,
				 sd_bus_error *error)
{
	struct dbus_context *ctx = userdata;
	(void)bus;
	(void)path;
	(void)interface;
	(void)property;
	(void)error;
	return sd_bus_message_append(reply, "u", dbus_status_word(ctx->ipc));
}

static int prop_get_mode(sd_bus *bus, const char *path, const char *interface,
			 const char *property, sd_bus_message *reply,
			 void *userdata, sd_bus_error *error)
{
	struct dbus_context *ctx = userdata;
	(void)bus;
	(void)path;
	(void)interface;
	(void)property;
	(void)error;
	return sd_bus_message_append(reply, "s", mode_string(ctx->ipc->mode));
}

static int prop_get_attest_count(sd_bus *bus, const char *path,
				 const char *interface, const char *property,
				 sd_bus_message *reply, void *userdata,
				 sd_bus_error *error)
{
	struct dbus_context *ctx = userdata;
	(void)bus;
	(void)path;
	(void)interface;
	(void)property;
	(void)error;
	return sd_bus_message_append(reply, "u", ctx->ipc->attest_count);
}

static int prop_get_fail_count(sd_bus *bus, const char *path,
			       const char *interface, const char *property,
			       sd_bus_message *reply, void *userdata,
			       sd_bus_error *error)
{
	struct dbus_context *ctx = userdata;
	(void)bus;
	(void)path;
	(void)interface;
	(void)property;
	(void)error;
	return sd_bus_message_append(reply, "u", ctx->ipc->fail_count);
}

static int prop_get_last_attest_time(sd_bus *bus, const char *path,
				     const char *interface,
				     const char *property,
				     sd_bus_message *reply, void *userdata,
				     sd_bus_error *error)
{
	struct dbus_context *ctx = userdata;
	(void)bus;
	(void)path;
	(void)interface;
	(void)property;
	(void)error;
	return sd_bus_message_append(reply, "t", ctx->ipc->last_attest_time);
}

static int prop_get_valid_until(sd_bus *bus, const char *path,
				const char *interface, const char *property,
				sd_bus_message *reply, void *userdata,
				sd_bus_error *error)
{
	struct dbus_context *ctx = userdata;
	(void)bus;
	(void)path;
	(void)interface;
	(void)property;
	(void)error;
	return sd_bus_message_append(reply, "t", ctx->ipc->valid_until);
}

const char *dbus_version_string(void)
{
	return LOTA_BUILD_VERSION_STRING;
}

static int prop_get_version(sd_bus *bus, const char *path,
			    const char *interface, const char *property,
			    sd_bus_message *reply, void *userdata,
			    sd_bus_error *error)
{
	(void)bus;
	(void)path;
	(void)interface;
	(void)property;
	(void)userdata;
	(void)error;
	return sd_bus_message_append(reply, "s", dbus_version_string());
}

static int method_ping(sd_bus_message *msg, void *userdata, sd_bus_error *error)
{
	struct dbus_context *ctx = userdata;
	struct timespec ts;
	uint64_t now_sec = 0;
	uint64_t uptime;
	(void)error;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
		now_sec = (uint64_t)ts.tv_sec;

	uptime = (now_sec >= ctx->ipc->start_time_sec) ?
			 (now_sec - ctx->ipc->start_time_sec) :
			 0;
	return sd_bus_reply_method_return(msg, "tu", uptime,
					  (uint32_t)getpid());
}

static int method_get_status(sd_bus_message *msg, void *userdata,
			     sd_bus_error *error)
{
	struct dbus_context *ctx = userdata;
	(void)error;

	return sd_bus_reply_method_return(
		msg, "usttuu", dbus_status_word(ctx->ipc),
		mode_string(ctx->ipc->mode), ctx->ipc->last_attest_time,
		ctx->ipc->valid_until, ctx->ipc->attest_count,
		ctx->ipc->fail_count);
}

/* the flags only; a signed token comes over the Unix socket */
static int method_get_token(sd_bus_message *msg, void *userdata,
			    sd_bus_error *error)
{
	struct dbus_context *ctx = userdata;

	if (!(ctx->ipc->status_flags & LOTA_STATUS_ATTESTED)) {
		return sd_bus_reply_method_errorf(msg,
						  LOTA_DBUS_INTERFACE
						  ".NotAttested",
						  "System is not attested");
	}

	(void)error;
	return sd_bus_reply_method_return(msg, "u", dbus_status_word(ctx->ipc));
}

static const sd_bus_vtable agent_vtable[] = {
	SD_BUS_VTABLE_START(0),

	SD_BUS_PROPERTY("StatusFlags", "u", prop_get_status_flags, 0,
			SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_PROPERTY("Mode", "s", prop_get_mode, 0,
			SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_PROPERTY("AttestCount", "u", prop_get_attest_count, 0,
			SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_PROPERTY("FailCount", "u", prop_get_fail_count, 0,
			SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_PROPERTY("LastAttestTime", "t", prop_get_last_attest_time, 0,
			SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_PROPERTY("ValidUntil", "t", prop_get_valid_until, 0,
			SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_PROPERTY("Version", "s", prop_get_version, 0,
			SD_BUS_VTABLE_PROPERTY_CONST),

	SD_BUS_METHOD("Ping", "", "tu", method_ping,
		      SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("GetStatus", "", "usttuu", method_get_status,
		      SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("GetToken", "", "u", method_get_token, 0),

	SD_BUS_SIGNAL("StatusChanged", "u", 0),
	SD_BUS_SIGNAL("AttestationResult", "b", 0),
	SD_BUS_SIGNAL("ModeChanged", "s", 0),

	SD_BUS_VTABLE_END
};

struct dbus_context *dbus_init(struct ipc_context *ipc)
{
	struct dbus_context *ctx;
	int ret;

	if (!ipc)
		return NULL;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->ipc = ipc;

	ret = sd_bus_open_system(&ctx->bus);
	if (ret < 0) {
		lota_err("D-Bus: failed to open system bus: %s",
			 strerror(-ret));
		free(ctx);
		return NULL;
	}

	ret = sd_bus_add_object_vtable(ctx->bus, &ctx->slot,
				       LOTA_DBUS_OBJECT_PATH,
				       LOTA_DBUS_INTERFACE, agent_vtable, ctx);
	if (ret < 0) {
		lota_err("D-Bus: failed to register vtable: %s",
			 strerror(-ret));
		sd_bus_unref(ctx->bus);
		free(ctx);
		return NULL;
	}

	ret = sd_bus_request_name(ctx->bus, LOTA_DBUS_BUS_NAME,
				  SD_BUS_NAME_REPLACE_EXISTING);
	if (ret < 0) {
		lota_err("D-Bus: failed to claim %s: %s", LOTA_DBUS_BUS_NAME,
			 strerror(-ret));
		sd_bus_slot_unref(ctx->slot);
		sd_bus_unref(ctx->bus);
		free(ctx);
		return NULL;
	}

	lota_info("D-Bus: registered %s on system bus", LOTA_DBUS_BUS_NAME);
	return ctx;
}

int dbus_get_fd(struct dbus_context *ctx)
{
	if (!ctx || !ctx->bus)
		return -1;
	return sd_bus_get_fd(ctx->bus);
}

int dbus_process(struct dbus_context *ctx, uint64_t timeout_us)
{
	int ret;

	if (!ctx || !ctx->bus)
		return -EINVAL;

	for (;;) {
		ret = sd_bus_process(ctx->bus, NULL);
		if (ret < 0) {
			lota_err("D-Bus: process error: %s", strerror(-ret));
			return ret;
		}
		if (ret == 0)
			break;
	}

	if (timeout_us > 0) {
		ret = sd_bus_wait(ctx->bus, timeout_us);
		if (ret < 0 && ret != -EINTR)
			return ret;
	}

	return 0;
}

/*
 * An emit writes what the socket takes without blocking and queues the rest;
 * without a flush the rest waits for the next message the bus sends in.
 */
static void emit_flush(struct dbus_context *ctx, const char *what, int ret)
{
	if (ret < 0) {
		lota_warn("D-Bus: %s not emitted: %s", what, strerror(-ret));
		return;
	}

	ret = sd_bus_flush(ctx->bus);
	if (ret < 0)
		lota_warn("D-Bus: %s emitted but not flushed: %s", what,
			  strerror(-ret));
}

void dbus_emit_status_changed(struct dbus_context *ctx)
{
	if (!ctx || !ctx->bus)
		return;

	emit_flush(ctx, "StatusChanged",
		   sd_bus_emit_signal(ctx->bus, LOTA_DBUS_OBJECT_PATH,
				      LOTA_DBUS_INTERFACE, "StatusChanged", "u",
				      dbus_status_word(ctx->ipc)));

	emit_flush(ctx, "StatusFlags properties",
		   sd_bus_emit_properties_changed(
			   ctx->bus, LOTA_DBUS_OBJECT_PATH, LOTA_DBUS_INTERFACE,
			   "StatusFlags", "LastAttestTime", "ValidUntil",
			   "AttestCount", "FailCount", NULL));
}

/* LastAttestTime and ValidUntil move here even on a steady status word */
void dbus_emit_attestation_result(struct dbus_context *ctx, bool success)
{
	if (!ctx || !ctx->bus)
		return;

	emit_flush(ctx, "AttestationResult",
		   sd_bus_emit_signal(ctx->bus, LOTA_DBUS_OBJECT_PATH,
				      LOTA_DBUS_INTERFACE, "AttestationResult",
				      "b", (int)success));

	emit_flush(ctx, "AttestCount properties",
		   sd_bus_emit_properties_changed(
			   ctx->bus, LOTA_DBUS_OBJECT_PATH, LOTA_DBUS_INTERFACE,
			   "AttestCount", "FailCount", "LastAttestTime",
			   "ValidUntil", NULL));
}

void dbus_emit_mode_changed(struct dbus_context *ctx, uint8_t mode)
{
	if (!ctx || !ctx->bus)
		return;

	emit_flush(ctx, "ModeChanged",
		   sd_bus_emit_signal(ctx->bus, LOTA_DBUS_OBJECT_PATH,
				      LOTA_DBUS_INTERFACE, "ModeChanged", "s",
				      mode_string(mode)));

	emit_flush(ctx, "Mode property",
		   sd_bus_emit_properties_changed(
			   ctx->bus, LOTA_DBUS_OBJECT_PATH, LOTA_DBUS_INTERFACE,
			   "Mode", NULL));
}

void dbus_cleanup(struct dbus_context *ctx)
{
	if (!ctx)
		return;

	if (ctx->bus) {
		sd_bus_release_name(ctx->bus, LOTA_DBUS_BUS_NAME);
		sd_bus_slot_unref(ctx->slot);
		sd_bus_flush_close_unref(ctx->bus);
	}

	free(ctx);
	lota_info("D-Bus: cleaned up");
}
