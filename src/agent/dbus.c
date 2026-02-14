/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - D-Bus Interface
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "dbus.h"
#include "../../include/lota.h"
#include "../../include/lota_ipc.h"
#include "ipc.h"
#include "journal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <systemd/sd-bus.h>
#include <unistd.h>

struct dbus_context {
  sd_bus *bus;
  sd_bus_slot *slot;
  struct ipc_context *ipc;
};

static const char *mode_string(uint8_t mode) {
  switch (mode) {
  case LOTA_MODE_MONITOR:
    return "monitor";
  case LOTA_MODE_ENFORCE:
    return "enforce";
  case LOTA_MODE_MAINTENANCE:
    return "maintenance";
  default:
    return "unknown";
  }
}

static int prop_get_status_flags(sd_bus *bus, const char *path,
                                 const char *interface, const char *property,
                                 sd_bus_message *reply, void *userdata,
                                 sd_bus_error *error) {
  struct dbus_context *ctx = userdata;
  (void)bus;
  (void)path;
  (void)interface;
  (void)property;
  (void)error;
  return sd_bus_message_append(reply, "u", ctx->ipc->status_flags);
}

static int prop_get_mode(sd_bus *bus, const char *path, const char *interface,
                         const char *property, sd_bus_message *reply,
                         void *userdata, sd_bus_error *error) {
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
                                 sd_bus_error *error) {
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
                               sd_bus_error *error) {
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
                                     sd_bus_error *error) {
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
                                sd_bus_error *error) {
  struct dbus_context *ctx = userdata;
  (void)bus;
  (void)path;
  (void)interface;
  (void)property;
  (void)error;
  return sd_bus_message_append(reply, "t", ctx->ipc->valid_until);
}

static int prop_get_version(sd_bus *bus, const char *path,
                            const char *interface, const char *property,
                            sd_bus_message *reply, void *userdata,
                            sd_bus_error *error) {
  (void)bus;
  (void)path;
  (void)interface;
  (void)property;
  (void)userdata;
  (void)error;
  return sd_bus_message_append(reply, "s", "1.0.0");
}

/*
 * Ping() -> (t uptime_sec, u pid)
 */
static int method_ping(sd_bus_message *msg, void *userdata,
                       sd_bus_error *error) {
  struct dbus_context *ctx = userdata;
  uint64_t uptime;
  (void)error;

  uptime = (uint64_t)(time(NULL) - ctx->ipc->start_time);
  return sd_bus_reply_method_return(msg, "tu", uptime, (uint32_t)getpid());
}

/*
 * GetStatus() -> (u flags, s mode, t last_attest_time,
 *                 t valid_until, u attest_count, u fail_count)
 */
static int method_get_status(sd_bus_message *msg, void *userdata,
                             sd_bus_error *error) {
  struct dbus_context *ctx = userdata;
  (void)error;

  return sd_bus_reply_method_return(
      msg, "usttuu", ctx->ipc->status_flags, mode_string(ctx->ipc->mode),
      ctx->ipc->last_attest_time, ctx->ipc->valid_until, ctx->ipc->attest_count,
      ctx->ipc->fail_count);
}

/*
 * GetToken() -> (u flags)
 *
 * Token generation requires TPM and the binary socket protocol
 * due to the variable-length TPM quote blob. Over D-Bus LOTA can
 * only report whether the system is attested, not the full token.
 * Clients that need the actual signed token must use the Unix
 * socket SDK.
 */
static int method_get_token(sd_bus_message *msg, void *userdata,
                            sd_bus_error *error) {
  struct dbus_context *ctx = userdata;

  if (!(ctx->ipc->status_flags & LOTA_STATUS_ATTESTED)) {
    return sd_bus_reply_method_errorf(msg, LOTA_DBUS_INTERFACE ".NotAttested",
                                      "System is not attested");
  }

  /*
   * return the status flags so callers can confirm attestation
   * state without needing the full binary token
   */
  (void)error;
  return sd_bus_reply_method_return(msg, "u", ctx->ipc->status_flags);
}

static const sd_bus_vtable agent_vtable[] = {
    SD_BUS_VTABLE_START(0),

    /* properties (read-only, emits-change on signal) */
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

    /* methods */
    SD_BUS_METHOD("Ping", "", "tu", method_ping, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("GetStatus", "", "usttuu", method_get_status,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("GetToken", "", "u", method_get_token,
                  SD_BUS_VTABLE_UNPRIVILEGED),

    /* signals */
    SD_BUS_SIGNAL("StatusChanged", "u", 0),
    SD_BUS_SIGNAL("AttestationResult", "b", 0),
    SD_BUS_SIGNAL("ModeChanged", "s", 0),

    SD_BUS_VTABLE_END};

struct dbus_context *dbus_init(struct ipc_context *ipc) {
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
    fprintf(stderr, "D-Bus: failed to open system bus: %s\n", strerror(-ret));
    free(ctx);
    return NULL;
  }

  ret = sd_bus_add_object_vtable(ctx->bus, &ctx->slot, LOTA_DBUS_OBJECT_PATH,
                                 LOTA_DBUS_INTERFACE, agent_vtable, ctx);
  if (ret < 0) {
    fprintf(stderr, "D-Bus: failed to register vtable: %s\n", strerror(-ret));
    sd_bus_unref(ctx->bus);
    free(ctx);
    return NULL;
  }

  ret = sd_bus_request_name(ctx->bus, LOTA_DBUS_BUS_NAME,
                            SD_BUS_NAME_REPLACE_EXISTING);
  if (ret < 0) {
    fprintf(stderr, "D-Bus: failed to claim %s: %s\n", LOTA_DBUS_BUS_NAME,
            strerror(-ret));
    sd_bus_slot_unref(ctx->slot);
    sd_bus_unref(ctx->bus);
    free(ctx);
    return NULL;
  }

  lota_info("D-Bus: registered %s on system bus", LOTA_DBUS_BUS_NAME);
  return ctx;
}

int dbus_get_fd(struct dbus_context *ctx) {
  if (!ctx || !ctx->bus)
    return -1;
  return sd_bus_get_fd(ctx->bus);
}

int dbus_process(struct dbus_context *ctx, uint64_t timeout_us) {
  int ret;

  if (!ctx || !ctx->bus)
    return -EINVAL;

  for (;;) {
    ret = sd_bus_process(ctx->bus, NULL);
    if (ret < 0) {
      fprintf(stderr, "D-Bus: process error: %s\n", strerror(-ret));
      return ret;
    }
    if (ret == 0)
      break; /* no more work */
  }

  /* wait for new work up to the caller-specified timeout */
  if (timeout_us > 0) {
    ret = sd_bus_wait(ctx->bus, timeout_us);
    if (ret < 0 && ret != -EINTR)
      return ret;
  }

  return 0;
}

void dbus_emit_status_changed(struct dbus_context *ctx, uint32_t flags) {
  if (!ctx || !ctx->bus)
    return;

  sd_bus_emit_signal(ctx->bus, LOTA_DBUS_OBJECT_PATH, LOTA_DBUS_INTERFACE,
                     "StatusChanged", "u", flags);

  sd_bus_emit_properties_changed(
      ctx->bus, LOTA_DBUS_OBJECT_PATH, LOTA_DBUS_INTERFACE, "StatusFlags",
      "LastAttestTime", "ValidUntil", "AttestCount", "FailCount", NULL);
}

void dbus_emit_attestation_result(struct dbus_context *ctx, bool success) {
  if (!ctx || !ctx->bus)
    return;

  sd_bus_emit_signal(ctx->bus, LOTA_DBUS_OBJECT_PATH, LOTA_DBUS_INTERFACE,
                     "AttestationResult", "b", (int)success);

  sd_bus_emit_properties_changed(ctx->bus, LOTA_DBUS_OBJECT_PATH,
                                 LOTA_DBUS_INTERFACE, "AttestCount",
                                 "FailCount", NULL);
}

void dbus_emit_mode_changed(struct dbus_context *ctx, uint8_t mode) {
  if (!ctx || !ctx->bus)
    return;

  sd_bus_emit_signal(ctx->bus, LOTA_DBUS_OBJECT_PATH, LOTA_DBUS_INTERFACE,
                     "ModeChanged", "s", mode_string(mode));

  sd_bus_emit_properties_changed(ctx->bus, LOTA_DBUS_OBJECT_PATH,
                                 LOTA_DBUS_INTERFACE, "Mode", NULL);
}

void dbus_cleanup(struct dbus_context *ctx) {
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
