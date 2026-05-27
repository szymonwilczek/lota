/* SPDX-License-Identifier: MIT */
#ifndef LOTA_TEST_SERVERS_H
#define LOTA_TEST_SERVERS_H

struct lota_config;

/*
 * @cfg: forwarded to setup_container_listener so the diagnostic
 *       paths honor container_listener_uid the same way the
 *       systemd-run daemon does. NULL keeps the legacy
 *       XDG_RUNTIME_DIR-driven single listener.
 */
int run_ipc_test_server(const struct lota_config *cfg);
int run_signed_ipc_test_server(const struct lota_config *cfg);

#endif /* LOTA_TEST_SERVERS_H */
