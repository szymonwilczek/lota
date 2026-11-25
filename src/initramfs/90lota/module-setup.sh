#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek

check() {
    [ -x /usr/lib/lota/lota-pcr14-lock ]
}

depends() {
    echo "systemd"
    return 0
}

install() {
    local unit="lota-pcr14-lock.service"

    inst_binary /usr/lib/lota/lota-pcr14-lock
    inst_simple "$moddir/$unit" "$systemdsystemunitdir/$unit"
    systemctl -q --root "$initdir" enable "$unit"
}
