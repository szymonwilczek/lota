#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# dracut module: install the LOTA PCR14 lock helper into initramfs.

check() {
    [ -x /usr/lib/lota/lota-pcr14-lock ]
}

depends() {
    echo "systemd"
    return 0
}

install() {
    local unit="lota-pcr14-lock.service"

    # dracut's inst_binary resolves the shared-library closure for the
    # helper, which is why the binary is intentionally linked only
    # against ESYS, device TCTI, libc, and libcrypto.
    inst_binary /usr/lib/lota/lota-pcr14-lock
    inst_simple "$moddir/$unit" "$systemdsystemunitdir/$unit"
    systemctl -q --root "$initdir" enable "$unit"
}
