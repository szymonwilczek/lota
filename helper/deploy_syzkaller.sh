#!/bin/bash
set -e

SCRIPT_DIR="$(dirname "$0")"
if [ -f "$SCRIPT_DIR/.env" ]; then
    export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
else
    echo "ERROR: .env file not found in $SCRIPT_DIR!"
    echo "Please copy $SCRIPT_DIR/.env.example to $SCRIPT_DIR/.env and configure it."
    exit 1
fi

REMOTE_HOST="${REMOTE_HOST:-dionisus}"
REMOTE_DIR="${REMOTE_SYZKALLER_DIR:-/home/wolfie/lota-fuzz}"
DIST_DIR="dist_deploy"

echo "=== Packaging Syzkaller for Remote Deployment to $REMOTE_HOST ==="

rm -rf "$DIST_DIR" "$DIST_DIR.tar.gz"
mkdir -p "$DIST_DIR/bin"

echo "-> Copying binaries (syz-manager, syz-execprog, syz-executor)..."
mkdir -p "$DIST_DIR/bin/linux_amd64"
cp syzkaller/repo/bin/syz-manager "$DIST_DIR/bin/"
cp syzkaller/repo/bin/linux_amd64/syz-execprog "$DIST_DIR/bin/linux_amd64/"
cp syzkaller/repo/bin/linux_amd64/syz-executor "$DIST_DIR/bin/linux_amd64/"

echo "-> Checking Kernel..."
mkdir -p "$DIST_DIR/kernel"
if [ -f "linux-6.18.10/arch/x86/boot/bzImage" ] && [ -f "linux-6.18.10/vmlinux" ]; then
    echo "-> Copying Kernel (bzImage & vmlinux)..."
    cp linux-6.18.10/arch/x86/boot/bzImage "$DIST_DIR/kernel/bzImage"
    cp linux-6.18.10/vmlinux "$DIST_DIR/kernel/vmlinux"
else
    echo "WARNING: Kernel binaries not found locally. Skipping copy."
    echo "This update will only deploy Syzkaller binaries and config."
fi

echo "-> Copying Disk Image & SSH Key..."
cp syzkaller/repo/tools/trixie.img "$DIST_DIR/trixie.img"
cp syzkaller/repo/tools/trixie.id_rsa "$DIST_DIR/trixie.id_rsa"
chmod 600 "$DIST_DIR/trixie.id_rsa"

echo "-> Generating Remote lota.cfg..."
cat > "$DIST_DIR/lota.cfg" <<EOF
{
    "target": "linux/amd64",
    "name": "lota-fuzzer-dionisus",
    "http": "0.0.0.0:56741",
    "workdir": "$REMOTE_DIR/workdir",
    "kernel_obj": "$REMOTE_DIR/kernel",
    "image": "$REMOTE_DIR/trixie.img",
    "sshkey": "$REMOTE_DIR/trixie.id_rsa",
    "syzkaller": "$REMOTE_DIR",
    "procs": 2,
    "type": "qemu",
    "vm": {
        "count": 4,
        "kernel": "$REMOTE_DIR/kernel/bzImage",
        "cmdline": "net.ifnames=0 biosdevname=0 root=/dev/sda console=ttyS0 oops=panic panic_on_warn=0 panic=1",
        "cpu": 2,
        "mem": 4096
    },
    "enable_syscalls": [
        "bpf",
        "execve",
        "ptrace",
        "mmap",
        "socket",
        "socket$unix",
        "socketpair",
        "socketpair$unix",
        "connect",
        "connect$lota",
        "sendto",
        "recvfrom",
        "bind",
        "listen",
        "accept",
        "ioctl",
        "open",
        "openat",
        "creat",
        "write",
        "read",
        "close",
        "unlink",
        "rename",
        "mkdir",
        "rmdir",
        "write$lota_ping",
        "write$lota_status",
        "write$lota_token",
        "write$lota_subscribe",
        "write$lota_generic"
    ],
    "email_addrs": [
        "developer@example.com"
    ]
}
EOF

echo "-> Generating Remote lota-fuzz.service..."
cat > "$DIST_DIR/lota-fuzz.service" <<EOF
[Unit]
Description=LOTA Syzkaller Fuzzing Daemon (Remote)
After=network.target

[Service]
Type=simple
User=wolfie
Group=wolfie
WorkingDirectory=$REMOTE_DIR
ExecStart=$REMOTE_DIR/bin/syz-manager -config $REMOTE_DIR/lota.cfg
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

echo "-> Creating archive $DIST_DIR.tar.gz..."
tar czf "$DIST_DIR.tar.gz" -C "$DIST_DIR" .

echo "=== archive ready. Size: $(du -h "$DIST_DIR.tar.gz" | cut -f1) ==="
echo ""
echo "Now, please run the following commands to deploy to $REMOTE_HOST:"
echo ""
echo "---------- 1. DEPLOY FILES ----------"
echo "scp $DIST_DIR.tar.gz $REMOTE_HOST:~/"
echo ""
echo "---------- 2. SETUP REMOTE ENVIRONMENT ----------"
echo "ssh $REMOTE_HOST 'mkdir -p $REMOTE_DIR && tar xzf dist_deploy.tar.gz -C $REMOTE_DIR'"
echo ""
echo "---------- 3. INSTALL DEPENDENCIES (Fedora) ----------"
echo "ssh $REMOTE_HOST 'sudo dnf install -y qemu-system-x86 s-nail'"
echo ""
echo "---------- 4. CONFIGURE EMAIL (IMPORTANT!) ----------"
echo "To send emails via Gmail/SMTP, you must create ~/.mailrc on $REMOTE_HOST:"
echo "ssh $REMOTE_HOST 'nano ~/.mailrc'"
echo "Content template:"
echo "  set v15-compat"
echo "  set mta=smtp://smtp.gmail.com:587"
echo "  set smtp-auth=login"
echo "  set smtp-auth-user=your_email@gmail.com"
echo "  set smtp-auth-password=your_password"
echo "  set from=your_email@gmail.com"
echo ""
echo "Test email: echo 'Test body' | mailx -v -s 'Test subject' your_email@gmail.com"
echo ""
echo "---------- 5. INSTALL SERVICE ----------"
echo "ssh $REMOTE_HOST 'sudo cp $REMOTE_DIR/lota-fuzz.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now lota-fuzz'"
echo ""
echo "---------- 6. VERIFY ----------"
echo "ssh $REMOTE_HOST 'sudo journalctl -u lota-fuzz -f'"
