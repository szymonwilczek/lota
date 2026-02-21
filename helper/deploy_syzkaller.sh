#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/.env" ]; then
    # shellcheck disable=SC2046
    export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
else
    echo "ERROR: .env file not found in $SCRIPT_DIR!"
    echo "Please copy $SCRIPT_DIR/.env.example to $SCRIPT_DIR/.env and configure it."
    exit 1
fi

REMOTE_HOST="${REMOTE_HOST:-dionisus.local}"
REMOTE_DIR_RAW="${REMOTE_SYZKALLER_DIR:-/home/wolfie/lota-fuzz}"
DIST_DIR="dist_deploy"

AUTO_DEPLOY=0
if [[ "${1:-}" == "--deploy" ]]; then
    AUTO_DEPLOY=1
fi

PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

require_file() {
    local p="$1"
    if [[ ! -f "$p" ]]; then
        echo "ERROR: missing file: $p" >&2
        exit 1
    fi
}

require_cmd() {
    local c="$1"
    if ! command -v "$c" >/dev/null 2>&1; then
        echo "ERROR: missing required command: $c" >&2
        exit 1
    fi
}

require_cmd ssh
require_cmd scp
require_cmd tar
require_cmd python3

echo "=== Packaging Syzkaller for Remote Deployment to $REMOTE_HOST ==="

require_file syzkaller/lota.txt
require_file syzkaller/lota.cfg
require_file syzkaller/lota-fuzz.service
require_file syzkaller/repo/Makefile

echo "-> Syncing custom syzlang (lota.txt) into syzkaller repo..."
cp -f syzkaller/lota.txt syzkaller/repo/sys/linux/lota.txt

echo "-> Rebuilding syzkaller binaries (so they include updated lota.txt)..."
(cd syzkaller/repo && make)

rm -rf "$DIST_DIR" "$DIST_DIR.tar.gz"
mkdir -p "$DIST_DIR/bin"

echo "-> Copying binaries (syz-manager, syz-execprog, syz-executor)..."
mkdir -p "$DIST_DIR/bin/linux_amd64"
cp syzkaller/repo/bin/syz-manager "$DIST_DIR/bin/"
cp syzkaller/repo/bin/syz-repro "$DIST_DIR/bin/" || true
cp syzkaller/repo/bin/linux_amd64/syz-execprog "$DIST_DIR/bin/linux_amd64/"
cp syzkaller/repo/bin/linux_amd64/syz-executor "$DIST_DIR/bin/linux_amd64/"

KERNEL_DIR="${KERNEL_BUILD_DIR:-linux-6.18.10}"

echo "-> Checking Kernel (from $KERNEL_DIR)..."
mkdir -p "$DIST_DIR/kernel"
if [ -f "$KERNEL_DIR/arch/x86/boot/bzImage" ] && [ -f "$KERNEL_DIR/vmlinux" ]; then
    echo "-> Copying Kernel (bzImage & vmlinux)..."
    cp "$KERNEL_DIR/arch/x86/boot/bzImage" "$DIST_DIR/kernel/bzImage"
    cp "$KERNEL_DIR/vmlinux" "$DIST_DIR/kernel/vmlinux"
else
    if [[ "${ALLOW_NO_KERNEL:-0}" == "1" ]]; then
        echo "WARNING: Kernel binaries not found locally. Skipping copy (ALLOW_NO_KERNEL=1)."
        echo "This update will only deploy Syzkaller binaries and config."
    else
        echo "ERROR: Kernel binaries not found locally (missing $KERNEL_DIR/arch/x86/boot/bzImage and/or $KERNEL_DIR/vmlinux)." >&2
        echo "Syzkaller/QEMU won't run without a kernel. Build it first, or re-run with ALLOW_NO_KERNEL=1 to package binaries only." >&2
        exit 1
    fi
fi

echo "-> Copying Disk Image & SSH Key..."
cp syzkaller/repo/tools/trixie.img "$DIST_DIR/trixie.img"
cp syzkaller/repo/tools/trixie.id_rsa "$DIST_DIR/trixie.id_rsa"
chmod 600 "$DIST_DIR/trixie.id_rsa"

echo "-> Resolving remote home directory..."
REMOTE_HOME=$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$REMOTE_HOST" 'printf "%s" "$HOME"')
REMOTE_DIR="$REMOTE_DIR_RAW"
if [[ "$REMOTE_DIR" == ~* ]]; then
  REMOTE_DIR="$REMOTE_HOME/${REMOTE_DIR#~/}"
fi

REMOTE_DIR="${REMOTE_DIR//\/~\//\/}"

echo "-> Generating Remote lota.cfg from syzkaller/lota.cfg..."
python3 - "$REMOTE_DIR" syzkaller/lota.cfg > "$DIST_DIR/lota.cfg" <<'PY'
import json
import sys

remote_dir = sys.argv[1]
cfg_path = sys.argv[2]
with open(cfg_path, "r", encoding="utf-8") as f:
    cfg = json.load(f)

cfg["name"] = cfg.get("name", "lota-fuzzer") + "-remote"
cfg["http"] = "0.0.0.0:56741"
cfg["workdir"] = f"{remote_dir}/workdir"
cfg["kernel_obj"] = f"{remote_dir}/kernel"
cfg["image"] = f"{remote_dir}/trixie.img"
cfg["sshkey"] = f"{remote_dir}/trixie.id_rsa"
cfg["syzkaller"] = remote_dir

vm = cfg.get("vm", {})
vm["kernel"] = f"{remote_dir}/kernel/bzImage"
cfg["vm"] = vm

json.dump(cfg, sys.stdout, indent=2, sort_keys=False)
sys.stdout.write("\n")
PY

echo "-> Generating Remote lota-fuzz.service from syzkaller/lota-fuzz.service..."
cat > "$DIST_DIR/lota-fuzz.service" <<EOF
[Unit]
Description=LOTA Syzkaller Manager (Remote)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$REMOTE_HOST" 'whoami')
Group=$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$REMOTE_HOST" 'id -gn')

WorkingDirectory=$REMOTE_DIR
ExecStart=$REMOTE_DIR/bin/syz-manager -config $REMOTE_DIR/lota.cfg

Restart=always
RestartSec=5

AmbientCapabilities=CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_SYS_PTRACE CAP_NET_ADMIN CAP_BPF CAP_PERFMON
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_SYS_PTRACE CAP_NET_ADMIN CAP_BPF CAP_PERFMON
LimitMEMLOCK=infinity
LimitNOFILE=1048576
LimitNPROC=65535
TasksMax=infinity

StandardOutput=journal
StandardError=journal

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
echo "ssh $REMOTE_HOST 'sudo cp $REMOTE_DIR/lota-fuzz.service /etc/systemd/system/lota-fuzz.service && sudo systemctl daemon-reload && sudo systemctl enable --now lota-fuzz.service'"
echo ""
echo "---------- 6. VERIFY ----------"
echo "ssh $REMOTE_HOST 'sudo journalctl -u lota-fuzz.service -f'"

if [[ "$AUTO_DEPLOY" -eq 1 ]]; then
    echo ""
    echo "=== Auto-deploy enabled (--deploy) ==="
    echo "-> Uploading archive..."
    scp "$DIST_DIR.tar.gz" "$REMOTE_HOST:~/dist_deploy.tar.gz"

    echo "-> Extracting to $REMOTE_DIR..."
    ssh "$REMOTE_HOST" "set -e; mkdir -p '$REMOTE_DIR' && tar xzf ~/dist_deploy.tar.gz -C '$REMOTE_DIR'"

    echo "-> Installing/refreshing systemd service..."
    if ssh -o BatchMode=yes -o ConnectTimeout=8 "$REMOTE_HOST" 'sudo -n true' >/dev/null 2>&1; then
        ssh "$REMOTE_HOST" "set -e; sudo cp '$REMOTE_DIR/lota-fuzz.service' /etc/systemd/system/lota-fuzz.service; sudo systemctl daemon-reload; sudo systemctl enable --now lota-fuzz.service"

        echo "-> Service status:"
        ssh "$REMOTE_HOST" "systemctl --no-pager --full status lota-fuzz.service || true"
    else
        echo "WARNING: non-interactive sudo is not available on $REMOTE_HOST (password/TTY required)."
        echo "The bundle is extracted to: $REMOTE_DIR"
        echo "Run this manually (interactive) to install the service:"
        echo "  ssh -t $REMOTE_HOST 'sudo cp $REMOTE_DIR/lota-fuzz.service /etc/systemd/system/lota-fuzz.service && sudo systemctl daemon-reload && sudo systemctl enable --now lota-fuzz.service'"
        echo "Then follow logs with:"
        echo "  ssh -t $REMOTE_HOST 'sudo journalctl -u lota-fuzz.service -f'"
    fi
fi
