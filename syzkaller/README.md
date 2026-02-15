# Syzkaller for LOTA

This directory contains configuration for fuzzing the LOTA kernel environment using [google/syzkaller](https://github.com/google/syzkaller).

## Prerequisites

1.  **Go Toolchain**: `go` 1.18+
2.  **C Compiler**: `gcc`
3.  **QEMU**: `qemu-system-x86_64`
4.  **Linux Kernel Source**: To compile a fuzzing-friendly kernel.

## Setup

1.  **Build Syzkaller**:
    ```bash
    git clone https://github.com/google/syzkaller syzkaller/repo
    cd syzkaller/repo
    make
    ```
    The binaries will be in `bin/` (e.g., `bin/syz-manager`, `bin/linux_amd64/syz-prog2c`).

2.  **Compile Linux Kernel**:
    Use a config with KASAN, KCOV, etc. enabled. Download Linux 6.18.10 (or latest stable).
    ```bash
    wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.10.tar.xz
    tar xJf linux-6.18.10.tar.xz
    cd linux-6.18.10
    make defconfig
    ./scripts/config -e KCT_KASAN -e KCOV -e KCOV_INSTRUMENT_ALL -e KCOV_ENABLE_COMPARISONS -e DEBUG_FS -e DEBUG_INFO -e KALLSYMS -e KALLSYMS_ALL -e NAMESPACES -e UTS_NS -e IPC_NS -e PID_NS -e NET_NS -e CGROUPS -e CGROUP_NET_PRIO -e CGROUP_NET_CLASSID -e BPF_SYSCALL -e USER_NS -e ADVISE_SYSCALLS -e MEMBARRIER -e KINGS -e VIRTIO_NET -e VIRTIO_BLK -e VIRTIO_PCI -e VIRTIO_CONSOLE
    make -j$(nproc)
    ```

3.  **Create Image**:
    Create a Debian strech image using `create-image.sh` script from Syzkaller repo:
    ```bash
    wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
    chmod +x create-image.sh
    ./create-image.sh
    ```
    This creates `stretch.img` and `stretch.id_rsa`.

4.  **Configure**:
    Edit `lota.cfg` and set paths to:
    - `kernel_obj`: Path to your compiled kernel source.
    - `image`: Path to `stretch.img`.
    - `sshkey`: Path to `stretch.id_rsa`.
    - `syzkaller`: Path to syzkaller repo (if cloned) or leave default if installed.

5.  **Reporting**:
    To receive crash reports via email, configure the `email_addrs` list in `lota.cfg`:
    ```json
    "email_addrs": [
        "your-email@example.com"
    ]
    ```
    Ensure `mailx` is configured on the host machine.

## Running

```bash
syz-manager -config lota.cfg
```

Syzkaller will start QEMU instances and begin fuzzing. Access the web dashboard at `http://127.0.0.1:56741`.

## Continuous Fuzzing (Systemd)

To run Syzkaller continuously as a background service:

1.  **Edit Service File**: Adjust user/paths in `lota-fuzz.service`.
2.  **Install**:
    ```bash
    sudo cp lota-fuzz.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now lota-fuzz
    ```
3.  **Check Status**:
    ```bash
    systemctl status lota-fuzz
    journalctl -u lota-fuzz -f
    ```
