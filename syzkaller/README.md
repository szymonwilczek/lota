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
    go install github.com/google/syzkaller/prog/syz-prog2c@latest
    go install github.com/google/syzkaller/syz-manager@latest
    ```
    This binaries will be in `$GOPATH/bin`.

2.  **Compile Linux Kernel**:
    Use a config with KASAN, KCOV, etc. enabled.
    ```bash
    cd /path/to/linux-source
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

## Running

```bash
syz-manager -config lota.cfg
```

Syzkaller will start QEMU instances and begin fuzzing. Access the web dashboard at `http://127.0.0.1:56741`.
