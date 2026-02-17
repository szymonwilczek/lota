#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Helper script for setting up fs-verity for LOTA testing.
#
# Usage:
#   ./setup-fsverity.sh check - Check kernel support
#   ./setup-fsverity.sh enable <file> - Enable fs-verity on a file
#   ./setup-fsverity.sh digest <file> - Get digest of a file

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

check_support() {
    echo "Checking fs-verity support..."
    
    if ! command_exists fsverity; then
        echo -e "${RED}Error: 'fsverity' utility not found.${NC}"
        echo "Please install fsverity-utils (e.g., 'sudo dnf install fsverity-utils' or 'sudo apt install fsverity')."
        return 1
    fi

    # check filesystem support (requires a file on the fs)
    # assume current dir is on a supporting fs
    touch .fsverity_check
    if ! fsverity enable .fsverity_check 2>/dev/null; then
         echo -e "${RED}Error: Filesystem does not support fs-verity or it is disabled.${NC}"
         echo "Ensure you are on ext4/f2fs/btrfs with 'verity' feature enabled."
         echo "tune2fs -O verity /dev/sdX"
         rm -f .fsverity_check
         return 1
    fi
    rm -f .fsverity_check
    
    echo -e "${GREEN}fs-verity is supported and working.${NC}"
    return 0
}

enable_verity() {
    local file="$1"
    if [ -z "$file" ]; then
        echo "Usage: $0 enable <file>"
        return 1
    fi

    if ! command_exists fsverity; then
        echo -e "${RED}fsverity tool missing${NC}"
        return 1
    fi

    echo "Enabling fs-verity on $file..."
    fsverity enable "$file"
    echo -e "${GREEN}Enabled.${NC}"
    
    digest=$(fsverity digest "$file" | awk '{print $2}')
    echo "Digest: $digest"
}

get_digest() {
    local file="$1"
    if [ -z "$file" ]; then
        echo "Usage: $0 digest <file>"
        return 1
    fi

    if ! command_exists fsverity; then
        echo -e "${RED}fsverity tool missing${NC}"
        return 1
    fi

    fsverity digest "$file"
}

case "$1" in
    check)
        check_support
        ;;
    enable)
        enable_verity "$2"
        ;;
    digest)
        get_digest "$2"
        ;;
    *)
        echo "Usage: $0 {check|enable|digest}"
        exit 1
        ;;
esac
