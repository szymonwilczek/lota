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
REMOTE_DIR="${REMOTE_GO_FUZZ_DIR:-/home/wolfie/lota-go-fuzz}"
BUILD_DIR="build/fuzz"

echo "=== Building Go Fuzzers for $REMOTE_HOST ==="

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "-> Compiling Go Fuzz Targets..."
find src -name "*_fuzz_test.go" -print0 | xargs -0 -n1 dirname | sort -u | while read -r pkg_path; do
    pkg_name=$(basename "$pkg_path")
    bin_name="fuzz_$(echo "$pkg_path" | tr '/' '_')"
    
    echo "   Building $bin_name from $pkg_path..."
    
    target_dir="$pkg_path"
    module_root=""
    rel_pkg="."
    
    pushd . > /dev/null
    
    cd "$pkg_path"
    
    while [ "$PWD" != "/" ]; do
        if [ -f "go.mod" ]; then
            module_root="$PWD"
            break
        fi
        cd ..
    done
    
    popd > /dev/null
    
    if [ -z "$module_root" ]; then
        echo "WARNING: No go.mod found for $pkg_path, skipping..."
        continue
    fi
    
    abs_pkg_path=$(realpath "$pkg_path")
    abs_mod_root=$(realpath "$module_root")
    rel_pkg_path=${abs_pkg_path#"$abs_mod_root"}
    rel_pkg_path=${rel_pkg_path#/}
    if [ -z "$rel_pkg_path" ]; then rel_pkg_path="."; else rel_pkg_path="./$rel_pkg_path"; fi
    
    echo "      Module root: $abs_mod_root"
    echo "      Package: $rel_pkg_path"

    (cd "$module_root" && GOOS=linux GOARCH=amd64 go test -c -o "../../../$BUILD_DIR/$bin_name" "$rel_pkg_path")
done

echo "-> Creating Runner Script..."
cat <<EOF > "$BUILD_DIR/run_fuzzers.sh"
#!/bin/bash
# Run all fuzzers in parallel, but with low priority
# Each fuzzer runs for 10 minutes then restarts (to rotate logs/prevent hangs)

PIDS=""

cleanup() {
    echo "Stopping fuzzers..."
    if [ -n "\$PIDS" ]; then
        kill \$PIDS 2>/dev/null || true
    fi
    exit 0
}
trap cleanup SIGINT SIGTERM

mkdir -p logs

while true; do
    echo "Starting fuzzers round..."
    PIDS=""
    for f in ./fuzz_*; do
        if [ -x "\$f" ]; then
            bin_name=\$(basename "\$f")
            
            targets=\$(\$f -test.list 'Fuzz' 2>/dev/null | grep '^Fuzz')
            
            if [ -z "\$targets" ]; then
                 echo "Warning: No fuzz targets in \$bin_name"
            fi

            for target in \$targets; do
                echo "   Launching \$target in \$bin_name..."
                logs_file="logs/\${bin_name}_\${target}.log"
                nice -n 19 \$f -test.fuzz="^\$target\$" -test.fuzztime=600s -test.parallel=1 > "\$logs_file" 2>&1 &
                pid=\$!
                PIDS="\$PIDS \$pid"
            done
        fi
    done

    if [ -z "\$PIDS" ]; then
        echo "No fuzz targets found! Waiting..."
        sleep 60
    else
        echo "Waiting for PIDs: \$PIDS"
        wait \$PIDS
        echo "Round finished. Sleeping 10s..."
        sleep 10
    fi
done
EOF
chmod +x "$BUILD_DIR/run_fuzzers.sh"

echo "-> Deploying to $REMOTE_HOST..."

tar -czf build/dist_go_fuzz.tar.gz -C "$BUILD_DIR" .
scp build/dist_go_fuzz.tar.gz "$REMOTE_HOST:~/"

ssh -t "$REMOTE_HOST" "
    mkdir -p '$REMOTE_DIR'
    tar -xzf ~/dist_go_fuzz.tar.gz -C '$REMOTE_DIR'
"

echo "=== Deployment Complete ==="
