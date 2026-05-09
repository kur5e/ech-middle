#!/usr/bin/env bash
# Cross-compile ech-middle for all supported platforms.
# Requires Go 1.23+ and bash. Works on Linux, macOS, and Windows (Git Bash).
#
# Usage:
#   ./scripts/build.sh              # Build all targets
#   ./scripts/build.sh linux/amd64  # Build single target
#   ./scripts/build.sh -o ./dist    # Output to custom directory
#
# Output structure:
#   dist/
#     ech-middle_windows_amd64.exe
#     ech-middle_linux_amd64
#     ech-middle_linux_arm64
#     ech-middle_darwin_amd64
#     ech-middle_darwin_arm64
#     ech-middle_openwrt_mipsle
set -euo pipefail

OUT_DIR="dist"
LDFLAGS="-s -w"
CGO_ENABLED=0
VERSION="${VERSION:-dev}"
BUILD_TIME="$(date -u '+%Y-%m-%d_%H:%M:%S_UTC')"
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"

# Ensure we are in the project root (where go.mod lives).
cd "$(dirname "$0")/.."

# Parse args.
SINGLE_TARGET=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--out) OUT_DIR="$2"; shift 2 ;;
        linux/*|darwin/*|windows/*|openwrt/*) SINGLE_TARGET="$1"; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

mkdir -p "$OUT_DIR"

# Target definitions: "label|GOOS|GOARCH|extra_env"
# extra_env is optional and space-separated (e.g. "GOMIPS=softfloat")
TARGETS=(
    "windows_amd64|windows|amd64|"
    "linux_amd64|linux|amd64|"
    "linux_arm64|linux|arm64|"
    "darwin_amd64|darwin|amd64|"
    "darwin_arm64|darwin|arm64|"
    "openwrt_mipsle|linux|mipsle|GOMIPS=softfloat"
)

build_target() {
    local label="$1"   # e.g. windows_amd64
    local goos="$2"    # e.g. windows
    local goarch="$3"  # e.g. amd64
    local extra="$4"   # e.g. GOMIPS=softfloat

    local out_name="ech-middle_${label}"
    if [[ "$goos" == "windows" ]]; then
        out_name="${out_name}.exe"
    fi

    local full_ldflags="${LDFLAGS} -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} -X main.gitCommit=${GIT_COMMIT}"

    echo ">>> Building ${label} (${goos}/${goarch}) ..."

    # Build in a subshell so 'export' doesn't pollute the parent.
    (
        export GOOS="$goos"
        export GOARCH="$goarch"
        export CGO_ENABLED=0
        if [[ -n "$extra" ]]; then
            # extra is like "GOMIPS=softfloat"
            eval "export ${extra}"
        fi

        go build \
            -ldflags="${full_ldflags}" \
            -trimpath \
            -o "${OUT_DIR}/${out_name}" \
            .
    )

    local size
    size=$(du -h "${OUT_DIR}/${out_name}" | cut -f1)
    echo "    -> ${OUT_DIR}/${out_name}  (${size})"
}

echo "╔══════════════════════════════════════╗"
echo "║  ech-middle cross-compile builder   ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "Version:    ${VERSION}"
echo "Commit:     ${GIT_COMMIT}"
echo "Build time: ${BUILD_TIME}"
echo "Go version: $(go version)"
echo "Output:     ${OUT_DIR}/"
echo ""

if [[ -n "$SINGLE_TARGET" ]]; then
    # Parse single target: linux/amd64 → label=linux_amd64, goos=linux, goarch=amd64
    IFS='/' read -r goos goarch <<< "$SINGLE_TARGET"
    label="${goos}_${goarch}"
    extra=""
    if [[ "$goos" == "linux" && "$goarch" == "mipsle" ]]; then
        label="openwrt_mipsle"
        extra="GOMIPS=softfloat"
    fi
    build_target "$label" "$goos" "$goarch" "$extra"
else
    for def in "${TARGETS[@]}"; do
        IFS='|' read -r label goos goarch extra <<< "$def"
        build_target "$label" "$goos" "$goarch" "$extra"
    done
fi

echo ""
echo "Done! Binaries in ${OUT_DIR}/"
ls -lh "${OUT_DIR}/" 2>/dev/null || true
