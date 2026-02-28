#!/usr/bin/env bash
# release.sh — Cross-compile and package Adria v0.1.0 binaries
# Usage: ./release.sh
# Output: dist/ directory containing platform archives ready for GitHub Release
set -euo pipefail

VERSION="v0.1.0"
SDK_DIR="core-sdk"
DIST_DIR="dist"
BINARIES=("adria_server" "apl")

# Platforms: <archive-suffix>:<zig-triple>
declare -a TARGETS=(
    "macos-arm64:aarch64-macos"
    "linux-x86_64:x86_64-linux-musl"
)

echo "=== Adria ${VERSION} Release Builder ==="
echo ""

# Sanity checks
if ! command -v zig &> /dev/null; then
    echo "ERROR: zig not found in PATH"
    exit 1
fi

ZIG_VER=$(zig version)
echo "Zig: ${ZIG_VER}"
echo ""

# Clean dist
rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

for entry in "${TARGETS[@]}"; do
    SUFFIX="${entry%%:*}"
    TRIPLE="${entry##*:}"
    ARCHIVE_NAME="adria-${VERSION}-${SUFFIX}"
    STAGE_DIR="${DIST_DIR}/${ARCHIVE_NAME}"

    echo "--- Building for ${SUFFIX} (${TRIPLE}) ---"
    mkdir -p "${STAGE_DIR}"

    # Build with release optimizations
    (
        cd "${SDK_DIR}"
        zig build \
            -Dtarget="${TRIPLE}" \
            -Doptimize=ReleaseSafe \
            --prefix "../${STAGE_DIR}" \
            2>&1
    )

    # zig build installs under bin/ — move binaries up one level for clean layout
    for BIN in "${BINARIES[@]}"; do
        SRC="${STAGE_DIR}/bin/${BIN}"
        if [ -f "${SRC}" ]; then
            mv "${SRC}" "${STAGE_DIR}/${BIN}"
        elif [ -f "${SRC}.exe" ]; then
            mv "${SRC}.exe" "${STAGE_DIR}/${BIN}.exe"
        else
            echo "ERROR: expected binary not found: ${SRC}"
            exit 1
        fi
    done

    # Remove the empty bin/ directory left by zig build
    rm -rf "${STAGE_DIR}/bin"

    # Bundle supporting files
    cp README.md "${STAGE_DIR}/"
    cp LICENSE "${STAGE_DIR}/"
    cp adria-config.example.json "${STAGE_DIR}/"

    # Write a minimal quick-start note alongside the binaries
    cat > "${STAGE_DIR}/QUICK_START.txt" <<'EOF'
Adria Permissioned Ledger — Quick Start
========================================

1. Copy adria-config.example.json to adria-config.json and edit as needed.
2. Create the Root CA wallet:
     ./apl wallet create root_ca
     ./apl pubkey root_ca --raw
   Copy the hex output into adria-config.json → consensus.seed_root_ca

3. Issue certificates:
     ./apl cert issue root_ca root_ca   # root_ca needs its own cert
     ./apl wallet create mynode
     ./apl cert issue root_ca mynode

4. Start the node:
     ./adria_server --orderer

5. Submit a transaction:
     ./apl ledger record hello world mynode

See README.md for the full CLI reference.
EOF

    # Create archive
    ARCHIVE_PATH="${DIST_DIR}/${ARCHIVE_NAME}.tar.gz"
    (
        cd "${DIST_DIR}"
        tar -czf "${ARCHIVE_NAME}.tar.gz" "${ARCHIVE_NAME}/"
    )
    # Remove staging dir — keep only the archive
    rm -rf "${STAGE_DIR}"

    # Print SHA256 for the release notes
    SHASUM=$(shasum -a 256 "${ARCHIVE_PATH}" | awk '{print $1}')
    echo "  -> ${ARCHIVE_PATH}"
    echo "     SHA256: ${SHASUM}"
    echo ""
done

echo "=== Build complete ==="
echo ""
echo "Archives in ${DIST_DIR}/:"
ls -lh "${DIST_DIR}/"
echo ""
echo "Next steps:"
echo "  1. Inspect the archives: tar -tzf dist/<archive>.tar.gz"
echo "  2. Create the GitHub release:"
echo "       gh release create ${VERSION} \\"
echo "         --title 'Adria Permissioned Ledger ${VERSION}' \\"
echo "         --notes-file RELEASE_NOTES.md \\"
echo "         dist/*.tar.gz"
