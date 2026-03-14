#!/usr/bin/env bash
set -euo pipefail

BIN_NAME="${BIN_NAME:-noders-anytls}"
RELEASE_TAG=""
TARGET=""
ASSET_SUFFIX=""

usage() {
  cat <<'EOF'
Usage: package-release-bundle.sh --release-tag <tag> --target <rust-target> --asset-suffix <suffix>
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release-tag)
      RELEASE_TAG="$2"
      shift 2
      ;;
    --target)
      TARGET="$2"
      shift 2
      ;;
    --asset-suffix)
      ASSET_SUFFIX="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

[[ -n "$RELEASE_TAG" && -n "$TARGET" && -n "$ASSET_SUFFIX" ]] || {
  usage >&2
  exit 1
}

package_dir="dist/${BIN_NAME}-${RELEASE_TAG}-${ASSET_SUFFIX}"
mkdir -p "$package_dir/packaging/systemd" "$package_dir/lib"
cp "target/${TARGET}/release/${BIN_NAME}" "$package_dir/${BIN_NAME}"
cp README.md LICENSE config.example.toml "$package_dir/"
cp scripts/install.sh "$package_dir/install.sh"
cp scripts/install-openrc.sh "$package_dir/install-openrc.sh"
cp scripts/lib/install-common.sh "$package_dir/lib/install-common.sh"
cp scripts/upgrade.sh "$package_dir/upgrade.sh"
cp packaging/systemd/noders-anytls.service "$package_dir/packaging/systemd/noders-anytls.service"
chmod +x "$package_dir/install.sh" "$package_dir/install-openrc.sh" "$package_dir/upgrade.sh" "$package_dir/${BIN_NAME}"
tar -C dist -czf "${package_dir}.tar.gz" "$(basename "$package_dir")"
sha256sum "${package_dir}.tar.gz" > "${package_dir}.tar.gz.sha256"
