#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="MoeclubM/NodeRS-AnyTLS"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
COMMON_LIB_PATH="$SCRIPT_DIR/lib/install-common.sh"
PREFIX="/usr/local"
CONFIG_DIR="/etc/noders/anytls"
SERVICE_NAME="noders-anytls"
VERSION="latest"
NO_RESTART=0
TMP_ROOT=""
BACKUP_BINARY=""
declare -a DISCOVERED_UNITS=()
declare -a ACTIVE_UNITS=()

if [[ -f "$COMMON_LIB_PATH" ]]; then
  # shellcheck source=/dev/null
  source "$COMMON_LIB_PATH"
fi

cleanup() {
  if [[ -n "$TMP_ROOT" && -d "$TMP_ROOT" ]]; then
    rm -rf "$TMP_ROOT"
  fi
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
Usage: upgrade.sh [options]

Upgrade the installed NodeRS-AnyTLS binary in place.
Existing node configs, certificates, ACME account files, and state are preserved.

Options:
  --version <tag>       Release tag to install, default: latest
  --prefix <path>       Binary prefix, default: /usr/local
  --config-dir <path>   Config directory, default: /etc/noders/anytls
  --no-restart          Replace the binary but do not restart services
  -h, --help            Show this help message

Examples:
  bash upgrade.sh
  bash upgrade.sh --version v0.0.8
  bash upgrade.sh --version v0.0.8 --no-restart
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

require_linux() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "This upgrader only supports Linux." >&2
    exit 1
  fi
}

detect_asset_suffix() {
  if declare -F detect_release_asset_suffix >/dev/null 2>&1; then
    detect_release_asset_suffix
    return
  fi

  local detected_glibc_version libc_family
  version_at_least() {
    local lhs rhs
    lhs="$1"
    rhs="$2"
    awk -v lhs="$lhs" -v rhs="$rhs" '
      BEGIN {
        split(lhs, left, ".");
        split(rhs, right, ".");
        max_len = length(left) > length(right) ? length(left) : length(right);
        for (i = 1; i <= max_len; i++) {
          left_part = (i in left) ? left[i] + 0 : 0;
          right_part = (i in right) ? right[i] + 0 : 0;
          if (left_part > right_part) exit 0;
          if (left_part < right_part) exit 1;
        }
        exit 0;
      }
    '
  }
  glibc_version() {
    if command -v getconf >/dev/null 2>&1; then
      getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}'
    fi
  }
  detect_local_libc() {
    local output version
    version="$(glibc_version)"
    if [[ -n "$version" ]]; then
      printf 'glibc\n'
      return
    fi
    if command -v ldd >/dev/null 2>&1; then
      output="$(ldd --version 2>&1 || true)"
      if printf '%s' "$output" | grep -qi 'musl'; then
        printf 'musl\n'
        return
      fi
    fi
    if compgen -G '/lib/ld-musl-*.so.1' >/dev/null || compgen -G '/usr/lib/ld-musl-*.so.1' >/dev/null; then
      printf 'musl\n'
      return
    fi
    printf 'unknown\n'
  }

  case "$(uname -m)" in
    x86_64|amd64)
      libc_family="$(detect_local_libc)"
      if [[ "$libc_family" == "glibc" ]]; then
        detected_glibc_version="$(glibc_version)"
        if [[ -n "$detected_glibc_version" ]] && version_at_least "$detected_glibc_version" "2.17"; then
          printf 'linux-amd64\n'
          return
        fi
        echo "Detected glibc ${detected_glibc_version:-unknown}; falling back to linux-amd64-musl because GNU builds target glibc >= 2.17." >&2
        printf 'linux-amd64-musl\n'
        return
      fi
      if [[ "$libc_family" == "musl" ]]; then
        echo "Detected musl userspace; using linux-amd64-musl release bundle." >&2
      else
        echo "Unable to detect the host libc; using linux-amd64-musl release bundle for compatibility." >&2
      fi
      printf 'linux-amd64-musl\n'
      ;;
    *)
      echo "Unsupported architecture for prebuilt releases: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version)
        VERSION="$2"
        shift 2
        ;;
      --prefix)
        PREFIX="$2"
        shift 2
        ;;
      --config-dir)
        CONFIG_DIR="$2"
        shift 2
        ;;
      --no-restart)
        NO_RESTART=1
        shift
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
}

release_layout_present() {
  [[ -f "$SCRIPT_DIR/noders-anytls" ]]
}

resolve_release_tag() {
  if [[ "$VERSION" != "latest" ]]; then
    printf '%s\n' "$VERSION"
    return
  fi

  need_cmd curl
  local tag
  tag="$(curl -fsSL "https://api.github.com/repos/$REPOSITORY/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)"
  [[ -n "$tag" ]] || {
    echo "Unable to detect the latest release tag for $REPOSITORY" >&2
    exit 1
  }
  printf '%s\n' "$tag"
}

bootstrap_release() {
  need_cmd curl
  need_cmd tar
  need_cmd mktemp

  local tag asset_suffix package_name archive_path package_root
  tag="$(resolve_release_tag)"
  asset_suffix="$(detect_asset_suffix)"
  package_name="noders-anytls-${tag}-${asset_suffix}"
  TMP_ROOT="$(mktemp -d)"
  archive_path="$TMP_ROOT/${package_name}.tar.gz"

  echo "Downloading ${package_name}.tar.gz from GitHub Release ${tag}"
  curl -fL -o "$archive_path" "https://github.com/${REPOSITORY}/releases/download/${tag}/${package_name}.tar.gz"
  tar -xzf "$archive_path" -C "$TMP_ROOT"
  package_root="$TMP_ROOT/$package_name"
  [[ -d "$package_root" ]] || {
    echo "Release package layout is invalid: $package_root not found" >&2
    exit 1
  }

  "$package_root/upgrade.sh" "$@"
}

ensure_existing_installation() {
  [[ -x "$PREFIX/bin/noders-anytls" ]] || {
    echo "Existing installation not found at $PREFIX/bin/noders-anytls" >&2
    echo "Use scripts/install.sh for first-time installation." >&2
    exit 1
  }
  [[ -d "$CONFIG_DIR" ]] || {
    echo "Config directory $CONFIG_DIR was not found." >&2
    echo "Use scripts/install.sh for first-time installation." >&2
    exit 1
  }
}

discover_units() {
  DISCOVERED_UNITS=()

  if ! command -v systemctl >/dev/null 2>&1; then
    return
  fi

  local unit_path unit_name
  shopt -s nullglob
  for unit_path in /etc/systemd/system/${SERVICE_NAME}.service /etc/systemd/system/${SERVICE_NAME}-*.service; do
    [[ -f "$unit_path" ]] || continue
    unit_name="$(basename "$unit_path" .service)"
    DISCOVERED_UNITS+=("$unit_name")
  done
  shopt -u nullglob
}

discover_active_units() {
  ACTIVE_UNITS=()
  if ! command -v systemctl >/dev/null 2>&1; then
    return
  fi

  local unit_name
  for unit_name in "${DISCOVERED_UNITS[@]}"; do
    if systemctl is-active --quiet "$unit_name"; then
      ACTIVE_UNITS+=("$unit_name")
    fi
  done
}

backup_current_binary() {
  need_cmd mktemp
  TMP_ROOT="${TMP_ROOT:-$(mktemp -d)}"
  BACKUP_BINARY="$TMP_ROOT/noders-anytls.previous"
  cp "$PREFIX/bin/noders-anytls" "$BACKUP_BINARY"
}

restore_previous_binary() {
  [[ -n "$BACKUP_BINARY" && -f "$BACKUP_BINARY" ]] || return 0
  install -m 0755 "$BACKUP_BINARY" "$PREFIX/bin/noders-anytls"
}

install_from_bundle() {
  local staging_dir
  staging_dir="$1"

  install -d "$PREFIX/bin"
  install -m 0755 "$staging_dir/noders-anytls" "$PREFIX/bin/noders-anytls"
}

restart_active_units() {
  [[ "$NO_RESTART" -eq 0 ]] || {
    echo "Binary upgraded; service restart skipped because --no-restart was used."
    return 0
  }

  if ! command -v systemctl >/dev/null 2>&1; then
    echo "Binary upgraded; systemd not detected, so services were not restarted."
    return 0
  fi

  if [[ "$(id -u)" -ne 0 ]]; then
    echo "Binary upgraded; run as root if you want the upgrader to restart services automatically."
    return 0
  fi

  if [[ ${#DISCOVERED_UNITS[@]} -eq 0 ]]; then
    echo "Binary upgraded; no NodeRS-AnyTLS systemd units were found."
    return 0
  fi

  systemctl daemon-reload

  if [[ ${#ACTIVE_UNITS[@]} -eq 0 ]]; then
    echo "Binary upgraded; no active NodeRS-AnyTLS services needed a restart."
    return 0
  fi

  local unit_name
  for unit_name in "${ACTIVE_UNITS[@]}"; do
    echo "Restarting $unit_name"
    if ! systemctl restart "$unit_name"; then
      echo "Restart failed for $unit_name; rolling binary back." >&2
      restore_previous_binary
      systemctl daemon-reload >/dev/null 2>&1 || true
      for unit_name in "${ACTIVE_UNITS[@]}"; do
        systemctl restart "$unit_name" >/dev/null 2>&1 || true
      done
      exit 1
    fi
  done
}

print_summary() {
  local unit_name
  cat <<EOF
Upgraded NodeRS-AnyTLS
  Binary: $PREFIX/bin/noders-anytls
  Config: $CONFIG_DIR
EOF

  if [[ "$NO_RESTART" -eq 1 ]]; then
    echo "  Restart: skipped"
    return
  fi

  if [[ ${#ACTIVE_UNITS[@]} -eq 0 ]]; then
    echo "  Restart: no active services"
    return
  fi

  for unit_name in "${ACTIVE_UNITS[@]}"; do
    echo "  Restarted: $unit_name"
  done
}

main() {
  parse_args "$@"
  require_linux

  if ! release_layout_present; then
    bootstrap_release "$@"
    return
  fi

  ensure_existing_installation
  discover_units
  discover_active_units
  backup_current_binary
  install_from_bundle "$SCRIPT_DIR"
  restart_active_units
  print_summary
}

main "$@"
