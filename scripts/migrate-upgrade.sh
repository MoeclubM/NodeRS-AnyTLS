#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="MoeclubM/NodeRS-AnyTLS"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
COMMON_LIB_PATH="$SCRIPT_DIR/lib/install-common.sh"
PREFIX="/usr/local"
CONFIG_DIR="/etc/noders/anytls"
SERVICE_NAME="noders-anytls"
OPENRC_DIR="/etc/init.d"
VERSION="latest"
NO_RESTART=0
TMP_ROOT=""
BACKUP_BINARY=""
BACKUP_DIR=""
SERVICE_MANAGER=""
BUNDLE_DIR=""
RESTART_STATE="pending"
declare -a DISCOVERED_UNITS=()
declare -a ACTIVE_UNITS=()
declare -a RESTARTED_UNITS=()
declare -a MIGRATED_ITEMS=()
declare -a WARNING_MESSAGES=()

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
Usage: migrate-upgrade.sh [options]

Upgrade NodeRS-AnyTLS in place and migrate known legacy Linux install layout.
This currently cleans up:
  - legacy cert-<node_id>.pem / key-<node_id>.pem names
  - config files that still point at those legacy certificate paths
  - obsolete tls.server_name lines in node config files

Options:
  --version <tag>       Release tag to install, default: latest
  --prefix <path>       Binary prefix, default: /usr/local
  --config-dir <path>   Config directory, default: /etc/noders/anytls
  --no-restart          Replace the binary and migrate files, but do not restart services
  -h, --help            Show this help message

Examples:
  bash migrate-upgrade.sh --version v0.0.26
  bash migrate-upgrade.sh --version v0.0.26 --no-restart
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
    echo "This migrator only supports Linux." >&2
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
  [[ -f "$SCRIPT_DIR/noders-anytls" ]] &&
  [[ -f "$COMMON_LIB_PATH" ]]
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

  local tag asset_suffix package_name archive_path package_root bundle_common_lib
  tag="$(resolve_release_tag)"
  asset_suffix="$(detect_asset_suffix)"
  package_name="noders-anytls-${tag}-${asset_suffix}"
  TMP_ROOT="$(mktemp -d)"
  archive_path="$TMP_ROOT/${package_name}.tar.gz"

  echo "Downloading ${package_name}.tar.gz from GitHub Release ${tag}"
  curl -fL -o "$archive_path" "https://github.com/${REPOSITORY}/releases/download/${tag}/${package_name}.tar.gz"
  tar -xzf "$archive_path" -C "$TMP_ROOT"
  package_root="$TMP_ROOT/$package_name"
  bundle_common_lib="$package_root/lib/install-common.sh"
  [[ -d "$package_root" && -f "$bundle_common_lib" && -f "$package_root/noders-anytls" ]] || {
    echo "Release package layout is invalid under $package_root" >&2
    exit 1
  }
  BUNDLE_DIR="$package_root"
  COMMON_LIB_PATH="$bundle_common_lib"
  # shellcheck source=/dev/null
  source "$COMMON_LIB_PATH"
}

ensure_existing_installation() {
  [[ -x "$PREFIX/bin/noders-anytls" ]] || {
    echo "Existing installation not found at $PREFIX/bin/noders-anytls" >&2
    echo "Use scripts/install.sh or scripts/install-openrc.sh for first-time installation." >&2
    exit 1
  }
  [[ -d "$CONFIG_DIR" ]] || {
    echo "Config directory $CONFIG_DIR was not found." >&2
    echo "Use scripts/install.sh or scripts/install-openrc.sh for first-time installation." >&2
    exit 1
  }
}

discover_systemd_units() {
  local unit_path unit_name
  shopt -s nullglob
  for unit_path in /etc/systemd/system/${SERVICE_NAME}.service /etc/systemd/system/${SERVICE_NAME}-*.service; do
    [[ -f "$unit_path" ]] || continue
    unit_name="$(basename "$unit_path" .service)"
    DISCOVERED_UNITS+=("$unit_name")
  done
  shopt -u nullglob
  if [[ ${#DISCOVERED_UNITS[@]} -gt 0 ]]; then
    SERVICE_MANAGER="systemd"
  fi
}

discover_openrc_units() {
  local unit_path unit_name
  shopt -s nullglob
  for unit_path in "${OPENRC_DIR%/}/${SERVICE_NAME}-"*; do
    [[ -f "$unit_path" ]] || continue
    unit_name="$(basename "$unit_path")"
    DISCOVERED_UNITS+=("$unit_name")
  done
  shopt -u nullglob
  if [[ ${#DISCOVERED_UNITS[@]} -gt 0 ]]; then
    SERVICE_MANAGER="openrc"
  fi
}

discover_units() {
  DISCOVERED_UNITS=()
  ACTIVE_UNITS=()
  SERVICE_MANAGER=""

  if command -v systemctl >/dev/null 2>&1; then
    discover_systemd_units
  fi

  if [[ -z "$SERVICE_MANAGER" ]] && command -v rc-service >/dev/null 2>&1; then
    discover_openrc_units
  fi
}

discover_active_units() {
  ACTIVE_UNITS=()

  local unit_name
  case "$SERVICE_MANAGER" in
    systemd)
      for unit_name in "${DISCOVERED_UNITS[@]}"; do
        if systemctl is-active --quiet "$unit_name"; then
          ACTIVE_UNITS+=("$unit_name")
        fi
      done
      ;;
    openrc)
      for unit_name in "${DISCOVERED_UNITS[@]}"; do
        if rc-service "$unit_name" status >/dev/null 2>&1; then
          ACTIVE_UNITS+=("$unit_name")
        fi
      done
      ;;
  esac
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

ensure_backup_dir() {
  [[ -n "$BACKUP_DIR" ]] && return 0
  BACKUP_DIR="${CONFIG_DIR%/}/migration-backups/$(date +%Y%m%d-%H%M%S)"
  install -d "$BACKUP_DIR"
}

backup_file() {
  local src backup_name
  src="$1"
  backup_name="$2"
  [[ -f "$src" ]] || return 0
  ensure_backup_dir
  cp -p "$src" "${BACKUP_DIR%/}/$backup_name"
}

record_migration() {
  MIGRATED_ITEMS+=("$1")
}

record_warning() {
  WARNING_MESSAGES+=("$1")
}

legacy_cert_path() {
  printf '%s\n' "${CONFIG_DIR%/}/cert-${1}.pem"
}

legacy_key_path() {
  printf '%s\n' "${CONFIG_DIR%/}/key-${1}.pem"
}

prune_duplicate_or_move_legacy_file() {
  local old_path new_path label backup_name
  old_path="$1"
  new_path="$2"
  label="$3"
  backup_name="$4"

  if [[ ! -f "$old_path" ]]; then
    return 1
  fi

  if [[ -f "$new_path" ]]; then
    if cmp -s "$old_path" "$new_path"; then
      backup_file "$old_path" "$backup_name"
      rm -f "$old_path"
      record_migration "Removed duplicate legacy ${label}: $old_path"
      return 0
    fi

    record_warning "Skipped conflicting legacy ${label}: $old_path already differs from $new_path"
    return 2
  fi

  backup_file "$old_path" "$backup_name"
  mv "$old_path" "$new_path"
  record_migration "Renamed legacy ${label}: $old_path -> $new_path"
  return 0
}

rewrite_node_config() {
  local config_path node_id old_cert old_key new_cert new_key tmp_path changed saw_old_cert_ref saw_old_key_ref saw_server_name
  local line indent key_name value suffix
  config_path="$1"
  node_id="$2"
  old_cert="$(legacy_cert_path "$node_id")"
  old_key="$(legacy_key_path "$node_id")"
  new_cert="$(node_cert_path "$node_id")"
  new_key="$(node_key_path "$node_id")"
  tmp_path="$(mktemp)"
  changed=0
  saw_old_cert_ref=0
  saw_old_key_ref=0
  saw_server_name=0

  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^([[:space:]]*)server_name[[:space:]]*=.*$ ]]; then
      changed=1
      saw_server_name=1
      continue
    fi

    if [[ "$line" =~ ^([[:space:]]*)(cert_path|key_path)[[:space:]]*=[[:space:]]*\"([^\"]*)\"([[:space:]]*(#.*)?)$ ]]; then
      indent="${BASH_REMATCH[1]}"
      key_name="${BASH_REMATCH[2]}"
      value="${BASH_REMATCH[3]}"
      suffix="${BASH_REMATCH[4]}"

      if [[ "$key_name" == "cert_path" && "$value" == "$old_cert" && -f "$new_cert" ]]; then
        line="${indent}cert_path = \"${new_cert}\"${suffix}"
        changed=1
        saw_old_cert_ref=1
      elif [[ "$key_name" == "key_path" && "$value" == "$old_key" && -f "$new_key" ]]; then
        line="${indent}key_path = \"${new_key}\"${suffix}"
        changed=1
        saw_old_key_ref=1
      fi
    fi

    printf '%s\n' "$line" >> "$tmp_path"
  done < "$config_path"

  if [[ "$changed" -eq 1 ]]; then
    backup_file "$config_path" "config-${node_id}.toml"
    mv "$tmp_path" "$config_path"
    record_migration "Updated node config: $config_path"
  else
    rm -f "$tmp_path"
  fi

  if [[ "$saw_server_name" -eq 1 ]]; then
    record_migration "Removed obsolete tls.server_name from: $config_path"
  fi
  if [[ "$saw_old_cert_ref" -eq 1 ]]; then
    record_migration "Repointed legacy cert_path for node ${node_id}"
  elif grep -Fq "cert_path = \"$old_cert\"" "$config_path" 2>/dev/null; then
    record_warning "Config still points at legacy cert path for node ${node_id}: $config_path"
  fi
  if [[ "$saw_old_key_ref" -eq 1 ]]; then
    record_migration "Repointed legacy key_path for node ${node_id}"
  elif grep -Fq "key_path = \"$old_key\"" "$config_path" 2>/dev/null; then
    record_warning "Config still points at legacy key path for node ${node_id}: $config_path"
  fi
}

migrate_node_layout() {
  local config_path node_file node_id old_cert old_key new_cert new_key

  shopt -s nullglob
  for config_path in "${CONFIG_DIR%/}/nodes/"*.toml; do
    [[ -f "$config_path" ]] || continue
    node_file="$(basename "$config_path")"
    node_id="${node_file%.toml}"
    old_cert="$(legacy_cert_path "$node_id")"
    old_key="$(legacy_key_path "$node_id")"
    new_cert="$(node_cert_path "$node_id")"
    new_key="$(node_key_path "$node_id")"

    prune_duplicate_or_move_legacy_file "$old_cert" "$new_cert" "certificate" "cert-${node_id}.pem" || true
    prune_duplicate_or_move_legacy_file "$old_key" "$new_key" "private key" "key-${node_id}.pem" || true
    rewrite_node_config "$config_path" "$node_id"
  done
  shopt -u nullglob
}

report_orphan_legacy_files() {
  local legacy_path

  shopt -s nullglob
  for legacy_path in "${CONFIG_DIR%/}/cert-"*.pem "${CONFIG_DIR%/}/key-"*.pem; do
    [[ -f "$legacy_path" ]] || continue
    record_warning "Legacy file still present and was not migrated automatically: $legacy_path"
  done
  shopt -u nullglob
}

install_from_bundle() {
  local staging_dir
  staging_dir="$1"

  install -d "$PREFIX/bin"
  install -m 0755 "$staging_dir/noders-anytls" "$PREFIX/bin/noders-anytls"
}

restart_active_units() {
  RESTARTED_UNITS=()

  [[ "$NO_RESTART" -eq 0 ]] || {
    RESTART_STATE="skipped-no-restart"
    echo "Upgrade and migration finished; service restart skipped because --no-restart was used."
    return 0
  }

  if [[ "$(id -u)" -ne 0 ]]; then
    RESTART_STATE="skipped-non-root"
    echo "Upgrade and migration finished; run as root if you want automatic service restart."
    return 0
  fi

  if [[ ${#DISCOVERED_UNITS[@]} -eq 0 ]]; then
    RESTART_STATE="no-services"
    echo "Upgrade and migration finished; no NodeRS-AnyTLS services were found."
    return 0
  fi

  if [[ ${#ACTIVE_UNITS[@]} -eq 0 ]]; then
    RESTART_STATE="no-active-services"
    echo "Upgrade and migration finished; no active NodeRS-AnyTLS services needed a restart."
    return 0
  fi

  local unit_name
  case "$SERVICE_MANAGER" in
    systemd)
      systemctl daemon-reload
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
        RESTARTED_UNITS+=("$unit_name")
      done
      ;;
    openrc)
      for unit_name in "${ACTIVE_UNITS[@]}"; do
        echo "Restarting $unit_name"
        if ! rc-service "$unit_name" restart >/dev/null 2>&1; then
          echo "Restart failed for $unit_name; rolling binary back." >&2
          restore_previous_binary
          for unit_name in "${ACTIVE_UNITS[@]}"; do
            rc-service "$unit_name" restart >/dev/null 2>&1 || true
          done
          exit 1
        fi
        RESTARTED_UNITS+=("$unit_name")
      done
      ;;
  esac
  RESTART_STATE="restarted"
}

print_summary() {
  local unit_name
  cat <<EOF
Migrated NodeRS-AnyTLS
  Binary: $PREFIX/bin/noders-anytls
  Config: $CONFIG_DIR
EOF

  if [[ -n "$BACKUP_DIR" ]]; then
    echo "  Backup: $BACKUP_DIR"
  fi

  if [[ ${#MIGRATED_ITEMS[@]} -eq 0 ]]; then
    echo "  Migration: no legacy files or config entries needed changes"
  else
    echo "  Migration:"
    for unit_name in "${MIGRATED_ITEMS[@]}"; do
      echo "    - $unit_name"
    done
  fi

  case "$RESTART_STATE" in
    skipped-no-restart)
      echo "  Restart: skipped"
      ;;
    skipped-non-root)
      echo "  Restart: skipped because the migrator was not run as root"
      ;;
    no-services)
      echo "  Restart: no services found"
      ;;
    no-active-services)
      echo "  Restart: no active services"
      ;;
    restarted)
      for unit_name in "${RESTARTED_UNITS[@]}"; do
        echo "  Restarted: $unit_name"
      done
      ;;
    *)
      echo "  Restart: not attempted"
      ;;
  esac

  if [[ ${#WARNING_MESSAGES[@]} -gt 0 ]]; then
    echo "  Warnings:"
    for unit_name in "${WARNING_MESSAGES[@]}"; do
      echo "    - $unit_name"
    done
  fi
}

main() {
  local staging_dir
  parse_args "$@"
  require_linux

  if ! release_layout_present; then
    bootstrap_release
    staging_dir="$BUNDLE_DIR"
  else
    staging_dir="$SCRIPT_DIR"
  fi

  ensure_existing_installation
  discover_units
  discover_active_units
  backup_current_binary
  install_from_bundle "$staging_dir"
  migrate_node_layout
  report_orphan_legacy_files
  restart_active_units
  print_summary
}

main "$@"
