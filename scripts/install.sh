#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="MoeclubM/NodeRS-AnyTLS"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PREFIX="/usr/local"
CONFIG_DIR="/etc/noders/anytls"
STATE_DIR="/var/lib/noders/anytls"
SERVICE_NAME="noders-anytls"
SERVICE_USER="noders-anytls"
VERSION="latest"
ACME_EMAIL=""
ACME_CHALLENGE_LISTEN="[::]:80"
TLS_SERVER_NAME=""
DNS_RESOLVER="system"
IP_STRATEGY="system"
SELF_SIGNED=0
SELF_SIGNED_DAYS=3650
NO_SERVICE=0
UNINSTALL=0
REMOVE_ALL=0
CERT_PATH=""
KEY_PATH=""
PANEL_URL=""
PANEL_TOKEN=""
PANEL_NODE_ID=""
TMP_ROOT=""
declare -a XBOARD_SPECS=()
declare -a GENERATED_CONFIGS=()
declare -a INSTALLED_SERVICES=()
declare -a TARGET_NODE_IDS=()

cleanup() {
  if [[ -n "$TMP_ROOT" && -d "$TMP_ROOT" ]]; then
    rm -rf "$TMP_ROOT"
  fi
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
Usage: install.sh [options]

Install mode:
  The script can run directly from the repo/raw URL and will download the Linux
  release bundle automatically. If it is already running inside an unpacked
  release bundle, it installs from local files without downloading again.

Uninstall mode:
  Pass `--uninstall` to remove one node or the whole installation.

Options:
  --version <tag>             Release tag to install, default: latest
  --prefix <path>             Binary installation prefix, default: /usr/local
  --config-dir <path>         Config directory, default: /etc/noders/anytls
  --state-dir <path>          Working directory, default: /var/lib/noders/anytls
  --panel-url <url>           Single-node Xboard API address
  --panel-token <token>       Single-node Xboard server_token
  --node-id <id>              Single-node Xboard node id
  --xboard <url> <token> <id> Add one Xboard node triplet; may be repeated
  --server-name <fqdn>        Override local tls.server_name and auto-issue ACME for it
  --self-signed               Generate a self-signed certificate per node and disable ACME
  --self-signed-days <days>   Validity for generated self-signed certs, default: 3650
  --cert-file <path>          Use an existing certificate file and disable ACME
  --key-file <path>           Use an existing private key file and disable ACME
  --acme-email <mailbox>      Contact email for ACME account registration
  --dns-resolver <value>      Outbound DNS: system or a custom nameserver like 1.1.1.1
  --ip-strategy <value>       Outbound IP order: system, prefer_ipv4, prefer_ipv6
  --acme-challenge-listen <addr>
                              HTTP-01 listener address, default: [::]:80
  --uninstall                 Remove installed service(s), binary, and related files
  --all                       Used with --uninstall to remove all nodes and all data
  --no-service                Skip systemd service installation
  -h, --help                  Show this help message

Examples:
  bash install.sh --panel-url https://api.example.com --panel-token token --node-id 1
  bash install.sh --panel-url https://api.example.com --panel-token token --node-id 1 --server-name node.example.com
  bash install.sh --panel-url https://api.example.com --panel-token token --node-id 1 --self-signed --server-name node.example.com
  bash install.sh --panel-url https://api.example.com --panel-token token --node-id 1 --cert-file /path/fullchain.pem --key-file /path/privkey.pem
  bash install.sh --xboard https://api.example.com tokenA 1 --xboard https://api.example.com tokenB 2
  bash install.sh --panel-url https://api.example.com --panel-token token --node-id 171 --uninstall
  bash install.sh --uninstall --all
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
    echo "This installer only supports Linux." >&2
    exit 1
  fi
}

normalize_paths() {
  :
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
      --state-dir)
        STATE_DIR="$2"
        shift 2
        ;;
      --panel-url)
        PANEL_URL="$2"
        shift 2
        ;;
      --panel-token)
        PANEL_TOKEN="$2"
        shift 2
        ;;
      --node-id)
        PANEL_NODE_ID="$2"
        TARGET_NODE_IDS+=("$2")
        shift 2
        ;;
      --xboard)
        XBOARD_SPECS+=("$2|$3|$4")
        TARGET_NODE_IDS+=("$4")
        shift 4
        ;;
      --cert-file)
        CERT_PATH="$2"
        shift 2
        ;;
      --key-file)
        KEY_PATH="$2"
        shift 2
        ;;
      --acme-email)
        ACME_EMAIL="$2"
        shift 2
        ;;
      --server-name)
        TLS_SERVER_NAME="$2"
        shift 2
        ;;
      --self-signed)
        SELF_SIGNED=1
        shift
        ;;
      --self-signed-days)
        SELF_SIGNED_DAYS="$2"
        shift 2
        ;;
      --dns-resolver)
        DNS_RESOLVER="$2"
        shift 2
        ;;
      --ip-strategy)
        IP_STRATEGY="$2"
        shift 2
        ;;
      --acme-challenge-listen)
        ACME_CHALLENGE_LISTEN="$2"
        shift 2
        ;;
      --uninstall)
        UNINSTALL=1
        shift
        ;;
      --all)
        REMOVE_ALL=1
        shift
        ;;
      --no-service)
        NO_SERVICE=1
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

validate_args() {
  if [[ -n "$PANEL_URL" || -n "$PANEL_TOKEN" || -n "$PANEL_NODE_ID" ]]; then
    if [[ -z "$PANEL_URL" || -z "$PANEL_TOKEN" || -z "$PANEL_NODE_ID" ]]; then
      echo "--panel-url, --panel-token and --node-id must be provided together." >&2
      exit 1
    fi
    XBOARD_SPECS+=("$PANEL_URL|$PANEL_TOKEN|$PANEL_NODE_ID")
  fi

  if [[ -n "$CERT_PATH" || -n "$KEY_PATH" ]]; then
    if [[ -z "$CERT_PATH" || -z "$KEY_PATH" ]]; then
      echo "--cert-file and --key-file must be provided together." >&2
      exit 1
    fi
    if [[ ! -f "$CERT_PATH" ]]; then
      echo "Certificate file not found: $CERT_PATH" >&2
      exit 1
    fi
    if [[ ! -f "$KEY_PATH" ]]; then
      echo "Private key file not found: $KEY_PATH" >&2
      exit 1
    fi
  fi

  if [[ "$SELF_SIGNED" -eq 1 && ( -n "$CERT_PATH" || -n "$KEY_PATH" ) ]]; then
    echo "--self-signed cannot be used together with --cert-file/--key-file." >&2
    exit 1
  fi

  [[ "$SELF_SIGNED_DAYS" =~ ^[0-9]+$ ]] || {
    echo "--self-signed-days must be a positive integer." >&2
    exit 1
  }
  if [[ "$SELF_SIGNED_DAYS" -lt 1 ]]; then
    echo "--self-signed-days must be at least 1." >&2
    exit 1
  fi

  if [[ "$UNINSTALL" -eq 1 ]]; then
    return
  fi

  if [[ ${#XBOARD_SPECS[@]} -eq 0 ]]; then
    echo "At least one node is required; pass --panel-url/--panel-token/--node-id or --xboard." >&2
    exit 1
  fi

  if [[ ${#XBOARD_SPECS[@]} -gt 1 && -n "$TLS_SERVER_NAME" ]]; then
    echo "--server-name applies to every node in this install invocation." >&2
  fi

  if [[ ${#XBOARD_SPECS[@]} -gt 1 && ( -n "$CERT_PATH" || -n "$KEY_PATH" ) ]]; then
    echo "--cert-file/--key-file apply to every node in this install invocation." >&2
  fi

  if [[ -n "$TLS_SERVER_NAME" && ( -n "$CERT_PATH" || -n "$KEY_PATH" ) ]]; then
    echo "--server-name only affects local SNI when using --cert-file/--key-file; ACME stays disabled." >&2
  fi
}

release_layout_present() {
  [[ -f "$SCRIPT_DIR/noders-anytls" ]] &&
  [[ -f "$SCRIPT_DIR/config.example.toml" ]] &&
  [[ -f "$SCRIPT_DIR/packaging/systemd/noders-anytls.service" ]]
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

  local tag package_name archive_path package_root bootstrap_args
  tag="$(resolve_release_tag)"
  package_name="noders-anytls-${tag}-linux-amd64"
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

  bootstrap_args=()
  while [[ $# -gt 0 ]]; do
    bootstrap_args+=("$1")
    shift
  done

  "$package_root/install.sh" "${bootstrap_args[@]}"
}

ensure_directories() {
  install -d "$PREFIX/bin" "$CONFIG_DIR" "$STATE_DIR" "$CONFIG_DIR/nodes"
}

sed_escape() {
  printf '%s' "$1" | sed -e 's/[\/&]/\\&/g'
}

render_config_file() {
  local template_path target_path panel_url panel_token node_id cert_path key_path tls_server_name acme_enabled acme_domain account_key_path escaped_url escaped_token escaped_node_id escaped_cert escaped_key escaped_tls_server_name escaped_dns_resolver escaped_ip_strategy escaped_acme_domain escaped_acme_email escaped_acme_challenge escaped_account_key
  template_path="$1"
  target_path="$2"
  panel_url="$3"
  panel_token="$4"
  node_id="$5"
  cert_path="$6"
  key_path="$7"
  tls_server_name="$8"
  acme_enabled="$9"
  acme_domain="${10}"
  account_key_path="${11}"

  escaped_url="$(sed_escape "$panel_url")"
  escaped_token="$(sed_escape "$panel_token")"
  escaped_node_id="$(sed_escape "$node_id")"
  escaped_cert="$(sed_escape "$cert_path")"
  escaped_key="$(sed_escape "$key_path")"
  escaped_tls_server_name="$(sed_escape "$tls_server_name")"
  escaped_dns_resolver="$(sed_escape "$DNS_RESOLVER")"
  escaped_ip_strategy="$(sed_escape "$IP_STRATEGY")"
  escaped_acme_domain="$(sed_escape "$acme_domain")"
  escaped_acme_email="$(sed_escape "$ACME_EMAIL")"
  escaped_acme_challenge="$(sed_escape "$ACME_CHALLENGE_LISTEN")"
  escaped_account_key="$(sed_escape "$account_key_path")"

  sed \
    -e "s#url = \"https://xboard.example.com\"#url = \"$escaped_url\"#g" \
    -e "s#token = \"replace-me\"#token = \"$escaped_token\"#g" \
    -e "s#node_id = 1#node_id = $escaped_node_id#g" \
    -e "s#cert_path = \"cert.pem\"#cert_path = \"$escaped_cert\"#g" \
    -e "s#key_path = \"key.pem\"#key_path = \"$escaped_key\"#g" \
    -e "s#server_name = \"\"#server_name = \"$escaped_tls_server_name\"#g" \
    -e "s#dns_resolver = \"system\"#dns_resolver = \"$escaped_dns_resolver\"#g" \
    -e "s#ip_strategy = \"system\"#ip_strategy = \"$escaped_ip_strategy\"#g" \
    -e "s#enabled = false#enabled = $acme_enabled#g" \
    -e "s#email = \"admin@example.com\"#email = \"$escaped_acme_email\"#g" \
    -e "s#domain = \"node.example.com\"#domain = \"$escaped_acme_domain\"#g" \
    -e "s#challenge_listen = \"\[::\]:80\"#challenge_listen = \"$escaped_acme_challenge\"#g" \
    -e "s#account_key_path = \"acme-account.pem\"#account_key_path = \"$escaped_account_key\"#g" \
    "$template_path" > "$target_path"
}

fetch_remote_server_name() {
  local panel_url panel_token node_id endpoint response http_code response_body server_name
  panel_url="${1%/}"
  panel_token="$2"
  node_id="$3"
  endpoint="$panel_url/api/v1/server/UniProxy/config"

  need_cmd curl
  if ! response="$(curl -sSL --get \
    --write-out $'\n%{http_code}' \
    --data-urlencode "token=$panel_token" \
    --data-urlencode "node_id=$node_id" \
    --data-urlencode "node_type=anytls" \
    "$endpoint")"; then
    echo "Unable to query $endpoint while discovering server_name." >&2
    return 1
  fi
  http_code="${response##*$'\n'}"
  response_body="${response%$'\n'*}"
  if [[ "$http_code" != "200" ]]; then
    echo "Xboard rejected automatic server_name discovery with HTTP $http_code from $endpoint." >&2
    if [[ "$http_code" == "403" ]]; then
      echo "This endpoint requires Xboard's global server_token; make sure --panel-token is admin_setting('server_token'), not a node key or user token." >&2
    fi
    if [[ -n "$response_body" ]]; then
      echo "Response body: $response_body" >&2
    fi
    echo "You can bypass auto-discovery by passing --server-name explicitly." >&2
    return 1
  fi
  response="$response_body"
  server_name="$(printf '%s' "$response" | tr -d '\n' | sed -n 's/.*"server_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  printf '%s\n' "$server_name"
}

node_cert_path() {
  printf '%s\n' "${CONFIG_DIR%/}/acme-cert-${1}.pem"
}

node_key_path() {
  printf '%s\n' "${CONFIG_DIR%/}/acme-key-${1}.pem"
}

node_account_key_path() {
  printf '%s\n' "${CONFIG_DIR%/}/acme-account-${1}.pem"
}

node_self_signed_cert_path() {
  printf '%s\n' "${CONFIG_DIR%/}/selfsigned-cert-${1}.pem"
}

node_self_signed_key_path() {
  printf '%s\n' "${CONFIG_DIR%/}/selfsigned-key-${1}.pem"
}

node_config_path() {
  printf '%s\n' "${CONFIG_DIR%/}/nodes/${1}.toml"
}

generate_self_signed_certificate() {
  local server_name cert_path key_path tmp_config cert_dir
  server_name="$1"
  cert_path="$2"
  key_path="$3"
  cert_dir="$(dirname "$cert_path")"

  need_cmd openssl
  install -d "$cert_dir"
  tmp_config="$(mktemp)"
  trap 'rm -f "$tmp_config"' RETURN
  cat > "$tmp_config" <<EOF
[req]
distinguished_name = req_dn
x509_extensions = v3_req
prompt = no

[req_dn]
CN = $server_name

[v3_req]
subjectAltName = DNS:$server_name
EOF
  openssl req -x509 -newkey rsa:2048 -nodes \
    -days "$SELF_SIGNED_DAYS" \
    -config "$tmp_config" \
    -extensions v3_req \
    -keyout "$key_path" \
    -out "$cert_path" >/dev/null 2>&1
  trap - RETURN
  rm -f "$tmp_config"
  chmod 600 "$key_path"
  chmod 644 "$cert_path"
}

determine_tls_settings() {
  local panel_url panel_token node_id discovered_domain selected_server_name cert_path key_path acme_enabled acme_domain account_key_path
  panel_url="$1"
  panel_token="$2"
  node_id="$3"
  selected_server_name="$TLS_SERVER_NAME"
  account_key_path="$(node_account_key_path "$node_id")"

  if [[ -n "$CERT_PATH" && -n "$KEY_PATH" ]]; then
    printf '%s|%s|%s|false|node.example.com|%s\n' "$CERT_PATH" "$KEY_PATH" "$selected_server_name" "$account_key_path"
    return
  fi

  if [[ -z "$selected_server_name" ]]; then
    if ! discovered_domain="$(fetch_remote_server_name "$panel_url" "$panel_token" "$node_id")"; then
      exit 1
    fi
    selected_server_name="$discovered_domain"
  fi

  [[ -n "$selected_server_name" ]] || {
    echo "Unable to discover server_name for node $node_id; pass --server-name explicitly or configure Xboard server_name." >&2
    exit 1
  }

  if [[ "$SELF_SIGNED" -eq 1 ]]; then
    cert_path="$(node_self_signed_cert_path "$node_id")"
    key_path="$(node_self_signed_key_path "$node_id")"
    generate_self_signed_certificate "$selected_server_name" "$cert_path" "$key_path"
    printf '%s|%s|%s|false|node.example.com|%s\n' "$cert_path" "$key_path" "$selected_server_name" "$account_key_path"
    return
  fi

  cert_path="$(node_cert_path "$node_id")"
  key_path="$(node_key_path "$node_id")"
  acme_enabled=true
  acme_domain="$selected_server_name"
  printf '%s|%s|%s|%s|%s|%s\n' "$cert_path" "$key_path" "$selected_server_name" "$acme_enabled" "$acme_domain" "$account_key_path"
}

write_xboard_configs() {
  local staging_dir template_path spec panel_url panel_token node_id tls_settings cert_path key_path tls_server_name config_path acme_enabled acme_domain account_key_path rest
  staging_dir="$1"
  template_path="$staging_dir/config.example.toml"

  for spec in "${XBOARD_SPECS[@]}"; do
    IFS='|' read -r panel_url panel_token node_id <<<"$spec"
    tls_settings="$(determine_tls_settings "$panel_url" "$panel_token" "$node_id")"
    cert_path="${tls_settings%%|*}"
    rest="${tls_settings#*|}"
    key_path="${rest%%|*}"
    rest="${rest#*|}"
    tls_server_name="${rest%%|*}"
    rest="${rest#*|}"
    acme_enabled="${rest%%|*}"
    rest="${rest#*|}"
    acme_domain="${rest%%|*}"
    account_key_path="${rest#*|}"
    config_path="$(node_config_path "$node_id")"
    render_config_file \
      "$template_path" \
      "$config_path" \
      "$panel_url" \
      "$panel_token" \
      "$node_id" \
      "$cert_path" \
      "$key_path" \
      "$tls_server_name" \
      "$acme_enabled" \
      "$acme_domain" \
      "$account_key_path"
    GENERATED_CONFIGS+=("$config_path")
  done
}

render_service_file() {
  local staging_dir target config_path template shell_path
  staging_dir="$1"
  target="$2"
  config_path="$3"
  template="$staging_dir/packaging/systemd/noders-anytls.service"
  [[ -f "$template" ]] || {
    echo "Missing service template at $template" >&2
    exit 1
  }
  shell_path="/usr/sbin/nologin"
  if [[ ! -x "$shell_path" ]]; then
    shell_path="/sbin/nologin"
  fi
  sed \
    -e "s#__BINARY__#$PREFIX/bin/noders-anytls#g" \
    -e "s#__CONFIG__#$config_path#g" \
    -e "s#__STATE_DIR__#$STATE_DIR#g" \
    -e "s#__USER__#$SERVICE_USER#g" \
    -e "s#__SHELL__#$shell_path#g" \
    "$template" > "$target"
}

install_service() {
  local staging_dir spec node_id config_path unit_path service_unit
  staging_dir="$1"
  [[ "$NO_SERVICE" -eq 0 ]] || return 0
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "Skipping service installation because the script is not running as root."
    return 0
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemd not detected; service installation skipped."
    return 0
  fi
  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --home "$STATE_DIR" --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null || \
      useradd --system --home "$STATE_DIR" --shell /sbin/nologin "$SERVICE_USER"
  fi
  chown -R "$SERVICE_USER":"$SERVICE_USER" "$STATE_DIR" "$CONFIG_DIR"

  for spec in "${XBOARD_SPECS[@]}"; do
    IFS='|' read -r _ _ node_id <<<"$spec"
    config_path="$(node_config_path "$node_id")"
    service_unit="${SERVICE_NAME}-${node_id}"
    unit_path="/etc/systemd/system/${service_unit}.service"
    render_service_file "$staging_dir" "$unit_path" "$config_path"
    INSTALLED_SERVICES+=("$service_unit")
  done

  systemctl daemon-reload
  for service_unit in "${INSTALLED_SERVICES[@]}"; do
    systemctl enable "$service_unit" >/dev/null 2>&1 || true
    systemctl restart "$service_unit" >/dev/null 2>&1 || systemctl start "$service_unit"
  done
}

stop_disable_unit() {
  local unit_name
  unit_name="$1"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "$unit_name" >/dev/null 2>&1 || true
  fi
  rm -f "/etc/systemd/system/${unit_name}.service"
}

remove_single_node() {
  local node_id config_path cert_path key_path legacy_cert_path legacy_key_path account_key_path self_signed_cert_path self_signed_key_path unit_name
  node_id="$1"
  config_path="$(node_config_path "$node_id")"
  cert_path="$(node_cert_path "$node_id")"
  key_path="$(node_key_path "$node_id")"
  legacy_cert_path="${CONFIG_DIR%/}/cert-${node_id}.pem"
  legacy_key_path="${CONFIG_DIR%/}/key-${node_id}.pem"
  account_key_path="$(node_account_key_path "$node_id")"
  self_signed_cert_path="$(node_self_signed_cert_path "$node_id")"
  self_signed_key_path="$(node_self_signed_key_path "$node_id")"
  unit_name="${SERVICE_NAME}-${node_id}"

  stop_disable_unit "$unit_name"
  rm -f "$config_path" "$cert_path" "$key_path" "$legacy_cert_path" "$legacy_key_path" "$account_key_path" "$self_signed_cert_path" "$self_signed_key_path"
}

remove_all_nodes() {
  local unit_path unit_name
  if command -v systemctl >/dev/null 2>&1; then
    for unit_path in /etc/systemd/system/${SERVICE_NAME}.service /etc/systemd/system/${SERVICE_NAME}-*.service; do
      [[ -e "$unit_path" ]] || continue
      unit_name="$(basename "$unit_path" .service)"
      systemctl disable --now "$unit_name" >/dev/null 2>&1 || true
      rm -f "$unit_path"
    done
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  rm -f "$PREFIX/bin/noders-anytls"
  rm -rf "$CONFIG_DIR" "$STATE_DIR"
  if id "$SERVICE_USER" >/dev/null 2>&1; then
    userdel "$SERVICE_USER" >/dev/null 2>&1 || true
  fi
}

uninstall() {
  require_linux
  normalize_paths

  if [[ "$REMOVE_ALL" -eq 1 || ${#TARGET_NODE_IDS[@]} -eq 0 ]]; then
    remove_all_nodes
    echo "Removed all NodeRS-AnyTLS nodes, configs, services, and binary."
    return
  fi

  for node_id in "${TARGET_NODE_IDS[@]}"; do
    remove_single_node "$node_id"
    echo "Removed node ${node_id}."
  done
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
}

print_summary() {
  local service_unit tls_summary
  if [[ "$SELF_SIGNED" -eq 1 ]]; then
    tls_summary="Self-signed certificates generated locally from --server-name or Xboard server_name"
  elif [[ -n "$CERT_PATH" && -n "$KEY_PATH" ]]; then
    tls_summary="Using existing certificate files from --cert-file/--key-file"
  else
    tls_summary="Auto ACME from local --server-name or Xboard server_name"
  fi
  cat <<EOF
Installed NodeRS-AnyTLS
  Binary: $PREFIX/bin/noders-anytls
  State:  $STATE_DIR
  TLS:    $tls_summary
EOF

  for config_path in "${GENERATED_CONFIGS[@]}"; do
    echo "  Config: $config_path"
  done
  for service_unit in "${INSTALLED_SERVICES[@]}"; do
    echo "  Service: $service_unit"
  done
}

install_from_bundle() {
  local staging_dir
  staging_dir="$1"

  ensure_directories
  install -m 0755 "$staging_dir/noders-anytls" "$PREFIX/bin/noders-anytls"
  write_xboard_configs "$staging_dir"
  install_service "$staging_dir"
  print_summary
}

main() {
  parse_args "$@"
  validate_args

  if [[ "$UNINSTALL" -eq 1 ]]; then
    uninstall
    return
  fi

  require_linux
  normalize_paths

  if ! release_layout_present; then
    bootstrap_release "$@"
    return
  fi

  install_from_bundle "$SCRIPT_DIR"
}

main "$@"
