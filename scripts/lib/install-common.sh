#!/usr/bin/env bash

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

GNU_GLIBC_FLOOR="2.17"

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
        if (left_part > right_part) {
          exit 0;
        }
        if (left_part < right_part) {
          exit 1;
        }
      }
      exit 0;
    }
  '
}

detect_glibc_version() {
  if command -v getconf >/dev/null 2>&1; then
    getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}'
  fi
}

detect_linux_libc() {
  local glibc_version ldd_output
  glibc_version="$(detect_glibc_version)"
  if [[ -n "$glibc_version" ]]; then
    printf 'glibc\n'
    return
  fi

  if command -v ldd >/dev/null 2>&1; then
    ldd_output="$(ldd --version 2>&1 || true)"
    if printf '%s' "$ldd_output" | grep -qi 'musl'; then
      printf 'musl\n'
      return
    fi
    if printf '%s' "$ldd_output" | grep -qiE 'glibc|gnu libc'; then
      printf 'glibc\n'
      return
    fi
  fi

  if compgen -G '/lib/ld-musl-*.so.1' >/dev/null || compgen -G '/usr/lib/ld-musl-*.so.1' >/dev/null; then
    printf 'musl\n'
    return
  fi

  printf 'unknown\n'
}

detect_release_asset_suffix() {
  local arch libc_family glibc_version
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64)
      libc_family="$(detect_linux_libc)"
      if [[ "$libc_family" == "glibc" ]]; then
        glibc_version="$(detect_glibc_version)"
        if [[ -n "$glibc_version" ]] && version_at_least "$glibc_version" "$GNU_GLIBC_FLOOR"; then
          printf 'linux-amd64\n'
          return
        fi
        if [[ -n "$glibc_version" ]]; then
          echo "Detected glibc ${glibc_version}; falling back to linux-amd64-musl because GNU builds target glibc >= ${GNU_GLIBC_FLOOR}." >&2
        else
          echo "Detected glibc but could not determine the exact version; falling back to linux-amd64-musl for compatibility." >&2
        fi
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
      echo "Unsupported architecture for prebuilt releases: $arch" >&2
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
