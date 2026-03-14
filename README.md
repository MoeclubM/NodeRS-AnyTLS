# NodeRS-AnyTLS

Pure Rust AnyTLS node for Xboard `UniProxy`.

- Linux only
- Native Rust AnyTLS + UOT implementation
- Xboard `config / user / push / alive / alivelist / status` compatible
- Multi-user hot reload, device-limit control, per-user rate limiting
- Built-in ACME HTTP-01, TLS hot reload, dual-stack listen
- No `sing-box_mod`, subprocess core, or external protocol engine at runtime

## Quick Start

### Install one node

The installer automatically downloads the Linux release package, writes config under `/etc/noders/anytls`, creates the `systemd` service, enables it, and starts it.

By default it tries to fetch the node `server_name` from Xboard and uses it for embedded ACME HTTP-01 certificate issuance.

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- \
  --panel-url https://api.example.com \
  --panel-token server_token \
  --node-id 1
```

`--panel-token` must be the Xboard global `server_token` used by `/api/v1/server/UniProxy/*`.

### Install multiple nodes

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- \
  --xboard https://api.example.com server_token 1 \
  --xboard https://api.example.com server_token 2
```

### Install on Alpine / OpenRC / non-systemd containers

If the host does not provide `systemd` such as Alpine or many LXC containers, use the standalone OpenRC installer instead. The issue is the init system, not LXC itself. Linux installers now prefer the GNU build on `glibc` hosts and automatically fall back to the `musl` bundle on Alpine, other `musl` systems, or `glibc` older than `2.17`.

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install-openrc.sh | bash -s -- \
  --panel-url https://api.example.com \
  --panel-token server_token \
  --node-id 1
```

### Override local `server_name`

If you want to force a local SNI instead of using the one from Xboard, pass `--server-name`. This still uses automatic ACME issuance.

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- \
  --panel-url https://api.example.com \
  --panel-token server_token \
  --node-id 1 \
  --server-name node.example.com
```

### Generate a self-signed certificate

If you want the installer to generate a local self-signed certificate instead of using ACME or pre-existing files, pass `--self-signed`. The certificate CN and SAN use `--server-name` when provided, otherwise they fall back to the node `server_name` fetched from Xboard.

This mode requires `openssl` on the target Linux host.

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- \
  --panel-url https://api.example.com \
  --panel-token server_token \
  --node-id 1 \
  --server-name node.example.com \
  --self-signed
```

### Use existing certificate files

If you already have a certificate and key, pass both paths. In this mode the installer writes those paths into the config and does not enable ACME.

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- \
  --panel-url https://api.example.com \
  --panel-token server_token \
  --node-id 1 \
  --cert-file /etc/ssl/private/fullchain.pem \
  --key-file /etc/ssl/private/privkey.pem
```

### Set outbound DNS and IP preference

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- \
  --panel-url https://api.example.com \
  --panel-token server_token \
  --node-id 1 \
  --dns-resolver 1.1.1.1 \
  --ip-strategy prefer_ipv6
```

## Paths

- Binary: `/usr/local/bin/noders-anytls`
- Config root: `/etc/noders/anytls`
- Node config: `/etc/noders/anytls/nodes/<node_id>.toml`
- State: `/var/lib/noders/anytls`
- Service: `noders-anytls-<node_id>`

## Maintenance

### Check service status

```bash
systemctl status noders-anytls-1 --no-pager -l
```

### View recent logs

```bash
journalctl -u noders-anytls-1 -n 100 --no-pager
```

### Follow logs live

```bash
journalctl -u noders-anytls-1 -f
```

### Restart service

```bash
systemctl restart noders-anytls-1
```

### Start or stop service

```bash
systemctl start noders-anytls-1
systemctl stop noders-anytls-1
```

### Enable or disable auto start

```bash
systemctl enable noders-anytls-1
systemctl disable noders-anytls-1
```

### Check generated config

```bash
cat /etc/noders/anytls/nodes/1.toml
```

### OpenRC status and logs

```bash
rc-service noders-anytls-1 status
tail -n 100 /var/log/noders-anytls/noders-anytls-1.log
tail -f /var/log/noders-anytls/noders-anytls-1.log
```

## Upgrade

### Upgrade to latest release

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/upgrade.sh | bash -s --
```

### Upgrade to a specific release

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/upgrade.sh | bash -s -- --version v0.0.9
```

### Upgrade without restart

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/upgrade.sh | bash -s -- --version v0.0.9 --no-restart
```

## Uninstall

### Remove one node

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- --uninstall --node-id 1
```

### Remove everything

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- --uninstall --all
```

## Local Run

```bash
cp config.example.toml config.toml
cargo run --offline -- config.toml
```

Fill at least:

- `panel.url`
- `panel.token`
- `panel.node_id`
- `tls.cert_path`
- `tls.key_path`

Optional:

- `tls.server_name`
- `[outbound].dns_resolver`
- `[outbound].ip_strategy`
- `[tls.acme]`
