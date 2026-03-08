# NodeRS-AnyTLS

Rust implementation of an Xboard `UniProxy` AnyTLS node.

## Features

- Native Rust AnyTLS inbound with TLS handshake and stream multiplexing
- Native Rust UOT support for `sp.v2.udp-over-tcp.arpa` and legacy `sp.udp-over-tcp.arpa`
- Xboard `UniProxy` compatibility for `config`, `user`, `push`, `alive`, `alivelist`, `status`
- Multi-user hot reload, kicked sessions on removal, and shared per-user speed limiting
- Device limit enforcement with local + panel alive-state accounting
- Xboard `routes` support for `block` and `dns` actions
- TLS file hot reload for external certificate renewal workflows
- Embedded ACME HTTP-01 issuance and renewal for native TLS certificate management
- GitHub Actions release packaging for Linux release bundles

## Implementation

- The AnyTLS protocol stack is implemented directly in this repository under `src/server/`
- Transport responsibilities are split across `src/server/session.rs`, `src/server/uot.rs`, `src/server/transport.rs`, and `src/server/traffic.rs` for easier maintenance
- No `sing-box_mod`, `sing-box`, subprocess core, FFI bridge, or external protocol engine is used at runtime
- CI enforces this constraint with `scripts/verify-pure-rust.sh`

## TLS Notes

- `uTLS` is an outbound TLS fingerprinting feature in `sing-box_mod`; it does not apply to this inbound node process
- Server-side AnyTLS padding negotiation is implemented by accepting client preface padding and sending `UPDATE_PADDING_SCHEME` when `padding-md5` mismatches
- Active record padding generation is a client-side behavior in the upstream AnyTLS reference implementation, so it is intentionally not emitted by this server
- UOT is handled inside the AnyTLS stream layer using the protocol-defined request and datagram framing for `sp.v2.udp-over-tcp.arpa`
- Local `tls.server_name` takes precedence over panel `server_name`
- Wildcard listen now binds IPv4 and IPv6 simultaneously on Linux when available
- Certificate files are hot-reloaded from disk according to `tls.reload_interval_seconds`
- Panel `base_config.pull_interval` / `push_interval` drive config sync and traffic/alive reporting cadence at runtime
- Embedded ACME HTTP-01 is implemented in pure Rust under `src/acme.rs`; issued certificates are renewed before expiry and reloaded automatically
- ACME renewal timing is computed from the current certificate `notAfter` field rather than a fixed timer guess
- ACME `http-01` requires `tls.acme.challenge_listen` to be reachable by the CA, typically `[::]:80`
- The Linux install script can bootstrap self-signed certificates with `--self-signed-domain`
- External ACME tools such as `acme.sh` or `certbot` can renew `cert.pem` / `key.pem`, and the node will reload them automatically
- Embedded ACME `dns-01` provider integration is not implemented yet

## Route Support

Current `routes` handling:

- `action=block`
  - `protocol:tcp`
  - `regexp:...`
  - raw regex matches against `host`, `host:port`, `ip`, `ip:port`
- `action=dns`
  - `main` sets the default upstream DNS server for domain resolution
  - `full:example.com` exact match
  - `domain:example.com` / `suffix:example.com` suffix match
  - `keyword:internal` substring match
  - `regexp:...` regex match

DNS routes are applied only to domain targets. IP targets bypass DNS rules.

## Local Run

1. Copy `config.example.toml` to `config.toml`
2. Fill `panel.url`, `panel.token`, `panel.node_id`, `tls.cert_path`, `tls.key_path`
3. Optional: set `tls.server_name`; when present it overrides panel `server_name`
4. Optional: set `[outbound] dns_resolver` to `system` or a custom server such as `1.1.1.1`
5. Optional: set `[outbound] ip_strategy` to `system`, `prefer_ipv4`, or `prefer_ipv6`
6. Optional: enable `[tls.acme]` for built-in HTTP-01 certificate issuance
7. `pull_interval` / `push_interval` do not need local config; the node follows Xboard `base_config`
8. Run `cargo run --offline -- config.toml`

## Release Packaging

A release workflow is provided at `.github/workflows/release.yml`.

- Trigger: push a tag like `v1.0.0`
- Outputs:
  - `noders-anytls-<tag>-linux-amd64.tar.gz`
  - matching `.sha256` checksum files

Each archive contains:

- `noders-anytls`
- `config.example.toml`
- `install.sh`
- `upgrade.sh`
- `packaging/systemd/noders-anytls.service`
- `README.md`
- `LICENSE`

## Install Scripts

### Linux

The Linux installer supports two modes:

- Run directly from the repository/raw URL: it auto-downloads the latest Linux release bundle and installs it
- Run from an unpacked Linux release bundle: it installs from the local release files directly

Services are enabled and started automatically during installation when the script runs as `root` on a `systemd` host. No extra `systemctl start` command is required.

**One-line install**

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- --panel-url https://api.example.com --panel-token server_token --node-id 1
```

**Multiple nodes**

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- \
  --xboard https://api.example.com server_token 1 \
  --xboard https://api.example.com server_token 2
```

**ACME**

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- \
  --panel-url https://api.example.com \
  --panel-token server_token \
  --node-id 1 \
  --acme-domain node.example.com \
  --acme-email admin@example.com
```

**Self-signed**

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- \
  --panel-url https://api.example.com \
  --panel-token server_token \
  --node-id 1 \
  --self-signed-domain node.example.com
```

**Local `server_name` override**

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- \
  --panel-url https://api.example.com \
  --panel-token server_token \
  --node-id 1 \
  --server-name node.example.com
```

**Outbound DNS and IP preference**

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- \
  --panel-url https://api.example.com \
  --panel-token server_token \
  --node-id 1 \
  --server-name node.example.com \
  --dns-resolver 1.1.1.1 \
  --ip-strategy prefer_ipv6
```

Default install paths:

- Binary: `/usr/local/bin/noders-anytls`
- Config directory: `/etc/noders/anytls`
- State: `/var/lib/noders/anytls`
- Cert: `/etc/noders/anytls/cert.pem`
- Key: `/etc/noders/anytls/key.pem`

When `--xboard` is repeated, the installer creates one config per node under `/etc/noders/anytls/nodes/<node_id>.toml` and one service per node named `noders-anytls-<node_id>`.

When running as root on a systemd host, the script installs, enables, and starts the corresponding `systemd` service or services automatically.

`--panel-token` must be the Xboard global `server_token` used by `/api/v1/server/UniProxy/*`, not a per-user token and not a subscription token. This is enforced by Xboard in `app/Http/Middleware/Server.php:14`.

If `--acme-domain` is used, the installer enables `[tls.acme]` in each generated node config and skips self-signed generation.
If neither `--self-signed-domain` nor `--acme-domain` is passed, the installer tries to fetch `server_name` from Xboard and auto-generates a per-node self-signed certificate when no certificate already exists.
If `--server-name` is passed, the installer writes `tls.server_name` locally and that value takes precedence over the panel response at runtime.
If `--dns-resolver` is set to `system`, the node uses the system resolver; any other value is treated as a custom nameserver. `--ip-strategy` controls address ordering for domain outbound connections.
The generated config does not include local pull/push interval knobs; sync and traffic/alive reporting follow Xboard `base_config.pull_interval` / `push_interval` automatically.

### Upgrade

The upgrade script only replaces the binary and restarts currently active `noders-anytls-*` services. Existing node configs, certificates, ACME account files, and state are preserved.

**Upgrade to the latest release**

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/upgrade.sh | bash -s --
```

**Upgrade to a specific release**

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/upgrade.sh | bash -s -- --version v0.0.7
```

**Upgrade without restarting services**

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/upgrade.sh | bash -s -- --version v0.0.7 --no-restart
```

If a restarted service fails after the new binary is installed, the upgrader restores the previous binary automatically and attempts to restart the previously active services again.

### Uninstall

**Remove one node**

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- --uninstall --node-id 171
```

**Remove everything**

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- --uninstall --all
```

`--uninstall --node-id <id>` removes the corresponding `noders-anytls-<id>` service, node config, and per-node certificate files.

`--uninstall --all` removes all `noders-anytls-*` services, `/etc/noders/anytls`, `/var/lib/noders/anytls`, and `/usr/local/bin/noders-anytls`.
