use anyhow::{Context, anyhow, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Client;
use reqwest::header::{CONTENT_TYPE, LOCATION, RETRY_AFTER};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rustls_pki_types::{CertificateDer, pem::PemObject};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::config::AcmeConfig;

const ACME_CONTENT_TYPE: &str = "application/jose+json";
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);
const MAX_POLL_ATTEMPTS: usize = 90;
const HTTP_BUFFER_SIZE: usize = 8192;

pub async fn ensure_certificate(
    config: &AcmeConfig,
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<bool> {
    if !config.enabled {
        return Ok(false);
    }
    ensure!(
        !config.domain.trim().is_empty(),
        "ACME domain must not be empty when ACME is enabled"
    );
    if !needs_renewal(cert_path, key_path, config.renew_before_days).await? {
        return Ok(false);
    }

    let client = Client::builder()
        .user_agent(format!("NodeRS-AnyTLS/{} ACME", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build ACME HTTP client")?;
    let directory = fetch_directory(&client, &config.directory_url).await?;
    let account_key = load_or_create_private_key(&config.account_key_path, true).await?;
    let acme = AcmeClient::new(client, directory, account_key)?;
    let account = acme.ensure_account(&config.email).await?;

    let mut order = acme.new_order(&account.kid, &config.domain).await?;
    let authorization_url = order
        .authorizations
        .first()
        .cloned()
        .context("ACME order did not include any authorizations")?;
    let authorization = acme
        .fetch_authorization(&account.kid, &authorization_url)
        .await?;

    if authorization.status != "valid" {
        let challenge = authorization
            .challenges
            .into_iter()
            .find(|challenge| challenge.kind == "http-01")
            .context("ACME authorization did not expose an http-01 challenge")?;
        let key_authorization = build_key_authorization(&challenge.token, acme.jwk_thumbprint());
        let server = Http01ChallengeServer::start(
            &config.challenge_listen,
            challenge.token.clone(),
            key_authorization,
        )
        .await?;
        let challenge_result = async {
            if challenge.status != "valid" {
                acme.trigger_challenge(&account.kid, &challenge.url).await?;
            }
            acme.poll_authorization_valid(&account.kid, &authorization_url)
                .await
        }
        .await;
        server.stop();
        challenge_result?;
    }

    let domain_key = load_or_create_private_key(key_path, false).await?;
    let csr_der = build_certificate_signing_request(&domain_key, &config.domain)?;
    order = acme
        .finalize_order(&account.kid, &order.url, &order.finalize, &csr_der)
        .await?;
    if order.status != "valid" {
        order = acme.poll_order_valid(&account.kid, &order.url).await?;
    }
    let certificate_url = order
        .certificate
        .context("ACME order became valid without a certificate URL")?;
    let certificate_pem = acme
        .download_certificate(&account.kid, &certificate_url)
        .await?;

    write_private_key(key_path, &domain_key).await?;
    write_atomic(cert_path, certificate_pem.as_bytes()).await?;
    Ok(true)
}

async fn needs_renewal(
    cert_path: &Path,
    key_path: &Path,
    renew_before_days: u64,
) -> anyhow::Result<bool> {
    if tokio::fs::metadata(cert_path).await.is_err() || tokio::fs::metadata(key_path).await.is_err()
    {
        return Ok(true);
    }
    let cert_pem = tokio::fs::read(cert_path)
        .await
        .with_context(|| format!("read certificate {}", cert_path.display()))?;
    let not_after = match first_certificate_not_after(&cert_pem) {
        Ok(timestamp) => timestamp,
        Err(_) => return Ok(true),
    };
    let renew_after = not_after.saturating_sub(renew_before_days.saturating_mul(24 * 60 * 60));
    Ok(unix_now() >= renew_after)
}

async fn fetch_directory(client: &Client, directory_url: &str) -> anyhow::Result<AcmeDirectory> {
    client
        .get(directory_url)
        .send()
        .await
        .with_context(|| format!("request ACME directory {directory_url}"))?
        .error_for_status()
        .context("ACME directory request failed")?
        .json::<AcmeDirectory>()
        .await
        .context("decode ACME directory")
}

struct AcmeClient {
    client: Client,
    directory: AcmeDirectory,
    account_key: RsaPrivateKey,
    jwk_header: Value,
    jwk_thumbprint: String,
}

#[derive(Debug, Deserialize, Clone)]
struct AcmeDirectory {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
}

#[derive(Debug, Deserialize)]
struct OrderBody {
    status: String,
    authorizations: Vec<String>,
    finalize: String,
    #[serde(default)]
    certificate: Option<String>,
}

#[derive(Debug)]
struct OrderState {
    url: String,
    status: String,
    authorizations: Vec<String>,
    finalize: String,
    certificate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorizationBody {
    status: String,
    identifier: AuthorizationIdentifier,
    challenges: Vec<AuthorizationChallenge>,
}

#[derive(Debug, Deserialize)]
struct AuthorizationIdentifier {
    value: String,
}

#[derive(Debug, Deserialize)]
struct AuthorizationChallenge {
    #[serde(rename = "type")]
    kind: String,
    url: String,
    token: String,
    #[serde(default)]
    status: String,
}

#[derive(Debug)]
struct AccountHandle {
    kid: String,
}

impl AcmeClient {
    fn new(
        client: Client,
        directory: AcmeDirectory,
        account_key: RsaPrivateKey,
    ) -> anyhow::Result<Self> {
        let jwk_header = build_jwk(&account_key);
        let jwk_thumbprint = jwk_thumbprint(&account_key)?;
        Ok(Self {
            client,
            directory,
            account_key,
            jwk_header,
            jwk_thumbprint,
        })
    }

    fn jwk_thumbprint(&self) -> &str {
        &self.jwk_thumbprint
    }

    async fn ensure_account(&self, email: &str) -> anyhow::Result<AccountHandle> {
        let payload = if email.trim().is_empty() {
            json!({
                "termsOfServiceAgreed": true,
            })
        } else {
            json!({
                "termsOfServiceAgreed": true,
                "contact": [format!("mailto:{email}")],
            })
        };
        let response = self
            .signed_request(&self.directory.new_account, None, Some(&payload))
            .await?;
        let location = header_value(response.headers(), LOCATION)
            .context("ACME account response did not include Location header")?;
        Ok(AccountHandle { kid: location })
    }

    async fn new_order(&self, kid: &str, domain: &str) -> anyhow::Result<OrderState> {
        let payload = json!({
            "identifiers": [{
                "type": "dns",
                "value": domain,
            }],
        });
        let response = self
            .signed_request(&self.directory.new_order, Some(kid), Some(&payload))
            .await?;
        let location = header_value(response.headers(), LOCATION)
            .context("ACME order response did not include Location header")?;
        let body = response
            .json::<OrderBody>()
            .await
            .context("decode ACME order")?;
        Ok(OrderState::from_body(location, body))
    }

    async fn fetch_authorization(
        &self,
        kid: &str,
        authorization_url: &str,
    ) -> anyhow::Result<AuthorizationBody> {
        self.signed_request(authorization_url, Some(kid), None)
            .await?
            .json::<AuthorizationBody>()
            .await
            .context("decode ACME authorization")
    }

    async fn trigger_challenge(&self, kid: &str, challenge_url: &str) -> anyhow::Result<()> {
        let payload = json!({});
        self.signed_request(challenge_url, Some(kid), Some(&payload))
            .await?
            .error_for_status_ref()
            .context("submit ACME challenge response")?;
        Ok(())
    }

    async fn poll_authorization_valid(
        &self,
        kid: &str,
        authorization_url: &str,
    ) -> anyhow::Result<AuthorizationBody> {
        for _ in 0..MAX_POLL_ATTEMPTS {
            let response = self
                .signed_request(authorization_url, Some(kid), None)
                .await?;
            let delay = retry_after(response.headers());
            let authorization = response
                .json::<AuthorizationBody>()
                .await
                .context("decode ACME authorization poll")?;
            match authorization.status.as_str() {
                "valid" => return Ok(authorization),
                "pending" | "processing" => tokio::time::sleep(delay).await,
                "invalid" => {
                    bail!(
                        "ACME authorization became invalid for {}",
                        authorization.identifier.value
                    )
                }
                status => bail!("unexpected ACME authorization status {status}"),
            }
        }
        bail!("timed out while polling ACME authorization")
    }

    async fn finalize_order(
        &self,
        kid: &str,
        order_url: &str,
        finalize_url: &str,
        csr_der: &[u8],
    ) -> anyhow::Result<OrderState> {
        let payload = json!({
            "csr": base64url(csr_der),
        });
        self.signed_request(finalize_url, Some(kid), Some(&payload))
            .await?
            .error_for_status_ref()
            .context("submit ACME finalize request")?;
        self.poll_order_valid(kid, order_url).await
    }

    async fn poll_order_valid(&self, kid: &str, order_url: &str) -> anyhow::Result<OrderState> {
        for _ in 0..MAX_POLL_ATTEMPTS {
            let response = self.signed_request(order_url, Some(kid), None).await?;
            let delay = retry_after(response.headers());
            let body = response
                .json::<OrderBody>()
                .await
                .context("decode ACME order poll")?;
            let order = OrderState::from_body(order_url.to_string(), body);
            match order.status.as_str() {
                "valid" => return Ok(order),
                "pending" | "processing" | "ready" => tokio::time::sleep(delay).await,
                "invalid" => bail!("ACME order became invalid for {}", order.url),
                status => bail!("unexpected ACME order status {status}"),
            }
        }
        bail!("timed out while polling ACME order")
    }

    async fn download_certificate(
        &self,
        kid: &str,
        certificate_url: &str,
    ) -> anyhow::Result<String> {
        self.signed_request(certificate_url, Some(kid), None)
            .await?
            .text()
            .await
            .context("read ACME certificate chain")
    }

    async fn signed_request(
        &self,
        url: &str,
        kid: Option<&str>,
        payload: Option<&Value>,
    ) -> anyhow::Result<reqwest::Response> {
        for _ in 0..2 {
            let nonce = self.fetch_nonce().await?;
            let body = self.signed_payload(url, &nonce, kid, payload)?;
            let response = self
                .client
                .post(url)
                .header(CONTENT_TYPE, ACME_CONTENT_TYPE)
                .body(body)
                .send()
                .await
                .with_context(|| format!("send ACME POST to {url}"))?;
            if response.status().is_success() {
                return Ok(response);
            }
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            if body.contains("badNonce") {
                continue;
            }
            bail!(
                "ACME request to {url} failed with {status}: {}",
                summarize_problem(&body)
            );
        }
        bail!("ACME request to {url} kept failing with badNonce")
    }

    async fn fetch_nonce(&self) -> anyhow::Result<String> {
        let response = self
            .client
            .head(&self.directory.new_nonce)
            .send()
            .await
            .with_context(|| format!("request ACME nonce {}", self.directory.new_nonce))?
            .error_for_status()
            .context("ACME nonce request failed")?;
        header_value(response.headers(), "Replay-Nonce")
            .context("ACME nonce response did not include Replay-Nonce header")
    }

    fn signed_payload(
        &self,
        url: &str,
        nonce: &str,
        kid: Option<&str>,
        payload: Option<&Value>,
    ) -> anyhow::Result<Vec<u8>> {
        let protected = if let Some(kid) = kid {
            json!({
                "alg": "RS256",
                "kid": kid,
                "nonce": nonce,
                "url": url,
            })
        } else {
            json!({
                "alg": "RS256",
                "jwk": self.jwk_header,
                "nonce": nonce,
                "url": url,
            })
        };
        let protected_b64 =
            base64url(&serde_json::to_vec(&protected).context("encode ACME protected header")?);
        let payload_b64 = match payload {
            Some(payload) => {
                base64url(&serde_json::to_vec(payload).context("encode ACME payload")?)
            }
            None => String::new(),
        };
        let signature_input = format!("{protected_b64}.{payload_b64}");
        let signature_b64 = sign_base64url(&self.account_key, signature_input.as_bytes())?;
        serde_json::to_vec(&json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature_b64,
        }))
        .context("encode ACME JWS body")
    }
}

impl OrderState {
    fn from_body(url: String, body: OrderBody) -> Self {
        Self {
            url,
            status: body.status,
            authorizations: body.authorizations,
            finalize: body.finalize,
            certificate: body.certificate,
        }
    }
}

struct Http01ChallengeServer {
    handle: JoinHandle<()>,
}

impl Http01ChallengeServer {
    async fn start(listen: &str, token: String, key_authorization: String) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(listen)
            .await
            .with_context(|| format!("bind ACME http-01 listener on {listen}"))?;
        let expected_path = format!("/.well-known/acme-challenge/{token}");
        let handle = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let path = expected_path.clone();
                let response_body = key_authorization.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_http_request(stream, &path, &response_body).await {
                        tracing::debug!(%error, "serve ACME http-01 request failed");
                    }
                });
            }
        });
        Ok(Self { handle })
    }

    fn stop(self) {
        self.handle.abort();
    }
}

async fn serve_http_request(
    mut stream: tokio::net::TcpStream,
    expected_path: &str,
    response_body: &str,
) -> anyhow::Result<()> {
    let mut buffer = Vec::with_capacity(1024);
    loop {
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).await.context("read HTTP request")?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") || buffer.len() >= HTTP_BUFFER_SIZE
        {
            break;
        }
    }

    let request = String::from_utf8_lossy(&buffer);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1));
    let (status_line, body) = if path == Some(expected_path) {
        ("HTTP/1.1 200 OK", response_body)
    } else {
        ("HTTP/1.1 404 Not Found", "not found")
    };
    let response = format!(
        "{status_line}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .context("write HTTP challenge response")?;
    stream
        .flush()
        .await
        .context("flush HTTP challenge response")?;
    Ok(())
}

async fn load_or_create_private_key(
    path: &Path,
    persist_generated: bool,
) -> anyhow::Result<RsaPrivateKey> {
    if let Ok(existing) = tokio::fs::read_to_string(path).await
        && let Ok(key) = parse_private_key(existing).await
    {
        return Ok(key);
    }

    let key = tokio::task::spawn_blocking(|| {
        let mut rng = rand::thread_rng();
        RsaPrivateKey::new(&mut rng, 2048).context("generate RSA private key")
    })
    .await
    .context("join RSA key generation")??;

    if persist_generated {
        write_private_key(path, &key).await?;
    }
    Ok(key)
}

async fn parse_private_key(pem: String) -> anyhow::Result<RsaPrivateKey> {
    tokio::task::spawn_blocking(move || {
        RsaPrivateKey::from_pkcs8_pem(&pem).context("parse PKCS#8 RSA private key")
    })
    .await
    .context("join RSA private key parser")?
}

async fn write_private_key(path: &Path, key: &RsaPrivateKey) -> anyhow::Result<()> {
    let key = key.clone();
    let pem = tokio::task::spawn_blocking(move || {
        key.to_pkcs8_pem(LineEnding::LF)
            .map(|pem| pem.to_string())
            .context("encode PKCS#8 private key")
    })
    .await
    .context("join private key encoder")??;
    write_atomic(path, pem.as_bytes()).await
}

async fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create directory {}", parent.display()))?;
    }
    let temp_path = temp_path(path);
    tokio::fs::write(&temp_path, bytes)
        .await
        .with_context(|| format!("write temporary file {}", temp_path.display()))?;
    if tokio::fs::metadata(path).await.is_ok() {
        tokio::fs::remove_file(path)
            .await
            .with_context(|| format!("remove existing file {}", path.display()))?;
    }
    tokio::fs::rename(&temp_path, path)
        .await
        .with_context(|| format!("move {} to {}", temp_path.display(), path.display()))
}

fn temp_path(path: &Path) -> PathBuf {
    let suffix = format!("{}.tmp", unix_now());
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(extension) if !extension.is_empty() => {
            path.with_extension(format!("{extension}.{suffix}"))
        }
        _ => path.with_extension(suffix),
    }
}

fn build_key_authorization(token: &str, thumbprint: &str) -> String {
    format!("{token}.{thumbprint}")
}

fn build_jwk(key: &RsaPrivateKey) -> Value {
    let public_key = key.to_public_key();
    json!({
        "e": base64url(public_key.e().to_bytes_be()),
        "kty": "RSA",
        "n": base64url(public_key.n().to_bytes_be()),
    })
}

fn jwk_thumbprint(key: &RsaPrivateKey) -> anyhow::Result<String> {
    let public_key = key.to_public_key();
    let jwk = format!(
        "{{\"e\":\"{}\",\"kty\":\"RSA\",\"n\":\"{}\"}}",
        base64url(public_key.e().to_bytes_be()),
        base64url(public_key.n().to_bytes_be()),
    );
    Ok(base64url(Sha256::digest(jwk.as_bytes()).as_slice()))
}

fn sign_base64url(key: &RsaPrivateKey, message: &[u8]) -> anyhow::Result<String> {
    let signing_key = SigningKey::<Sha256>::new(key.clone());
    let signature = signing_key.sign(message);
    Ok(base64url(signature.to_bytes()))
}

fn build_certificate_signing_request(
    private_key: &RsaPrivateKey,
    domain: &str,
) -> anyhow::Result<Vec<u8>> {
    let public_key = RsaPublicKey::from(private_key);
    let spki = public_key
        .to_public_key_der()
        .context("encode CSR subject public key")?;
    let subject = encode_sequence(&[encode_set(&encode_sequence(&[
        encode_oid(&[2, 5, 4, 3]),
        encode_utf8_string(domain),
    ]))]);
    let san_extension = encode_sequence(&[
        encode_oid(&[2, 5, 29, 17]),
        encode_octet_string(&encode_sequence(&[encode_context_specific_primitive(
            2,
            domain.as_bytes(),
        )])),
    ]);
    let extensions = encode_sequence(&[san_extension]);
    let extension_request_attribute = encode_sequence(&[
        encode_oid(&[1, 2, 840, 113549, 1, 9, 14]),
        encode_set(&extensions),
    ]);
    let certification_request_info = encode_sequence(&[
        encode_integer_zero(),
        subject,
        spki.as_bytes().to_vec(),
        encode_context_specific_constructed(0, &extension_request_attribute),
    ]);
    let signature =
        SigningKey::<Sha256>::new(private_key.clone()).sign(&certification_request_info);
    Ok(encode_sequence(&[
        certification_request_info,
        encode_sequence(&[encode_oid(&[1, 2, 840, 113549, 1, 1, 11]), encode_null()]),
        encode_bit_string(&signature.to_bytes()),
    ]))
}

fn first_certificate_not_after(cert_pem: &[u8]) -> anyhow::Result<u64> {
    let certificate = CertificateDer::pem_slice_iter(cert_pem)
        .next()
        .transpose()
        .context("parse certificate PEM")?
        .context("certificate PEM did not include any certificates")?;
    parse_certificate_not_after(certificate.as_ref())
}

fn parse_certificate_not_after(certificate_der: &[u8]) -> anyhow::Result<u64> {
    let mut certificate = DerReader::new(certificate_der);
    let cert_sequence = certificate.read_tag(0x30)?;
    ensure!(certificate.is_empty(), "trailing bytes after certificate");

    let mut cert_fields = DerReader::new(cert_sequence);
    let tbs_certificate = cert_fields.read_tag(0x30)?;
    let mut tbs = DerReader::new(tbs_certificate);
    if tbs.peek_tag() == Some(0xa0) {
        let _ = tbs.read_tag(0xa0)?;
    }
    let _ = tbs.read_tag(0x02)?;
    let _ = tbs.read_tag(0x30)?;
    let _ = tbs.read_tag(0x30)?;
    let validity = tbs.read_tag(0x30)?;
    let mut validity_fields = DerReader::new(validity);
    let _ = validity_fields.read_any()?;
    let not_after = validity_fields.read_any()?;
    parse_der_time(not_after.tag, not_after.content)
}

fn parse_der_time(tag: u8, bytes: &[u8]) -> anyhow::Result<u64> {
    let text = std::str::from_utf8(bytes).context("decode certificate time")?;
    match tag {
        0x17 => parse_time_string(text, false),
        0x18 => parse_time_string(text, true),
        _ => bail!("unsupported certificate time tag {tag:#x}"),
    }
}

fn parse_time_string(text: &str, generalized: bool) -> anyhow::Result<u64> {
    ensure!(text.ends_with('Z'), "certificate time must end with Z");
    let body = &text[..text.len() - 1];
    let (year, rest) = if generalized {
        ensure!(body.len() == 14, "invalid GeneralizedTime length");
        (body[0..4].parse::<i32>()?, &body[4..])
    } else {
        ensure!(body.len() == 12, "invalid UTCTime length");
        let short_year = body[0..2].parse::<i32>()?;
        let full_year = if short_year >= 50 {
            1900 + short_year
        } else {
            2000 + short_year
        };
        (full_year, &body[2..])
    };
    let month = rest[0..2].parse::<u32>()?;
    let day = rest[2..4].parse::<u32>()?;
    let hour = rest[4..6].parse::<u32>()?;
    let minute = rest[6..8].parse::<u32>()?;
    let second = rest[8..10].parse::<u32>()?;
    unix_timestamp(year, month, day, hour, minute, second)
}

fn unix_timestamp(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> anyhow::Result<u64> {
    ensure!((1..=12).contains(&month), "invalid month {month}");
    ensure!((1..=31).contains(&day), "invalid day {day}");
    ensure!(hour < 24, "invalid hour {hour}");
    ensure!(minute < 60, "invalid minute {minute}");
    ensure!(second < 60, "invalid second {second}");
    let days = days_from_civil(year, month as i32, day as i32);
    let epoch_days = days_from_civil(1970, 1, 1);
    let seconds = (days - epoch_days) * 86_400
        + i64::from(hour) * 3_600
        + i64::from(minute) * 60
        + i64::from(second);
    ensure!(seconds >= 0, "certificate time predates UNIX epoch");
    Ok(seconds as u64)
}

fn days_from_civil(year: i32, month: i32, day: i32) -> i64 {
    let year = year - if month <= 2 { 1 } else { 0 };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * month + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    i64::from(era * 146097 + doe)
}

fn encode_integer_zero() -> Vec<u8> {
    vec![0x02, 0x01, 0x00]
}

fn encode_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

fn encode_utf8_string(value: &str) -> Vec<u8> {
    encode_tagged(0x0c, value.as_bytes())
}

fn encode_octet_string(value: &[u8]) -> Vec<u8> {
    encode_tagged(0x04, value)
}

fn encode_bit_string(value: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(value.len() + 1);
    content.push(0);
    content.extend_from_slice(value);
    encode_tagged(0x03, &content)
}

fn encode_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let body = flatten(parts);
    encode_tagged(0x30, &body)
}

fn encode_set(value: &[u8]) -> Vec<u8> {
    encode_tagged(0x31, value)
}

fn encode_context_specific_constructed(tag_number: u8, value: &[u8]) -> Vec<u8> {
    encode_tagged(0xa0 | (tag_number & 0x1f), value)
}

fn encode_context_specific_primitive(tag_number: u8, value: &[u8]) -> Vec<u8> {
    encode_tagged(0x80 | (tag_number & 0x1f), value)
}

fn encode_oid(components: &[u64]) -> Vec<u8> {
    assert!(components.len() >= 2);
    let mut body = Vec::new();
    body.push((components[0] * 40 + components[1]) as u8);
    for &component in &components[2..] {
        encode_oid_component(component, &mut body);
    }
    encode_tagged(0x06, &body)
}

fn encode_oid_component(mut value: u64, out: &mut Vec<u8>) {
    let mut buffer = [0u8; 10];
    let mut index = buffer.len();
    buffer[index - 1] = (value & 0x7f) as u8;
    index -= 1;
    value >>= 7;
    while value > 0 {
        buffer[index - 1] = ((value & 0x7f) as u8) | 0x80;
        index -= 1;
        value >>= 7;
    }
    out.extend_from_slice(&buffer[index..]);
}

fn encode_tagged(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(1 + encoded_len_len(value.len()) + value.len());
    encoded.push(tag);
    encode_length(value.len(), &mut encoded);
    encoded.extend_from_slice(value);
    encoded
}

fn encoded_len_len(length: usize) -> usize {
    if length < 128 {
        1
    } else {
        let mut length = length;
        let mut count = 0;
        while length > 0 {
            count += 1;
            length >>= 8;
        }
        1 + count
    }
}

fn encode_length(length: usize, out: &mut Vec<u8>) {
    if length < 128 {
        out.push(length as u8);
        return;
    }
    let mut buffer = [0u8; 8];
    let mut index = buffer.len();
    let mut value = length;
    while value > 0 {
        buffer[index - 1] = (value & 0xff) as u8;
        index -= 1;
        value >>= 8;
    }
    out.push(0x80 | (buffer.len() - index) as u8);
    out.extend_from_slice(&buffer[index..]);
}

fn flatten(parts: &[Vec<u8>]) -> Vec<u8> {
    let total = parts.iter().map(Vec::len).sum();
    let mut body = Vec::with_capacity(total);
    for part in parts {
        body.extend_from_slice(part);
    }
    body
}

fn header_value(
    headers: &reqwest::header::HeaderMap,
    name: impl reqwest::header::AsHeaderName,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn retry_after(headers: &reqwest::header::HeaderMap) -> Duration {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_POLL_INTERVAL)
}

fn summarize_problem(body: &str) -> String {
    #[derive(Deserialize)]
    struct ProblemBody {
        #[serde(rename = "type")]
        typ: Option<String>,
        detail: Option<String>,
    }

    serde_json::from_str::<ProblemBody>(body)
        .ok()
        .map(|problem| match (problem.typ, problem.detail) {
            (Some(typ), Some(detail)) => format!("{typ}: {detail}"),
            (Some(typ), None) => typ,
            (None, Some(detail)) => detail,
            (None, None) => body.to_string(),
        })
        .unwrap_or_else(|| body.to_string())
}

fn base64url(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

struct DerReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> DerReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn is_empty(&self) -> bool {
        self.position >= self.bytes.len()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn read_tag(&mut self, expected_tag: u8) -> anyhow::Result<&'a [u8]> {
        let element = self.read_any()?;
        ensure!(
            element.tag == expected_tag,
            "expected DER tag {expected_tag:#x}, got {:#x}",
            element.tag
        );
        Ok(element.content)
    }

    fn read_any(&mut self) -> anyhow::Result<DerElement<'a>> {
        let tag = *self
            .bytes
            .get(self.position)
            .ok_or_else(|| anyhow!("unexpected end of DER input"))?;
        self.position += 1;
        let length = self.read_length()?;
        let end = self.position + length;
        ensure!(end <= self.bytes.len(), "DER length exceeds input");
        let content = &self.bytes[self.position..end];
        self.position = end;
        Ok(DerElement { tag, content })
    }

    fn read_length(&mut self) -> anyhow::Result<usize> {
        let first = *self
            .bytes
            .get(self.position)
            .ok_or_else(|| anyhow!("unexpected end of DER length"))?;
        self.position += 1;
        if first & 0x80 == 0 {
            return Ok(first as usize);
        }
        let count = (first & 0x7f) as usize;
        ensure!(
            count > 0 && count <= 8,
            "unsupported DER length size {count}"
        );
        ensure!(
            self.position + count <= self.bytes.len(),
            "truncated DER length"
        );
        let mut length = 0usize;
        for byte in &self.bytes[self.position..self.position + count] {
            length = (length << 8) | (*byte as usize);
        }
        self.position += count;
        Ok(length)
    }
}

struct DerElement<'a> {
    tag: u8,
    content: &'a [u8],
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn builds_key_authorization() {
        assert_eq!(build_key_authorization("token", "thumb"), "token.thumb");
    }

    #[test]
    fn parses_utc_time() {
        assert_eq!(parse_der_time(0x17, b"260308000000Z").unwrap(), 1772928000);
    }

    #[test]
    fn parses_generalized_time() {
        assert_eq!(
            parse_der_time(0x18, b"20260308000000Z").unwrap(),
            1772928000
        );
    }

    #[tokio::test]
    async fn serves_http01_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);

        let server = Http01ChallengeServer::start(
            &address.to_string(),
            "abc".to_string(),
            "abc.thumb".to_string(),
        )
        .await
        .unwrap();
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /.well-known/acme-challenge/abc HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        server.stop();

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.ends_with("abc.thumb"));
    }
}
