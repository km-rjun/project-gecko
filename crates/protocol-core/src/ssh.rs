//! SSH client engine on `russh`: host-key policy hook (TOFU), password/key auth, PTY shell,
//! window-limited output and keepalive RTT. Credentials are dropped (zeroized) right after auth.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use russh::{
    ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Pty, SshId,
    client::{self, Handle, Msg},
    keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate, decode_secret_key},
};
use vault::SecretString;

use crate::dial::BoxStream;

/// Client SSH window (docs/03 §6.1, D-041).
pub const SSH_WINDOW: u32 = 256 * 1024;
/// russh per-channel message queue (bounded; provides backpressure).
pub const SSH_CHANNEL_BUFFER: usize = 16;

/// How to authenticate.
pub enum SshAuth {
    Password(SecretString),
    PrivateKey {
        pem: SecretString,
        passphrase: Option<SecretString>,
    },
    None,
}

impl std::fmt::Debug for SshAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Password(_) => "SshAuth::Password([REDACTED])",
            Self::PrivateKey { .. } => "SshAuth::PrivateKey([REDACTED])",
            Self::None => "SshAuth::None",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtySize {
    pub cols: u16,
    pub rows: u16,
    pub px_w: u16,
    pub px_h: u16,
}

/// Everything needed to open a shell. Consumed by [`connect`]; secrets are wiped on drop.
#[derive(Debug)]
pub struct SshParams {
    pub username: String,
    pub auth: SshAuth,
    pub term: String,
    pub size: PtySize,
}

/// Server host key as presented during key exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyInfo {
    pub algorithm: String,
    pub fingerprint_sha256: [u8; 32],
    /// OpenSSH display form, e.g. `SHA256:abc…`.
    pub fingerprint: String,
    /// SSH wire encoding of the public key.
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyRejection {
    /// Key differs from the pinned key.
    Mismatch,
    /// User declined the unknown key (or the prompt timed out).
    Declined,
    /// Host certificates are not supported.
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyDecision {
    Accept,
    Reject(HostKeyRejection),
}

/// Decides whether a server key is trusted (pinned comparison and/or user prompt).
#[async_trait::async_trait]
pub trait HostKeyPolicy: Send {
    async fn check(&mut self, key: &HostKeyInfo) -> HostKeyDecision;
}

#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("host key rejected: {0:?}")]
    HostKey(HostKeyRejection),
    #[error("authentication failed")]
    AuthFailed,
    #[error("private key could not be decoded (wrong passphrase or unsupported format)")]
    KeyDecode,
    #[error("{0}")]
    UnsupportedKey(&'static str),
    #[error("ssh protocol error: {0}")]
    Protocol(String),
}

struct ClientHandler {
    policy: Box<dyn HostKeyPolicy>,
    rejection: Arc<Mutex<Option<HostKeyRejection>>>,
}

impl ClientHandler {
    fn reject(&self, r: HostKeyRejection) {
        *self
            .rejection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(r);
    }
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = server_key else {
            self.reject(HostKeyRejection::Unsupported);
            return Ok(false);
        };
        let fp = key.fingerprint(HashAlg::Sha256);
        let Some(fingerprint_sha256) = fp.sha256() else {
            self.reject(HostKeyRejection::Unsupported);
            return Ok(false);
        };
        let info = HostKeyInfo {
            algorithm: key.algorithm().as_str().to_owned(),
            fingerprint_sha256,
            fingerprint: fp.to_string(),
            public_key: key.to_bytes().unwrap_or_default(),
        };
        match self.policy.check(&info).await {
            HostKeyDecision::Accept => Ok(true),
            HostKeyDecision::Reject(r) => {
                self.reject(r);
                Ok(false)
            }
        }
    }
}

/// User-facing reason RSA private keys are refused (decision D-044, RUSTSEC-2023-0071: the `rsa`
/// crate's private-key operations are not constant-time). RSA *host* keys remain supported: verifying
/// them uses only the public key.
pub const RSA_USER_KEY_REJECTED: &str = "RSA private keys are not supported (non-constant-time RSA implementation, RUSTSEC-2023-0071); use an Ed25519 or ECDSA key";

/// Cheap pre-check of a private key before it is stored or used. Rejects RSA keys; anything it
/// cannot classify (e.g. encrypted PKCS#8) is left to the full decode at connect time.
pub fn check_private_key(pem: &str) -> Result<(), &'static str> {
    if pem.contains("BEGIN RSA PRIVATE KEY") {
        return Err(RSA_USER_KEY_REJECTED);
    }
    if pem.contains("BEGIN OPENSSH PRIVATE KEY") {
        // The public half of an OpenSSH key is readable without the passphrase.
        if let Ok(k) = russh::keys::PrivateKey::from_openssh(pem)
            && k.algorithm().is_rsa()
        {
            return Err(RSA_USER_KEY_REJECTED);
        }
        return Ok(());
    }
    if let Ok(k) = decode_secret_key(pem, None)
        && k.algorithm().is_rsa()
    {
        return Err(RSA_USER_KEY_REJECTED);
    }
    Ok(())
}

fn config() -> Arc<client::Config> {
    Arc::new(client::Config {
        client_id: SshId::Standard("SSH-2.0-gateway".into()),
        window_size: SSH_WINDOW,
        channel_buffer_size: SSH_CHANNEL_BUFFER,
        nodelay: true,
        inactivity_timeout: None,
        ..Default::default()
    })
}

/// Output events from the remote shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// stdout or stderr bytes.
    Data(Bytes),
    /// Remote process exited with this status (channel may still deliver data).
    Exit(u32),
    /// Channel closed.
    Closed,
}

/// An authenticated interactive shell.
pub struct SshShell {
    handle: Arc<Handle<ClientHandler>>,
    reader: ChannelReadHalf,
    writer: ChannelWriteHalf<Msg>,
}

impl std::fmt::Debug for SshShell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SshShell")
    }
}

/// Handshake, host-key policy, authentication, PTY + shell. `params` (and its secrets) are dropped
/// before this returns, whatever the outcome.
pub async fn connect(
    stream: BoxStream,
    params: SshParams,
    policy: Box<dyn HostKeyPolicy>,
) -> Result<SshShell, SshError> {
    let rejection = Arc::new(Mutex::new(None));
    let handler = ClientHandler {
        policy,
        rejection: Arc::clone(&rejection),
    };
    let mut handle = match client::connect_stream(config(), stream, handler).await {
        Ok(h) => h,
        Err(e) => {
            if let Some(r) = *rejection
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
            {
                return Err(SshError::HostKey(r));
            }
            return Err(SshError::Protocol(e.to_string()));
        }
    };

    let SshParams {
        username,
        auth,
        term,
        size,
    } = params;
    let ok = match auth {
        SshAuth::Password(pw) => handle
            .authenticate_password(username.as_str(), pw.expose())
            .await
            .map_err(|e| SshError::Protocol(e.to_string()))?
            .success(),
        SshAuth::PrivateKey { pem, passphrase } => {
            check_private_key(pem.expose()).map_err(SshError::UnsupportedKey)?;
            let key =
                decode_secret_key(pem.expose(), passphrase.as_ref().map(SecretString::expose))
                    .map_err(|_| SshError::KeyDecode)?;
            drop((pem, passphrase));
            // Never sign with RSA (D-044); this also covers formats the pre-check cannot classify.
            if key.algorithm().is_rsa() {
                return Err(SshError::UnsupportedKey(RSA_USER_KEY_REJECTED));
            }
            handle
                .authenticate_publickey(
                    username.as_str(),
                    PrivateKeyWithHashAlg::new(Arc::new(key), None),
                )
                .await
                .map_err(|e| SshError::Protocol(e.to_string()))?
                .success()
        }
        SshAuth::None => handle
            .authenticate_none(username.as_str())
            .await
            .map_err(|e| SshError::Protocol(e.to_string()))?
            .success(),
    };
    if !ok {
        return Err(SshError::AuthFailed);
    }

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| SshError::Protocol(e.to_string()))?;
    channel
        .request_pty(
            false,
            &term,
            u32::from(size.cols),
            u32::from(size.rows),
            u32::from(size.px_w),
            u32::from(size.px_h),
            &[(Pty::TTY_OP_ISPEED, 38400), (Pty::TTY_OP_OSPEED, 38400)],
        )
        .await
        .map_err(|e| SshError::Protocol(e.to_string()))?;
    channel
        .request_shell(false)
        .await
        .map_err(|e| SshError::Protocol(e.to_string()))?;
    let (reader, writer) = channel.split();
    Ok(SshShell {
        handle: Arc::new(handle),
        reader,
        writer,
    })
}

impl SshShell {
    /// Splits into the output half (read by the stream task, gated by flow-control credit) and the
    /// input half (written by a separate task, so a stalled output reader never blocks acks).
    pub fn split(self) -> (ShellOutput, ShellInput) {
        (
            ShellOutput {
                reader: self.reader,
            },
            ShellInput {
                handle: self.handle,
                writer: self.writer,
            },
        )
    }
}

/// Output half of a shell.
pub struct ShellOutput {
    reader: ChannelReadHalf,
}

impl std::fmt::Debug for ShellOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShellOutput")
    }
}

impl ShellOutput {
    /// Next output event. Not calling this is how backpressure reaches the server.
    pub async fn next(&mut self) -> Output {
        loop {
            match self.reader.wait().await {
                Some(ChannelMsg::Data { data }) => return Output::Data(data),
                Some(ChannelMsg::ExtendedData { data, ext: 1 }) => return Output::Data(data),
                Some(ChannelMsg::ExitStatus { exit_status }) => return Output::Exit(exit_status),
                Some(ChannelMsg::Close) | None => return Output::Closed,
                Some(_) => {}
            }
        }
    }
}

/// Input half of a shell.
pub struct ShellInput {
    handle: Arc<Handle<ClientHandler>>,
    writer: ChannelWriteHalf<Msg>,
}

impl std::fmt::Debug for ShellInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShellInput")
    }
}

impl ShellInput {
    pub async fn write(&self, data: Bytes) -> Result<(), SshError> {
        self.writer
            .data_bytes(data)
            .await
            .map_err(|e| SshError::Protocol(e.to_string()))
    }

    pub async fn resize(&self, size: PtySize) -> Result<(), SshError> {
        self.writer
            .window_change(
                u32::from(size.cols),
                u32::from(size.rows),
                u32::from(size.px_w),
                u32::from(size.px_h),
            )
            .await
            .map_err(|e| SshError::Protocol(e.to_string()))
    }

    /// Handle used for keepalive RTT probes from a separate task.
    pub fn rtt_probe(&self) -> RttProbe {
        RttProbe(Arc::clone(&self.handle))
    }

    /// Sends EOF and disconnects.
    pub async fn close(&self) {
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            let _ = self.writer.eof().await;
            let _ = self
                .handle
                .disconnect(russh::Disconnect::ByApplication, "", "en")
                .await;
        })
        .await;
    }
}

/// Measures gateway → target RTT with `keepalive@openssh.com` requests.
pub struct RttProbe(Arc<Handle<ClientHandler>>);

impl std::fmt::Debug for RttProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RttProbe")
    }
}

impl RttProbe {
    /// Round trip of one keepalive request, or `None` on timeout/closed session.
    pub async fn measure(&self, timeout: Duration) -> Option<Duration> {
        let start = std::time::Instant::now();
        match tokio::time::timeout(timeout, self.0.send_ping()).await {
            Ok(Ok(())) => Some(start.elapsed()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};

    use super::*;

    fn openssh(alg: Algorithm) -> String {
        let k = PrivateKey::random(&mut rand::rng(), alg).expect("keygen");
        k.to_openssh(LineEnding::LF).expect("pem").to_string()
    }

    #[test]
    fn rsa_private_keys_are_rejected() {
        let rsa = openssh(Algorithm::Rsa { hash: None });
        assert_eq!(check_private_key(&rsa), Err(RSA_USER_KEY_REJECTED));
        // Encrypted OpenSSH RSA key: detected from the unencrypted public half.
        let enc = PrivateKey::from_openssh(&rsa)
            .expect("parse")
            .encrypt(&mut rand::rng(), "pw")
            .expect("encrypt");
        assert_eq!(
            check_private_key(&enc.to_openssh(LineEnding::LF).expect("pem")),
            Err(RSA_USER_KEY_REJECTED)
        );
        assert_eq!(
            check_private_key(
                "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"
            ),
            Err(RSA_USER_KEY_REJECTED)
        );
    }

    #[test]
    fn other_keys_pass_the_precheck() {
        assert_eq!(check_private_key(&openssh(Algorithm::Ed25519)), Ok(()));
        assert_eq!(
            check_private_key(&openssh(Algorithm::Ecdsa {
                curve: russh::keys::EcdsaCurve::NistP256
            })),
            Ok(())
        );
        assert_eq!(check_private_key("not a key"), Ok(()));
    }
}
