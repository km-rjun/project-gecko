//! One SSH terminal stream: load node → (prompt credentials) → dial → host-key policy (TOFU) →
//! authenticate → PTY shell → credit-gated output pump + separate input task.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use protocol_core::{
    dial::{DialError, Dialer, DirectDialer},
    ssh::{
        self, HostKeyDecision, HostKeyInfo, HostKeyPolicy, HostKeyRejection, Output, PtySize,
        SshAuth, SshError, SshParams,
    },
    wire::{self, Code, Opcode},
};
use serde_json::json;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vault::Mvk;

use super::{Credit, PromptReply, SocketCtx, StreamInput};
use crate::{
    api::nodes::{self, ConnectTarget, PinnedIdentity},
    audit::{self, Event, Outcome},
    error::ApiError,
};

/// How long the user has to answer a credential or host-key prompt.
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(120);
/// Keepalive RTT probe interval (docs/03 §5.1).
const RTT_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_SIZE: PtySize = PtySize {
    cols: 80,
    rows: 24,
    px_w: 0,
    px_h: 0,
};

#[derive(Debug)]
pub struct StreamTask {
    pub id: u32,
    pub ctx: SocketCtx,
    pub req: wire::StreamOpen,
    pub mvk: Option<Arc<Mvk>>,
    pub input: mpsc::Receiver<StreamInput>,
    pub prompts: mpsc::Receiver<PromptReply>,
    pub credit: Arc<Credit>,
    pub cancel: CancellationToken,
    pub upstream_rtt_us: Arc<AtomicU32>,
    pub allow_paste: Arc<AtomicBool>,
    pub established: Arc<AtomicBool>,
}

/// Why a stream ended (maps to a `StreamClose` reason and audit `error_code`).
struct Failure(Code, String);

impl Failure {
    fn new(code: Code, text: impl Into<String>) -> Self {
        Self(code, text.into())
    }
}

impl From<ApiError> for Failure {
    fn from(e: ApiError) -> Self {
        match e {
            ApiError::NotFound => Self::new(Code::NodeNotFound, "node not found"),
            ApiError::Integrity => Self::new(Code::Internal, "stored data failed integrity check"),
            _ => Self::new(Code::Internal, "internal error"),
        }
    }
}

#[derive(Default)]
struct Counters {
    up: AtomicU64,
    down: AtomicU64,
}

impl StreamTask {
    pub async fn run(mut self) {
        let started = Instant::now();
        let counters = Arc::new(Counters::default());
        let cancel = self.cancel.clone();
        let result = tokio::select! {
            r = self.drive(Arc::clone(&counters)) => r,
            () = cancel.cancelled() => Err(Failure::new(Code::ClosedByUser, "")),
        };
        let (code, text) = match result {
            Ok(()) => (Code::ClosedByRemote, String::new()),
            Err(Failure(c, t)) => (c, t),
        };
        // A cancelled stream was closed by the user, the socket or the session; tell the client
        // (the writer drops it if the socket is already gone).
        let _ = self
            .ctx
            .out
            .control(wire::encode_coded(
                Opcode::StreamClose,
                self.id,
                code,
                &text,
            ))
            .await;
        let established = self.established.load(Ordering::Acquire);
        let mut ev = Event::new(
            if established {
                "session.closed"
            } else {
                "session.failed"
            },
            if established || code == Code::ClosedByUser {
                Outcome::Success
            } else {
                Outcome::Failure
            },
        )
        .actor(&self.ctx.session.user_id)
        .ip(self.ctx.session.ip)
        .node(&self.req.node_id)
        .detail("route", "direct")
        .detail(
            "duration_ms",
            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        )
        .detail("bytes_up", counters.up.load(Ordering::Relaxed))
        .detail("bytes_down", counters.down.load(Ordering::Relaxed));
        if code != Code::ClosedByUser && code != Code::ClosedByRemote {
            ev = ev.detail("error_code", code as u16);
        }
        let _ = audit::record(&self.ctx.state, ev).await;
        let _ = self.ctx.done.send(self.id);
    }

    fn mvk(&self) -> Result<&Mvk, Failure> {
        self.mvk
            .as_deref()
            .ok_or_else(|| Failure::new(Code::Internal, "vault key released"))
    }

    async fn audit(
        &self,
        event: &'static str,
        outcome: Outcome,
        sealed: Option<serde_json::Value>,
    ) {
        let mut ev = Event::new(event, outcome)
            .actor(&self.ctx.session.user_id)
            .ip(self.ctx.session.ip)
            .node(&self.req.node_id);
        if let (Some(v), Some(mvk)) = (sealed, self.mvk.as_deref()) {
            ev = ev.sealed(mvk, v);
        }
        let _ = audit::record(&self.ctx.state, ev).await;
    }

    async fn drive(&mut self, counters: Arc<Counters>) -> Result<(), Failure> {
        let state = self.ctx.state.clone();
        let user_id = self.ctx.session.user_id.clone();
        let target =
            nodes::connect_target(&state, self.mvk()?, &user_id, &self.req.node_id).await?;
        let sealed_target = json!({ "protocol": target.protocol, "node_name": target.name, "target": format!("{}:{}", target.host, target.port) });
        self.audit(
            "session.open",
            Outcome::Success,
            Some(sealed_target.clone()),
        )
        .await;

        if target.protocol != "ssh" {
            return Err(Failure::new(
                Code::TargetProtocolError,
                format!("{} streams are not available yet", target.protocol),
            ));
        }
        if target.edge_pool_id.is_some() {
            return Err(Failure::new(
                Code::RunnerUnavailable,
                "edge runners are not available yet",
            ));
        }
        self.allow_paste
            .store(target.allow_clipboard_paste, Ordering::Relaxed);

        let size = match (self.req.cols, self.req.rows) {
            (Some(cols), Some(rows))
                if (1..=1000).contains(&cols) && (1..=1000).contains(&rows) =>
            {
                PtySize {
                    cols,
                    rows,
                    px_w: self.req.px_w.unwrap_or(0),
                    px_h: self.req.px_h.unwrap_or(0),
                }
            }
            _ => DEFAULT_SIZE,
        };
        let pinned = target.pinned.clone();
        let (host, port) = (target.host.clone(), target.port);
        let params = self.credentials(target, size).await?;

        let dial_start = Instant::now();
        let stream = DirectDialer::default()
            .dial(&host, port)
            .await
            .map_err(|e| match e {
                DialError::Timeout => Failure::new(Code::Timeout, "connection timed out"),
                DialError::RunnerUnavailable => Failure::new(Code::RunnerUnavailable, "no runner"),
                DialError::Io(_) => Failure::new(Code::DialFailed, "connection failed"),
            })?;
        self.upstream_rtt_us.store(
            u32::try_from(dial_start.elapsed().as_micros()).unwrap_or(u32::MAX - 1),
            Ordering::Relaxed,
        );

        let result = Arc::new(std::sync::Mutex::new(PolicyResult::default()));
        let policy = Tofu {
            pinned,
            id: self.id,
            out: self.ctx.out.clone(),
            prompts: std::mem::replace(&mut self.prompts, mpsc::channel(1).1),
            result: Arc::clone(&result),
        };
        let shell = ssh::connect(stream, params, Box::new(policy)).await;
        let policy_result = std::mem::take(
            &mut *result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        if let Some(info) = &policy_result.mismatch {
            self.audit(
                "session.hostkey_mismatch",
                Outcome::Denied,
                Some(identity_json(info)),
            )
            .await;
        }
        if let Some(info) = &policy_result.approved {
            let pin = PinnedIdentity {
                kind: "ssh-hostkey".into(),
                algorithm: info.algorithm.clone(),
                fingerprint: info.fingerprint.clone(),
                public_key: B64.encode(&info.public_key),
            };
            nodes::pin_host_identity(&state, self.mvk()?, &user_id, &self.req.node_id, &pin)
                .await?;
            self.audit(
                "session.hostkey_pinned",
                Outcome::Success,
                Some(identity_json(info)),
            )
            .await;
        }
        let shell = shell.map_err(|e| match e {
            SshError::HostKey(HostKeyRejection::Mismatch) => Failure::new(
                Code::HostIdentityMismatch,
                "host key changed; reset the pinned identity to reconnect",
            ),
            SshError::HostKey(HostKeyRejection::Declined) => {
                Failure::new(Code::ClosedByUser, "host key not approved")
            }
            SshError::HostKey(HostKeyRejection::Unsupported) => Failure::new(
                Code::TargetProtocolError,
                "host certificates are not supported",
            ),
            SshError::AuthFailed => Failure::new(Code::AuthFailed, "authentication failed"),
            SshError::KeyDecode => {
                Failure::new(Code::AuthFailed, "private key could not be decoded")
            }
            SshError::UnsupportedKey(reason) => Failure::new(Code::PolicyDenied, reason),
            SshError::Protocol(_) => Failure::new(Code::TargetProtocolError, "ssh protocol error"),
        })?;

        let opened = wire::StreamOpened {
            protocol: "ssh".into(),
            route: "direct".into(),
            runner: None,
            policy: json!({ "clipboard_paste": self.allow_paste.load(Ordering::Relaxed) }),
        };
        self.ctx
            .out
            .control(wire::encode_json(Opcode::StreamOpened, self.id, &opened))
            .await;
        self.established.store(true, Ordering::Release);
        self.audit("session.established", Outcome::Success, Some(sealed_target))
            .await;
        // The MVK is not needed for the rest of the session; drop this task's reference so that
        // locking the vault really removes it from memory while the terminal stays connected.
        self.mvk = None;

        let (mut output, input) = shell.split();
        let input = Arc::new(input);
        let input_task = tokio::spawn(pump_input(
            std::mem::replace(&mut self.input, mpsc::channel(1).1),
            Arc::clone(&input),
            Arc::clone(&counters),
        ));
        let rtt_task = tokio::spawn(probe_rtt(
            input.rtt_probe(),
            Arc::clone(&self.upstream_rtt_us),
        ));

        let lane = self.ctx.out.lane(self.id);
        let result = loop {
            self.credit.wait().await;
            match output.next().await {
                Output::Data(data) => {
                    counters
                        .down
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                    let mut off = 0;
                    while off < data.len() {
                        let end = (off + wire::TERM_CHUNK).min(data.len());
                        self.credit.consume(end - off);
                        if !lane
                            .send(wire::encode(Opcode::TermData, self.id, &data[off..end]))
                            .await
                        {
                            break;
                        }
                        off = end;
                    }
                }
                Output::Exit(_) => {}
                Output::Closed => break Ok(()),
            }
            if input_task.is_finished() {
                break Ok(());
            }
        };
        input_task.abort();
        rtt_task.abort();
        input.close().await;
        result
    }

    /// Builds SSH parameters from stored secrets, prompting for anything missing. The node's
    /// secrets move into the params (no copies) and are zeroized when they drop.
    async fn credentials(
        &mut self,
        mut t: ConnectTarget,
        size: PtySize,
    ) -> Result<SshParams, Failure> {
        let method = t.auth_method.as_str();
        let mut fields = Vec::new();
        if t.username.is_none() {
            fields.push("username");
        }
        let needs_secret = match method {
            "private_key" => t.ephemeral || t.private_key.is_none(),
            "password" => t.ephemeral || t.password.is_none(),
            _ => false,
        };
        if needs_secret {
            if method == "private_key" {
                fields.extend(["private_key", "passphrase"]);
            } else {
                fields.push("password");
            }
        }
        if !fields.is_empty() {
            let req = wire::CredentialRequest {
                fields: fields.iter().map(|f| (*f).to_owned()).collect(),
                username: t.username.clone(),
            };
            if !self
                .ctx
                .out
                .control(wire::encode_json(Opcode::CredentialRequest, self.id, &req))
                .await
            {
                return Err(Failure::new(Code::ClosedBySocketLoss, ""));
            }
            let reply = loop {
                match tokio::time::timeout(PROMPT_TIMEOUT, self.prompts.recv()).await {
                    Err(_) => {
                        return Err(Failure::new(Code::Timeout, "credential prompt timed out"));
                    }
                    Ok(None) => return Err(Failure::new(Code::ClosedByUser, "")),
                    Ok(Some(PromptReply::Credentials(c))) => break c,
                    Ok(Some(PromptReply::HostIdentity(_))) => {}
                }
            };
            let wire::CredentialSubmit {
                username,
                password,
                private_key,
                passphrase,
            } = *reply;
            if t.username.is_none() {
                t.username = username.filter(|u| {
                    !u.is_empty() && u.len() <= 255 && !u.chars().any(char::is_control)
                });
            }
            if needs_secret {
                t.password = password;
                t.private_key = private_key;
                t.key_passphrase = passphrase;
            }
        }
        let username = t
            .username
            .take()
            .ok_or_else(|| Failure::new(Code::AuthFailed, "username required"))?;
        let auth = match method {
            "private_key" => {
                let pem = t
                    .private_key
                    .take()
                    .ok_or_else(|| Failure::new(Code::AuthFailed, "private key required"))?;
                SshAuth::PrivateKey {
                    pem,
                    passphrase: t.key_passphrase.take().filter(|p| !p.is_empty()),
                }
            }
            "password" => SshAuth::Password(
                t.password
                    .take()
                    .ok_or_else(|| Failure::new(Code::AuthFailed, "password required"))?,
            ),
            _ => SshAuth::None,
        };
        Ok(SshParams {
            username,
            auth,
            term: "xterm-256color".into(),
            size,
        })
    }
}

fn identity_json(info: &HostKeyInfo) -> serde_json::Value {
    json!({ "kind": "ssh-hostkey", "algorithm": info.algorithm, "fingerprint": info.fingerprint })
}

/// Outcome of the host-key check, readable after the handshake whatever happened.
#[derive(Default)]
struct PolicyResult {
    approved: Option<HostKeyInfo>,
    mismatch: Option<HostKeyInfo>,
}

/// Trust-on-first-use host-key policy (docs/02 §8): pinned → exact key match required; unknown →
/// prompt the user over the stream.
struct Tofu {
    pinned: Option<PinnedIdentity>,
    id: u32,
    out: super::Outbound,
    prompts: mpsc::Receiver<PromptReply>,
    result: Arc<std::sync::Mutex<PolicyResult>>,
}

impl Tofu {
    fn record(&self, f: impl FnOnce(&mut PolicyResult)) {
        f(&mut self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner));
    }
}

#[async_trait::async_trait]
impl HostKeyPolicy for Tofu {
    async fn check(&mut self, key: &HostKeyInfo) -> HostKeyDecision {
        if let Some(pin) = &self.pinned {
            if pin.kind == "ssh-hostkey"
                && B64
                    .decode(&pin.public_key)
                    .is_ok_and(|k| k == key.public_key)
            {
                return HostKeyDecision::Accept;
            }
            self.record(|r| r.mismatch = Some(key.clone()));
            return HostKeyDecision::Reject(HostKeyRejection::Mismatch);
        }
        let prompt = wire::HostIdentityPrompt {
            kind: "ssh-hostkey".into(),
            algorithm: key.algorithm.clone(),
            fingerprint: key.fingerprint.clone(),
            state: "unknown".into(),
        };
        if !self
            .out
            .control(wire::encode_json(
                Opcode::HostIdentityPrompt,
                self.id,
                &prompt,
            ))
            .await
        {
            return HostKeyDecision::Reject(HostKeyRejection::Declined);
        }
        let deadline = tokio::time::Instant::now() + PROMPT_TIMEOUT;
        loop {
            match tokio::time::timeout_at(deadline, self.prompts.recv()).await {
                Ok(Some(PromptReply::HostIdentity(true))) => {
                    self.record(|r| r.approved = Some(key.clone()));
                    return HostKeyDecision::Accept;
                }
                Ok(Some(PromptReply::HostIdentity(false)) | None) | Err(_) => {
                    return HostKeyDecision::Reject(HostKeyRejection::Declined);
                }
                Ok(Some(PromptReply::Credentials(_))) => {}
            }
        }
    }
}

async fn pump_input(
    mut rx: mpsc::Receiver<StreamInput>,
    input: Arc<ssh::ShellInput>,
    counters: Arc<Counters>,
) {
    while let Some(msg) = rx.recv().await {
        let r = match msg {
            StreamInput::Data(d) => {
                counters.up.fetch_add(d.len() as u64, Ordering::Relaxed);
                input.write(d).await
            }
            StreamInput::Resize(r) => {
                input
                    .resize(PtySize {
                        cols: r.cols,
                        rows: r.rows,
                        px_w: r.px_w,
                        px_h: r.px_h,
                    })
                    .await
            }
        };
        if r.is_err() {
            break;
        }
    }
}

async fn probe_rtt(probe: ssh::RttProbe, slot: Arc<AtomicU32>) {
    let mut tick = tokio::time::interval(RTT_INTERVAL);
    loop {
        tick.tick().await;
        let v = probe
            .measure(RTT_INTERVAL)
            .await
            .map_or(wire::RTT_UNKNOWN, |d| {
                u32::try_from(d.as_micros()).unwrap_or(wire::RTT_UNKNOWN - 1)
            });
        slot.store(v, Ordering::Relaxed);
    }
}
