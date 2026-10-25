//! Workspace WebSocket (`GET /api/ws`, docs/03): one socket per browser window, multiplexing
//! streams with the binary framing from `protocol_core::wire`.

pub mod ssh_stream;
pub mod writer;

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    extract::{
        ConnectInfo, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures_util::StreamExt;
use protocol_core::{
    WORKSPACE_SUBPROTOCOL,
    wire::{self, Code, Frame, Opcode, WireError},
};
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;

use crate::{
    error::ApiError,
    keyring::VaultState,
    session::{self, Session},
    state::AppState,
};

pub use writer::Outbound;

/// Interval of gateway → client pings; two missed pongs close the socket (docs/03 §5.1).
const SERVER_PING: Duration = Duration::from_secs(15);
/// Session revalidation / `SessionState` push interval.
const SESSION_CHECK: Duration = Duration::from_secs(5);
/// Per-stream input queue (frames). Overflow closes the stream with `RateLimited`.
const INPUT_QUEUE: usize = 64;

/// `GET /api/ws` — validates subprotocol, session and Origin before upgrading.
pub async fn upgrade(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let wants_proto = headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|p| p.trim() == WORKSPACE_SUBPROTOCOL);
    if !wants_proto {
        return (StatusCode::BAD_REQUEST, "missing subprotocol").into_response();
    }
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if origin != Some(state.settings.public_origin.as_str()) {
        return ApiError::Forbidden("origin not allowed").into_response();
    }
    let session = match Session::load(&state, &headers).await {
        Ok(Some(s)) => s,
        Ok(None) => return ApiError::Unauthenticated { needs_setup: false }.into_response(),
        Err(e) => return e.into_response(),
    };
    let Some((socket_id, cancel)) = state.hub.register(&session.session_id) else {
        return ApiError::RateLimited {
            retry_after_secs: 5,
        }
        .into_response();
    };
    let mut session = session;
    session.ip = Some(addr.ip());
    ws.protocols([WORKSPACE_SUBPROTOCOL])
        .max_message_size(wire::MAX_CLIENT_FRAME)
        .max_frame_size(wire::MAX_CLIENT_FRAME)
        .on_upgrade(move |socket| async move {
            let sid = session.session_id.clone();
            run(state.clone(), session, socket, cancel).await;
            state.hub.unregister(&sid, socket_id);
        })
}

/// Terminal output credit shared between the socket reader (acks) and the stream task.
#[derive(Debug)]
pub struct Credit {
    in_flight: AtomicI64,
    notify: Notify,
}

impl Credit {
    pub fn new() -> Self {
        Self {
            in_flight: AtomicI64::new(0),
            notify: Notify::new(),
        }
    }
    /// Bytes still allowed before the window is exhausted.
    pub fn available(&self) -> i64 {
        i64::from(wire::TERM_WINDOW) - self.in_flight.load(Ordering::Acquire)
    }
    pub fn consume(&self, n: usize) {
        self.in_flight
            .fetch_add(i64::try_from(n).unwrap_or(i64::MAX), Ordering::AcqRel);
    }
    /// Applies a client ack, clamped to what is actually in flight.
    pub fn ack(&self, n: u32) {
        let mut cur = self.in_flight.load(Ordering::Acquire);
        loop {
            let next = (cur - i64::from(n)).max(0);
            match self.in_flight.compare_exchange_weak(
                cur,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
        self.notify.notify_one();
    }
    /// Waits until credit is available.
    pub async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            if self.available() > 0 {
                return;
            }
            notified.await;
        }
    }
}

impl Default for Credit {
    fn default() -> Self {
        Self::new()
    }
}

/// Input forwarded from the socket to a stream.
#[derive(Debug)]
pub enum StreamInput {
    Data(Bytes),
    Resize(wire::TermResize),
}

/// Answers to prompts the stream sent to the client.
#[derive(Debug)]
pub enum PromptReply {
    Credentials(Box<wire::CredentialSubmit>),
    HostIdentity(bool),
}

/// Socket-side handle of one stream.
#[derive(Debug)]
pub struct StreamHandle {
    pub input: mpsc::Sender<StreamInput>,
    pub prompts: mpsc::Sender<PromptReply>,
    pub credit: Arc<Credit>,
    pub cancel: CancellationToken,
    pub upstream_rtt_us: Arc<AtomicU32>,
    pub allow_paste: Arc<AtomicBool>,
    /// Set once the stream is established (input before that is a protocol error).
    pub established: Arc<AtomicBool>,
}

/// Context shared by all streams of one socket.
#[derive(Debug, Clone)]
pub struct SocketCtx {
    pub state: AppState,
    pub session: Session,
    pub out: Outbound,
    /// Stream tasks report their id here when they finish.
    pub done: mpsc::UnboundedSender<u32>,
}

async fn run(state: AppState, session: Session, socket: WebSocket, cancel: CancellationToken) {
    let (sink, mut rx) = socket.split();
    let out = writer::spawn(sink, cancel.clone());
    let (done_tx, mut done_rx) = mpsc::unbounded_channel();
    let ctx = SocketCtx {
        state: state.clone(),
        session: session.clone(),
        out: out.clone(),
        done: done_tx,
    };
    let mut sock = Socket {
        ctx,
        streams: HashMap::new(),
        last_stream_id: 0,
        locked_notified: false,
        last_touch: None,
    };

    let mut ping = tokio::time::interval(SERVER_PING);
    ping.tick().await;
    let mut check = tokio::time::interval(SESSION_CHECK);
    let mut missed_pongs = 0u8;
    let mut ping_seq = 0u32;
    let started = Instant::now();
    let mut last_vault: Option<bool> = None;

    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            msg = rx.next() => match msg {
                Some(Ok(Message::Binary(b))) => {
                    if let Some(()) = sock.handle(b, &mut missed_pongs).await { continue }
                    break;
                }
                Some(Ok(Message::Text(_))) => {
                    out.close(1003);
                    break;
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
            },
            Some(id) = done_rx.recv() => { sock.streams.remove(&id); }
            _ = ping.tick() => {
                if missed_pongs >= 2 {
                    tracing::debug!("workspace socket: client stopped answering pings");
                    break;
                }
                missed_pongs += 1;
                ping_seq = ping_seq.wrapping_add(1);
                let t_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
                let p = wire::Ping { pong: false, seq: ping_seq, t_us, upstream_rtt_us: wire::RTT_UNKNOWN };
                if !out.control(wire::encode(Opcode::Ping, 0, &p.to_bytes())).await { break }
            }
            _ = check.tick() => {
                match Session::by_id(&state, &session.session_id).await {
                    Ok(Some(_)) => {}
                    _ => {
                        let _ = out.control(wire::encode_coded(Opcode::ControlError, 0, Code::Unauthorized, "session ended")).await;
                        break;
                    }
                }
                let unlocked = matches!(state.keyring.state(&session.session_id), VaultState::Unlocked(_));
                if last_vault != Some(unlocked) {
                    last_vault = Some(unlocked);
                    if unlocked { sock.locked_notified = false; }
                    if !out.control(session_state(&state, &session, unlocked)).await { break }
                }
            }
        }
    }
    for h in sock.streams.values() {
        h.cancel.cancel();
    }
    // Give stream tasks a moment to emit their final frames, then close the socket.
    let _ = tokio::time::timeout(Duration::from_millis(500), async {
        while !sock.streams.is_empty() {
            match done_rx.recv().await {
                Some(id) => {
                    sock.streams.remove(&id);
                }
                None => break,
            }
        }
    })
    .await;
    out.close(1000);
}

fn session_state(state: &AppState, session: &Session, unlocked: bool) -> Bytes {
    let expires_in = (session.expires_at - crate::util::now_ms()) / 1000;
    let msg = wire::SessionState {
        vault: if unlocked { "unlocked" } else { "locked" }.into(),
        idle_lock_in_s: state.keyring.idle_lock_in(&session.session_id),
        session_expires_in_s: expires_in.max(0),
    };
    wire::encode_json(Opcode::SessionState, 0, &msg)
}

struct Socket {
    ctx: SocketCtx,
    streams: HashMap<u32, StreamHandle>,
    last_stream_id: u32,
    locked_notified: bool,
    last_touch: Option<Instant>,
}

impl Socket {
    async fn error(&self, stream_id: u32, code: Code, text: &str) -> bool {
        self.ctx
            .out
            .control(wire::encode_coded(
                Opcode::ControlError,
                stream_id,
                code,
                text,
            ))
            .await
    }

    /// Records user activity: vault idle timer always, session idle timer at most once a minute (D-042).
    async fn activity(&mut self) {
        let sid = &self.ctx.session.session_id;
        self.ctx.state.keyring.touch(sid);
        if self
            .last_touch
            .is_none_or(|t| t.elapsed() >= Duration::from_secs(60))
        {
            self.last_touch = Some(Instant::now());
            let _ = session::touch(&self.ctx.state, sid).await;
        }
    }

    /// Handles one client message. `None` ends the socket.
    async fn handle(&mut self, msg: Bytes, missed_pongs: &mut u8) -> Option<()> {
        let frame = match wire::decode_client(msg) {
            Ok(f) => f,
            Err(WireError::TooLarge(_)) => {
                self.ctx.out.close(1009);
                return None;
            }
            Err(e) => {
                return self
                    .error(0, Code::BadFrame, &e.to_string())
                    .await
                    .then_some(());
            }
        };
        let Frame {
            opcode,
            stream_id,
            payload,
        } = frame;

        if opcode.is_user_input() {
            let unlocked = matches!(
                self.ctx.state.keyring.state(&self.ctx.session.session_id),
                VaultState::Unlocked(_)
            );
            if !unlocked {
                if !self.locked_notified {
                    self.locked_notified = true;
                    return self
                        .error(
                            stream_id,
                            Code::VaultLocked,
                            "vault is locked; input dropped",
                        )
                        .await
                        .then_some(());
                }
                return Some(());
            }
            self.activity().await;
        }

        match opcode {
            Opcode::Ping => {
                let Ok(p) = wire::Ping::parse(&payload) else {
                    return self
                        .error(stream_id, Code::BadFrame, "bad ping")
                        .await
                        .then_some(());
                };
                if p.pong {
                    if stream_id == 0 {
                        *missed_pongs = 0;
                    }
                    return Some(());
                }
                let upstream = match stream_id {
                    0 => wire::RTT_UNKNOWN,
                    id => match self.streams.get(&id) {
                        Some(h) => h.upstream_rtt_us.load(Ordering::Relaxed),
                        None => {
                            return self
                                .error(id, Code::UnknownStream, "unknown stream")
                                .await
                                .then_some(());
                        }
                    },
                };
                let pong = wire::Ping {
                    pong: true,
                    upstream_rtt_us: upstream,
                    ..p
                };
                self.ctx
                    .out
                    .control(wire::encode(Opcode::Ping, stream_id, &pong.to_bytes()))
                    .await
                    .then_some(())
            }
            Opcode::StreamOpen => self.open(stream_id, &payload).await,
            _ if stream_id == 0 => self
                .error(0, Code::BadFrame, "stream id 0 is control only")
                .await
                .then_some(()),
            _ => {
                let Some(h) = self.streams.get(&stream_id) else {
                    return self
                        .error(stream_id, Code::UnknownStream, "unknown stream")
                        .await
                        .then_some(());
                };
                self.dispatch(stream_id, opcode, payload, h).await
            }
        }
    }

    async fn dispatch(
        &self,
        id: u32,
        opcode: Opcode,
        payload: Bytes,
        h: &StreamHandle,
    ) -> Option<()> {
        let established = h.established.load(Ordering::Acquire);
        let input = match opcode {
            Opcode::StreamClose => {
                h.cancel.cancel();
                return Some(());
            }
            Opcode::CredentialSubmit => {
                return match wire::CredentialSubmit::parse(payload) {
                    Ok(c) => {
                        let _ = h.prompts.try_send(PromptReply::Credentials(Box::new(c)));
                        Some(())
                    }
                    Err(_) => self
                        .error(id, Code::BadFrame, "malformed credentials")
                        .await
                        .then_some(()),
                };
            }
            Opcode::HostIdentityDecision => {
                return match serde_json::from_slice::<wire::HostIdentityDecision>(&payload) {
                    Ok(d) => {
                        let _ = h.prompts.try_send(PromptReply::HostIdentity(d.approve));
                        Some(())
                    }
                    Err(_) => self
                        .error(id, Code::BadFrame, "malformed decision")
                        .await
                        .then_some(()),
                };
            }
            Opcode::FlowAck => {
                return match wire::parse_flow_ack(&payload) {
                    Ok(n) => {
                        h.credit.ack(n);
                        Some(())
                    }
                    Err(_) => self
                        .error(id, Code::BadFrame, "bad ack")
                        .await
                        .then_some(()),
                };
            }
            _ if !established => {
                return self
                    .error(id, Code::BadFrame, "stream not established")
                    .await
                    .then_some(());
            }
            Opcode::TermData => StreamInput::Data(payload),
            Opcode::TermPaste => {
                if !h.allow_paste.load(Ordering::Relaxed) {
                    return self
                        .error(id, Code::PolicyDenied, "paste is disabled for this node")
                        .await
                        .then_some(());
                }
                StreamInput::Data(payload)
            }
            Opcode::TermResize => match wire::TermResize::parse(&payload) {
                Ok(r) => StreamInput::Resize(r),
                Err(_) => {
                    return self
                        .error(id, Code::BadFrame, "bad resize")
                        .await
                        .then_some(());
                }
            },
            _ => {
                return self
                    .error(id, Code::BadFrame, "opcode not valid for a terminal stream")
                    .await
                    .then_some(());
            }
        };
        if h.input.try_send(input).is_err() {
            h.cancel.cancel();
            return self
                .error(id, Code::RateLimited, "input queue full")
                .await
                .then_some(());
        }
        Some(())
    }

    async fn open(&mut self, id: u32, payload: &[u8]) -> Option<()> {
        let close =
            |code: Code, text: &str| wire::encode_coded(Opcode::StreamClose, id, code, text);
        if id == 0 || id <= self.last_stream_id {
            return self
                .error(id, Code::BadFrame, "stream ids must be strictly increasing")
                .await
                .then_some(());
        }
        self.last_stream_id = id;
        if self.streams.len() >= wire::MAX_STREAMS_PER_SOCKET {
            return self
                .ctx
                .out
                .control(close(Code::StreamLimit, "too many streams"))
                .await
                .then_some(());
        }
        let Ok(req) = serde_json::from_slice::<wire::StreamOpen>(payload) else {
            return self
                .error(id, Code::BadFrame, "malformed StreamOpen")
                .await
                .then_some(());
        };
        let mvk = match self.ctx.state.keyring.state(&self.ctx.session.session_id) {
            VaultState::Unlocked(m) => m,
            _ => {
                return self
                    .ctx
                    .out
                    .control(close(Code::VaultLocked, "vault is locked"))
                    .await
                    .then_some(());
            }
        };
        self.activity().await;
        let (input_tx, input_rx) = mpsc::channel(INPUT_QUEUE);
        let (prompt_tx, prompt_rx) = mpsc::channel(4);
        let handle = StreamHandle {
            input: input_tx,
            prompts: prompt_tx,
            credit: Arc::new(Credit::new()),
            cancel: CancellationToken::new(),
            upstream_rtt_us: Arc::new(AtomicU32::new(wire::RTT_UNKNOWN)),
            allow_paste: Arc::new(AtomicBool::new(false)),
            established: Arc::new(AtomicBool::new(false)),
        };
        let task = ssh_stream::StreamTask {
            id,
            ctx: self.ctx.clone(),
            req,
            mvk: Some(mvk),
            input: input_rx,
            prompts: prompt_rx,
            credit: Arc::clone(&handle.credit),
            cancel: handle.cancel.clone(),
            upstream_rtt_us: Arc::clone(&handle.upstream_rtt_us),
            allow_paste: Arc::clone(&handle.allow_paste),
            established: Arc::clone(&handle.established),
        };
        self.streams.insert(id, handle);
        tokio::spawn(task.run());
        Some(())
    }
}
