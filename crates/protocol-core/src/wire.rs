//! Binary frame codec: `[opcode u8][stream_id u32 BE][payload]`, one frame per WebSocket message.

use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use vault::SecretString;

pub const HEADER_LEN: usize = 5;
/// Maximum client → server frame (header included).
pub const MAX_CLIENT_FRAME: usize = 64 * 1024;
/// Maximum server → client frame (header included).
pub const MAX_SERVER_FRAME: usize = 512 * 1024;
/// Terminal output chunk size (well under [`MAX_SERVER_FRAME`]).
pub const TERM_CHUNK: usize = 32 * 1024;
/// Per-stream terminal byte window (docs/03 §6.1).
pub const TERM_WINDOW: u32 = 256 * 1024;
/// Maximum streams per workspace socket.
pub const MAX_STREAMS_PER_SOCKET: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Opcode {
    TermData = 0x01,
    TermResize = 0x02,
    Ping = 0x03,
    TermPaste = 0x04,
    FlowAck = 0x05,
    FrameRect = 0x10,
    InputMouse = 0x11,
    InputKey = 0x12,
    ClipboardSet = 0x13,
    ClipboardUpdate = 0x14,
    DesktopSize = 0x15,
    CursorShape = 0x16,
    DesktopResizeRequest = 0x17,
    StreamOpen = 0x20,
    StreamOpened = 0x21,
    StreamClose = 0x22,
    CredentialRequest = 0x24,
    CredentialSubmit = 0x25,
    HostIdentityPrompt = 0x26,
    HostIdentityDecision = 0x27,
    SessionState = 0x28,
    ControlError = 0xFF,
}

impl Opcode {
    pub fn from_u8(b: u8) -> Option<Self> {
        use Opcode::*;
        Some(match b {
            0x01 => TermData,
            0x02 => TermResize,
            0x03 => Ping,
            0x04 => TermPaste,
            0x05 => FlowAck,
            0x10 => FrameRect,
            0x11 => InputMouse,
            0x12 => InputKey,
            0x13 => ClipboardSet,
            0x14 => ClipboardUpdate,
            0x15 => DesktopSize,
            0x16 => CursorShape,
            0x17 => DesktopResizeRequest,
            0x20 => StreamOpen,
            0x21 => StreamOpened,
            0x22 => StreamClose,
            0x24 => CredentialRequest,
            0x25 => CredentialSubmit,
            0x26 => HostIdentityPrompt,
            0x27 => HostIdentityDecision,
            0x28 => SessionState,
            0xFF => ControlError,
            _ => return None,
        })
    }

    /// Opcodes a client is allowed to send.
    pub fn client_may_send(self) -> bool {
        use Opcode::*;
        matches!(
            self,
            TermData
                | TermResize
                | Ping
                | TermPaste
                | FlowAck
                | InputMouse
                | InputKey
                | ClipboardSet
                | DesktopResizeRequest
                | StreamOpen
                | StreamClose
                | CredentialSubmit
                | HostIdentityDecision
        )
    }

    /// Opcodes a server is allowed to send.
    pub fn server_may_send(self) -> bool {
        use Opcode::*;
        matches!(
            self,
            TermData
                | Ping
                | FrameRect
                | ClipboardUpdate
                | DesktopSize
                | CursorShape
                | StreamOpened
                | StreamClose
                | CredentialRequest
                | HostIdentityPrompt
                | SessionState
                | ControlError
        )
    }

    /// Frames that carry user input (blocked while the vault is locked).
    pub fn is_user_input(self) -> bool {
        use Opcode::*;
        matches!(
            self,
            TermData | TermPaste | InputMouse | InputKey | ClipboardSet
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("frame shorter than header")]
    Short,
    #[error("frame exceeds {0} bytes")]
    TooLarge(usize),
    #[error("unknown opcode 0x{0:02x}")]
    UnknownOpcode(u8),
    #[error("opcode not allowed in this direction")]
    WrongDirection,
    #[error("malformed payload for {0:?}")]
    Payload(Opcode),
}

/// One decoded frame. `payload` is a zero-copy slice of the WebSocket message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub opcode: Opcode,
    pub stream_id: u32,
    pub payload: Bytes,
}

/// Decodes a client → server frame, enforcing size and direction.
pub fn decode_client(msg: Bytes) -> Result<Frame, WireError> {
    let f = decode(msg, MAX_CLIENT_FRAME)?;
    if !f.opcode.client_may_send() {
        return Err(WireError::WrongDirection);
    }
    Ok(f)
}

/// Decodes a server → client frame (used by clients and tests).
pub fn decode_server(msg: Bytes) -> Result<Frame, WireError> {
    let f = decode(msg, MAX_SERVER_FRAME)?;
    if !f.opcode.server_may_send() {
        return Err(WireError::WrongDirection);
    }
    Ok(f)
}

fn decode(mut msg: Bytes, max: usize) -> Result<Frame, WireError> {
    if msg.len() > max {
        return Err(WireError::TooLarge(max));
    }
    if msg.len() < HEADER_LEN {
        return Err(WireError::Short);
    }
    let opcode = Opcode::from_u8(msg[0]).ok_or(WireError::UnknownOpcode(msg[0]))?;
    let stream_id = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
    let payload = msg.split_off(HEADER_LEN);
    Ok(Frame {
        opcode,
        stream_id,
        payload,
    })
}

/// Encodes a frame with the header reserved up front (single allocation).
pub fn encode(opcode: Opcode, stream_id: u32, payload: &[u8]) -> Bytes {
    let mut b = BytesMut::with_capacity(HEADER_LEN + payload.len());
    b.put_u8(opcode as u8);
    b.put_u32(stream_id);
    b.put_slice(payload);
    b.freeze()
}

/// Encodes a JSON control frame.
pub fn encode_json<T: Serialize>(opcode: Opcode, stream_id: u32, value: &T) -> Bytes {
    let body = serde_json::to_vec(value).unwrap_or_default();
    encode(opcode, stream_id, &body)
}

fn be_u16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}
fn be_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}
fn be_u64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// `0x02 TermResize`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TermResize {
    pub cols: u16,
    pub rows: u16,
    pub px_w: u16,
    pub px_h: u16,
}

impl TermResize {
    pub fn parse(p: &[u8]) -> Result<Self, WireError> {
        let e = || WireError::Payload(Opcode::TermResize);
        if p.len() != 8 {
            return Err(e());
        }
        let r = Self {
            cols: be_u16(p, 0).ok_or_else(e)?,
            rows: be_u16(p, 2).ok_or_else(e)?,
            px_w: be_u16(p, 4).ok_or_else(e)?,
            px_h: be_u16(p, 6).ok_or_else(e)?,
        };
        if r.cols == 0 || r.rows == 0 || r.cols > 1000 || r.rows > 1000 {
            return Err(e());
        }
        Ok(r)
    }
    pub fn to_bytes(self) -> [u8; 8] {
        let mut o = [0u8; 8];
        o[0..2].copy_from_slice(&self.cols.to_be_bytes());
        o[2..4].copy_from_slice(&self.rows.to_be_bytes());
        o[4..6].copy_from_slice(&self.px_w.to_be_bytes());
        o[6..8].copy_from_slice(&self.px_h.to_be_bytes());
        o
    }
}

/// `0x03 Ping / Pong`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ping {
    pub pong: bool,
    pub seq: u32,
    pub t_us: u64,
    /// Gateway → target RTT in µs; `u32::MAX` = unknown.
    pub upstream_rtt_us: u32,
}

pub const RTT_UNKNOWN: u32 = u32::MAX;

impl Ping {
    pub fn parse(p: &[u8]) -> Result<Self, WireError> {
        let e = || WireError::Payload(Opcode::Ping);
        if p.len() != 17 || p[0] > 1 {
            return Err(e());
        }
        Ok(Self {
            pong: p[0] == 1,
            seq: be_u32(p, 1).ok_or_else(e)?,
            t_us: be_u64(p, 5).ok_or_else(e)?,
            upstream_rtt_us: be_u32(p, 13).ok_or_else(e)?,
        })
    }
    pub fn to_bytes(self) -> [u8; 17] {
        let mut o = [0u8; 17];
        o[0] = u8::from(self.pong);
        o[1..5].copy_from_slice(&self.seq.to_be_bytes());
        o[5..13].copy_from_slice(&self.t_us.to_be_bytes());
        o[13..17].copy_from_slice(&self.upstream_rtt_us.to_be_bytes());
        o
    }
}

/// `0x05 FlowAck`
pub fn parse_flow_ack(p: &[u8]) -> Result<u32, WireError> {
    if p.len() != 4 {
        return Err(WireError::Payload(Opcode::FlowAck));
    }
    be_u32(p, 0).ok_or(WireError::Payload(Opcode::FlowAck))
}

/// `0x22 StreamClose` reason codes and `0xFF ControlError` codes (docs/03 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Code {
    BadFrame = 1,
    UnknownStream = 2,
    StreamLimit = 3,
    Unauthorized = 4,
    VaultLocked = 5,
    NodeNotFound = 6,
    PolicyDenied = 7,
    DialFailed = 8,
    AuthFailed = 9,
    HostIdentityMismatch = 10,
    Timeout = 11,
    RunnerUnavailable = 12,
    TargetProtocolError = 13,
    RateLimited = 14,
    Internal = 15,
    ClosedByUser = 100,
    ClosedByRemote = 101,
    ClosedBySocketLoss = 102,
}

impl Code {
    pub fn from_u16(v: u16) -> Option<Self> {
        use Code::*;
        [
            BadFrame,
            UnknownStream,
            StreamLimit,
            Unauthorized,
            VaultLocked,
            NodeNotFound,
            PolicyDenied,
            DialFailed,
            AuthFailed,
            HostIdentityMismatch,
            Timeout,
            RunnerUnavailable,
            TargetProtocolError,
            RateLimited,
            Internal,
            ClosedByUser,
            ClosedByRemote,
            ClosedBySocketLoss,
        ]
        .into_iter()
        .find(|c| *c as u16 == v)
    }
}

/// `code u16 ‖ UTF-8 text` payload used by `StreamClose` and `ControlError`.
pub fn encode_coded(opcode: Opcode, stream_id: u32, code: Code, text: &str) -> Bytes {
    let mut p = Vec::with_capacity(2 + text.len());
    p.extend_from_slice(&(code as u16).to_be_bytes());
    p.extend_from_slice(text.as_bytes());
    encode(opcode, stream_id, &p)
}

pub fn parse_coded(opcode: Opcode, p: &[u8]) -> Result<(u16, String), WireError> {
    let code = be_u16(p, 0).ok_or(WireError::Payload(opcode))?;
    let text = std::str::from_utf8(&p[2..]).map_err(|_| WireError::Payload(opcode))?;
    Ok((code, text.to_owned()))
}

/// `0x20 StreamOpen`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamOpen {
    pub node_id: String,
    #[serde(default)]
    pub cols: Option<u16>,
    #[serde(default)]
    pub rows: Option<u16>,
    #[serde(default)]
    pub px_w: Option<u16>,
    #[serde(default)]
    pub px_h: Option<u16>,
    #[serde(default)]
    pub width: Option<u16>,
    #[serde(default)]
    pub height: Option<u16>,
    #[serde(default)]
    pub codecs: Vec<String>,
}

/// `0x21 StreamOpened`
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StreamOpened {
    pub protocol: String,
    pub route: String,
    pub runner: Option<String>,
    pub policy: serde_json::Value,
}

/// `0x24 CredentialRequest`
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CredentialRequest {
    pub fields: Vec<String>,
    pub username: Option<String>,
}

/// `0x25 CredentialSubmit` — secret fields land directly in zeroizing containers.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSubmit {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<SecretString>,
    #[serde(default)]
    pub private_key: Option<SecretString>,
    #[serde(default)]
    pub passphrase: Option<SecretString>,
}

impl CredentialSubmit {
    /// Parses the payload and wipes the frame buffer when it is uniquely owned.
    pub fn parse(payload: Bytes) -> Result<Self, WireError> {
        let parsed = serde_json::from_slice(&payload)
            .map_err(|_| WireError::Payload(Opcode::CredentialSubmit));
        if let Ok(mut owned) = payload.try_into_mut() {
            zeroize::Zeroize::zeroize(&mut owned[..]);
        }
        parsed
    }
}

/// `0x26 HostIdentityPrompt`
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HostIdentityPrompt {
    pub kind: String,
    pub algorithm: String,
    pub fingerprint: String,
    pub state: String,
}

/// `0x27 HostIdentityDecision`
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostIdentityDecision {
    pub approve: bool,
}

/// `0x28 SessionState`
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionState {
    pub vault: String,
    pub idle_lock_in_s: Option<u64>,
    pub session_expires_in_s: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn header_layout() {
        let f = encode(Opcode::TermData, 0x0102_0304, b"hi");
        assert_eq!(&f[..], &[0x01, 0x01, 0x02, 0x03, 0x04, b'h', b'i']);
        let d = decode_server(f).expect("decode");
        assert_eq!(
            (d.opcode, d.stream_id, &d.payload[..]),
            (Opcode::TermData, 0x0102_0304, &b"hi"[..])
        );
    }

    #[test]
    fn direction_and_size_enforced() {
        assert_eq!(
            decode_client(encode(Opcode::StreamOpened, 1, b"{}")),
            Err(WireError::WrongDirection)
        );
        assert_eq!(
            decode_server(encode(Opcode::StreamOpen, 1, b"{}")),
            Err(WireError::WrongDirection)
        );
        assert_eq!(
            decode_client(Bytes::from(vec![1u8; MAX_CLIENT_FRAME + 1])),
            Err(WireError::TooLarge(MAX_CLIENT_FRAME))
        );
        assert_eq!(
            decode_client(Bytes::from_static(&[1, 0, 0])),
            Err(WireError::Short)
        );
        assert_eq!(
            decode_client(Bytes::from_static(&[0x99, 0, 0, 0, 1])),
            Err(WireError::UnknownOpcode(0x99))
        );
    }

    #[test]
    fn payload_round_trips() {
        let r = TermResize {
            cols: 120,
            rows: 40,
            px_w: 1200,
            px_h: 800,
        };
        assert_eq!(TermResize::parse(&r.to_bytes()), Ok(r));
        assert!(TermResize::parse(&TermResize { cols: 0, ..r }.to_bytes()).is_err());
        let p = Ping {
            pong: true,
            seq: 7,
            t_us: 123_456_789,
            upstream_rtt_us: RTT_UNKNOWN,
        };
        assert_eq!(Ping::parse(&p.to_bytes()), Ok(p));
        assert_eq!(parse_flow_ack(&65536u32.to_be_bytes()), Ok(65536));
        let c = encode_coded(
            Opcode::ControlError,
            3,
            Code::VaultLocked,
            "vault is locked",
        );
        let f = decode_server(c).expect("decode");
        assert_eq!(
            parse_coded(f.opcode, &f.payload),
            Ok((5, "vault is locked".into()))
        );
        assert_eq!(Code::from_u16(10), Some(Code::HostIdentityMismatch));
    }

    #[test]
    fn credential_submit_is_redacted_and_buffer_wiped() {
        let raw = br#"{"username":"dev","password":"s3cret-pass"}"#.to_vec();
        let c = CredentialSubmit::parse(Bytes::from(raw)).expect("parse");
        assert_eq!(
            c.password.as_ref().map(SecretString::expose),
            Some("s3cret-pass")
        );
        assert!(!format!("{c:?}").contains("s3cret"));
        assert!(CredentialSubmit::parse(Bytes::from_static(b"{\"bogus\":1}")).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20_000))]
        /// Arbitrary bytes never panic any decoder.
        #[test]
        fn decoders_never_panic(data in proptest::collection::vec(any::<u8>(), 0..300)) {
            let b = Bytes::from(data);
            let _ = decode_client(b.clone());
            let _ = decode_server(b.clone());
            let _ = TermResize::parse(&b);
            let _ = Ping::parse(&b);
            let _ = parse_flow_ack(&b);
            let _ = parse_coded(Opcode::ControlError, &b);
            let _ = CredentialSubmit::parse(b.clone());
            let _ = serde_json::from_slice::<StreamOpen>(&b);
        }

        #[test]
        fn encode_decode_round_trip(op in prop::sample::select(vec![0x01u8, 0x02, 0x03, 0x04, 0x05, 0x11, 0x12, 0x13, 0x17, 0x20, 0x22, 0x25, 0x27]),
                                    id in any::<u32>(), payload in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let opcode = Opcode::from_u8(op).expect("valid");
            let f = decode_client(encode(opcode, id, &payload)).expect("decode");
            prop_assert_eq!(f.opcode, opcode);
            prop_assert_eq!(f.stream_id, id);
            prop_assert_eq!(&f.payload[..], &payload[..]);
        }
    }
}
