//! Workspace-socket test client over a real TCP listener.
#![allow(dead_code)]

use std::{net::SocketAddr, time::Duration};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use protocol_core::wire::{self, Frame, Opcode};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{Message, client::IntoClientRequest, http::HeaderValue},
};

use super::{ORIGIN, TestApp};

/// Serves the app on an ephemeral port with real connect info.
pub async fn serve(app: &TestApp) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let router = gateway::http::router(app.state.clone());
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("serve");
    });
    addr
}

pub struct Ws {
    pub inner: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

/// Opens `/api/ws` with optional cookie/origin/subprotocol; returns the HTTP status on rejection.
pub async fn connect(
    addr: SocketAddr,
    cookie: Option<&str>,
    origin: Option<&str>,
    subprotocol: Option<&str>,
) -> Result<Ws, u16> {
    let mut req = format!("ws://{addr}/api/ws")
        .into_client_request()
        .expect("request");
    let h = req.headers_mut();
    if let Some(c) = cookie {
        h.insert(
            "cookie",
            HeaderValue::from_str(&format!("gw_session={c}")).expect("cookie"),
        );
    }
    if let Some(o) = origin {
        h.insert("origin", HeaderValue::from_str(o).expect("origin"));
    }
    if let Some(p) = subprotocol {
        h.insert(
            "sec-websocket-protocol",
            HeaderValue::from_str(p).expect("proto"),
        );
    }
    match tokio_tungstenite::connect_async(req).await {
        Ok((inner, _)) => Ok(Ws { inner }),
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => Err(r.status().as_u16()),
        Err(e) => panic!("ws connect: {e}"),
    }
}

pub async fn open(addr: SocketAddr, cookie: &str) -> Ws {
    connect(addr, Some(cookie), Some(ORIGIN), Some("workspace.v1"))
        .await
        .expect("ws upgrade")
}

pub const TIMEOUT: Duration = Duration::from_secs(10);

impl Ws {
    pub async fn send(&mut self, opcode: Opcode, stream: u32, payload: &[u8]) {
        self.inner
            .send(Message::Binary(wire::encode(opcode, stream, payload)))
            .await
            .expect("send");
    }

    pub async fn send_json(&mut self, opcode: Opcode, stream: u32, v: &Value) {
        self.send(opcode, stream, v.to_string().as_bytes()).await;
    }

    /// Next frame other than server pings/SessionState; `None` when the socket closed.
    pub async fn next(&mut self) -> Option<Frame> {
        self.next_within(TIMEOUT).await
    }

    pub async fn next_within(&mut self, t: Duration) -> Option<Frame> {
        loop {
            let msg = tokio::time::timeout(t, self.inner.next()).await.ok()??;
            match msg.ok()? {
                Message::Binary(b) => {
                    let f = wire::decode_server(Bytes::from(b.to_vec())).expect("server frame");
                    if (f.opcode == Opcode::Ping && f.stream_id == 0 && f.payload[0] == 0)
                        || f.opcode == Opcode::SessionState
                    {
                        continue;
                    }
                    return Some(f);
                }
                Message::Close(_) => return None,
                _ => {}
            }
        }
    }

    /// Waits for a frame with the given opcode, collecting TermData text seen on the way.
    pub async fn expect(&mut self, opcode: Opcode) -> (Frame, String) {
        let mut text = String::new();
        loop {
            let f = self.next().await.unwrap_or_else(|| {
                panic!("socket closed while waiting for {opcode:?}; saw {text:?}")
            });
            if f.opcode == opcode {
                return (f, text);
            }
            if f.opcode == Opcode::TermData {
                text.push_str(&String::from_utf8_lossy(&f.payload));
                continue;
            }
            if f.opcode == Opcode::ControlError || f.opcode == Opcode::StreamClose {
                let (code, msg) = wire::parse_coded(f.opcode, &f.payload).expect("coded");
                panic!(
                    "waiting for {opcode:?}, got {:?} code={code} {msg}",
                    f.opcode
                );
            }
        }
    }

    /// Reads TermData (acking it) until `needle` appears.
    pub async fn read_until(&mut self, stream: u32, needle: &str) -> String {
        let mut text = String::new();
        while !text.contains(needle) {
            let f = self
                .next()
                .await
                .unwrap_or_else(|| panic!("closed before {needle:?}; saw {text:?}"));
            match f.opcode {
                Opcode::TermData if f.stream_id == stream => {
                    text.push_str(&String::from_utf8_lossy(&f.payload));
                    self.ack(stream, f.payload.len()).await;
                }
                Opcode::ControlError | Opcode::StreamClose => {
                    let (code, msg) = wire::parse_coded(f.opcode, &f.payload).expect("coded");
                    panic!("waiting for {needle:?}: {:?} code={code} {msg}", f.opcode);
                }
                _ => {}
            }
        }
        text
    }

    pub async fn ack(&mut self, stream: u32, n: usize) {
        self.send(
            Opcode::FlowAck,
            stream,
            &u32::try_from(n).expect("u32").to_be_bytes(),
        )
        .await;
    }

    pub async fn type_text(&mut self, stream: u32, s: &str) {
        self.send(Opcode::TermData, stream, s.as_bytes()).await;
    }
}

pub fn coded(f: &Frame) -> (u16, String) {
    wire::parse_coded(f.opcode, &f.payload).expect("coded payload")
}

pub fn json(f: &Frame) -> Value {
    serde_json::from_slice(&f.payload).expect("json payload")
}
