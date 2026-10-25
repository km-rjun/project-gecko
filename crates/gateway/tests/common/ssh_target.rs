//! In-process SSH server used as a deterministic test target: password + public-key auth,
//! PTY/shell, echo, window-change recording and a window-respecting output flood.
#![allow(dead_code)]

use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use russh::{
    Channel, ChannelId,
    keys::{PrivateKey, PublicKey, ssh_key::private::Ed25519Keypair},
    server::{self, Auth, Msg, Session},
};

pub const USER: &str = "tester";
pub const PASSWORD: &str = "target-pass-123";
/// Bytes produced by the `FLOOD` command.
pub const FLOOD_BYTES: u64 = 8 * 1024 * 1024;

pub fn ed25519(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

#[derive(Default)]
pub struct Stats {
    pub resizes: Mutex<Vec<(u32, u32)>>,
    pub pty: Mutex<Option<(String, u32, u32)>>,
    pub flood_sent: AtomicU64,
    pub auth_attempts: AtomicU64,
}

pub struct SshTarget {
    pub addr: SocketAddr,
    pub stats: Arc<Stats>,
    host_key: Arc<Mutex<PrivateKey>>,
}

impl SshTarget {
    /// Replaces the host key used for new connections (simulates a re-installed or spoofed host).
    pub fn set_host_key(&self, key: PrivateKey) {
        *self.host_key.lock().expect("lock") = key;
    }
    pub fn fingerprint(&self) -> String {
        self.host_key
            .lock()
            .expect("lock")
            .public_key()
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string()
    }
}

/// Starts a target on 127.0.0.1 with the given host key; `client_key` is accepted for USER.
pub async fn start(host_key: PrivateKey, client_key: PublicKey) -> SshTarget {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let stats = Arc::new(Stats::default());
    let host_key = Arc::new(Mutex::new(host_key));
    let st = Arc::clone(&stats);
    let hk = Arc::clone(&host_key);
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let handler = Handler {
                stats: Arc::clone(&st),
                client_key: client_key.clone(),
                channel: None,
            };
            let config = Arc::new(server::Config {
                keys: vec![hk.lock().expect("lock").clone()],
                auth_rejection_time: std::time::Duration::from_millis(10),
                auth_rejection_time_initial: Some(std::time::Duration::ZERO),
                inactivity_timeout: None,
                ..Default::default()
            });
            tokio::spawn(async move {
                if let Ok(running) = server::run_stream(config, sock, handler).await {
                    let _ = running.await;
                }
            });
        }
    });
    SshTarget {
        addr,
        stats,
        host_key,
    }
}

struct Handler {
    stats: Arc<Stats>,
    client_key: PublicKey,
    channel: Option<Channel<Msg>>,
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.stats.auth_attempts.fetch_add(1, Ordering::Relaxed);
        Ok(if user == USER && password == PASSWORD {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        self.stats.auth_attempts.fetch_add(1, Ordering::Relaxed);
        Ok(
            if user == USER && key.key_data() == self.client_key.key_data() {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channel = Some(channel);
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        *self.stats.pty.lock().expect("lock") = Some((term.to_owned(), cols, rows));
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, &b"welcome to the test target\r\n"[..])?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _: ChannelId,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.stats.resizes.lock().expect("lock").push((cols, rows));
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if data.windows(5).any(|w| w == b"FLOOD") {
            let Some(ch) = self.channel.take() else {
                return Ok(());
            };
            let (mut read, write) = ch.split();
            // Drain the read half so the session loop never blocks on it.
            tokio::spawn(async move { while read.wait().await.is_some() {} });
            let stats = Arc::clone(&self.stats);
            tokio::spawn(async move {
                let chunk = bytes::Bytes::from(vec![b'y'; 16 * 1024]);
                let mut sent = 0u64;
                while sent < FLOOD_BYTES {
                    // `data_bytes` waits for the client's SSH window: this is the sshd analogue of a
                    // process blocking in write().
                    if write.data_bytes(chunk.clone()).await.is_err() {
                        return;
                    }
                    sent += chunk.len() as u64;
                    stats.flood_sent.store(sent, Ordering::Relaxed);
                }
                let _ = write
                    .data_bytes(bytes::Bytes::from_static(b"\r\nFLOOD-END\r\n"))
                    .await;
            });
            return Ok(());
        }
        if data == b"exit\r" {
            session.exit_status_request(channel, 0)?;
            session.close(channel)?;
            return Ok(());
        }
        session.data(channel, data.to_vec())?;
        Ok(())
    }
}
