//! Outbound connections to targets. `DirectDialer` now; the edge-runner `PoolDialer` later (docs/05 §5.3).

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

/// Any bidirectional byte stream to a target.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

pub type BoxStream = Box<dyn AsyncStream>;

#[derive(Debug, thiserror::Error)]
pub enum DialError {
    #[error("connection timed out")]
    Timeout,
    #[error("connection failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("no edge runner available")]
    RunnerUnavailable,
}

#[async_trait::async_trait]
pub trait Dialer: Send + Sync {
    async fn dial(&self, host: &str, port: u16) -> Result<BoxStream, DialError>;
}

/// Plain TCP from the gateway host.
#[derive(Debug, Clone)]
pub struct DirectDialer {
    pub timeout: Duration,
}

impl Default for DirectDialer {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }
}

#[async_trait::async_trait]
impl Dialer for DirectDialer {
    async fn dial(&self, host: &str, port: u16) -> Result<BoxStream, DialError> {
        let stream =
            tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect((host, port)))
                .await
                .map_err(|_| DialError::Timeout)??;
        stream.set_nodelay(true)?;
        Ok(Box::new(stream))
    }
}
