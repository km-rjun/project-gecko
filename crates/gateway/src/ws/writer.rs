//! Two-lane socket writer (docs/01 §4.1, docs/03 §6.3): the priority lane (pongs, control,
//! errors) always drains first; bulk frames are round-robin across streams with at most
//! [`BULK_PER_STREAM`] frames queued per stream.

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU16, Ordering},
    },
};

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use bytes::Bytes;
use futures_util::{SinkExt, stream::SplitSink};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

pub const BULK_PER_STREAM: usize = 4;
const PRIORITY_CAPACITY: usize = 256;

type Item = (Bytes, OwnedSemaphorePermit);

#[derive(Debug, Default)]
struct BulkInner {
    queues: HashMap<u32, VecDeque<Item>>,
    order: VecDeque<u32>,
}

#[derive(Debug, Default)]
struct Bulk {
    inner: Mutex<BulkInner>,
    notify: Notify,
}

impl Bulk {
    fn lock(&self) -> MutexGuard<'_, BulkInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn push(&self, stream_id: u32, item: Item) {
        let mut g = self.lock();
        let q = g.queues.entry(stream_id).or_default();
        let was_empty = q.is_empty();
        q.push_back(item);
        if was_empty {
            g.order.push_back(stream_id);
        }
        drop(g);
        self.notify.notify_one();
    }
    fn pop(&self) -> Option<Item> {
        let mut g = self.lock();
        while let Some(id) = g.order.pop_front() {
            let Some(q) = g.queues.get_mut(&id) else {
                continue;
            };
            let Some(item) = q.pop_front() else {
                g.queues.remove(&id);
                continue;
            };
            if q.is_empty() {
                g.queues.remove(&id);
            } else {
                g.order.push_back(id);
            }
            return Some(item);
        }
        None
    }
}

/// Sending side shared by the socket reader and stream tasks.
#[derive(Debug, Clone)]
pub struct Outbound {
    prio: mpsc::Sender<Bytes>,
    bulk: Arc<Bulk>,
    cancel: CancellationToken,
    close_code: Arc<AtomicU16>,
}

impl Outbound {
    /// Closes the socket with a WebSocket close code (pending priority frames are flushed first).
    pub fn close(&self, code: u16) {
        // First non-normal code wins.
        let _ = self
            .close_code
            .compare_exchange(1000, code, Ordering::Relaxed, Ordering::Relaxed);
        self.cancel.cancel();
    }

    /// Priority lane. Returns `false` when the socket is gone.
    pub async fn control(&self, frame: Bytes) -> bool {
        tokio::select! {
            r = self.prio.send(frame) => r.is_ok(),
            () = self.cancel.cancelled() => false,
        }
    }

    /// Bulk lane for one stream.
    pub fn lane(&self, stream_id: u32) -> BulkLane {
        BulkLane {
            stream_id,
            sem: Arc::new(Semaphore::new(BULK_PER_STREAM)),
            bulk: Arc::clone(&self.bulk),
            cancel: self.cancel.clone(),
        }
    }
}

/// Per-stream bulk sender; waits while the stream already has [`BULK_PER_STREAM`] frames queued.
#[derive(Debug)]
pub struct BulkLane {
    stream_id: u32,
    sem: Arc<Semaphore>,
    bulk: Arc<Bulk>,
    cancel: CancellationToken,
}

impl BulkLane {
    /// Returns `false` when the socket is gone.
    pub async fn send(&self, frame: Bytes) -> bool {
        let permit = tokio::select! {
            p = Arc::clone(&self.sem).acquire_owned() => match p { Ok(p) => p, Err(_) => return false },
            () = self.cancel.cancelled() => return false,
        };
        self.bulk.push(self.stream_id, (frame, permit));
        true
    }
}

/// Creates the outbound handle and spawns the writer task for `sink`.
pub fn spawn(sink: SplitSink<WebSocket, Message>, cancel: CancellationToken) -> Outbound {
    let (prio_tx, prio_rx) = mpsc::channel(PRIORITY_CAPACITY);
    let bulk = Arc::new(Bulk::default());
    let close_code = Arc::new(AtomicU16::new(1000));
    tokio::spawn(run(
        sink,
        prio_rx,
        Arc::clone(&bulk),
        cancel.clone(),
        Arc::clone(&close_code),
    ));
    Outbound {
        prio: prio_tx,
        bulk,
        cancel,
        close_code,
    }
}

async fn run(
    mut sink: SplitSink<WebSocket, Message>,
    mut prio: mpsc::Receiver<Bytes>,
    bulk: Arc<Bulk>,
    cancel: CancellationToken,
    close_code: Arc<AtomicU16>,
) {
    'outer: loop {
        while let Ok(f) = prio.try_recv() {
            if sink.send(Message::Binary(f)).await.is_err() {
                break 'outer;
            }
        }
        if let Some((f, permit)) = bulk.pop() {
            let ok = sink.send(Message::Binary(f)).await.is_ok();
            drop(permit);
            if !ok {
                break;
            }
            continue;
        }
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            f = prio.recv() => match f {
                Some(f) => if sink.send(Message::Binary(f)).await.is_err() { break },
                None => break,
            },
            () = bulk.notify.notified() => {}
        }
    }
    cancel.cancel();
    // Flush final control frames (errors, StreamClose) with a short deadline.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while let Ok(f) = prio.try_recv() {
            if sink.send(Message::Binary(f)).await.is_err() {
                break;
            }
        }
    })
    .await;
    let code = close_code.load(Ordering::Relaxed);
    let _ = sink
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: "".into(),
        })))
        .await;
    let _ = sink.close().await;
}
