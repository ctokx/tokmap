//! TCP connect probing shared by the port scan and host discovery.

use futures::stream::{self, StreamExt};
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpSocket;
use tokio::sync::Semaphore;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Answer {
    Open(u64),
    Closed,
    Silent,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Transport {
    Tcp,
    Udp,
}

/// Each loss signal halves the send rate, down to 1/32 of normal.
const MAX_BACKOFF: u32 = 5;

/// Spreads probes out to honour a packets-per-second limit.
pub struct Pacer {
    gap: Option<Duration>,
    next: Mutex<Instant>,
}

impl Pacer {
    pub fn new(rate: Option<u32>) -> Self {
        Self {
            gap: rate.filter(|&r| r > 0).map(|r| Duration::from_secs_f64(1.0 / r as f64)),
            next: Mutex::new(Instant::now()),
        }
    }

    fn reserve_slot(&self) -> Option<Instant> {
        let gap = self.gap?;
        let mut next = self.next.lock().unwrap();
        let slot = (*next).max(Instant::now());
        *next = slot + gap;
        Some(slot)
    }

    pub async fn wait(&self) {
        if let Some(slot) = self.reserve_slot() {
            tokio::time::sleep_until(slot.into()).await;
        }
    }

    pub fn wait_blocking(&self) {
        if let Some(slot) = self.reserve_slot() {
            std::thread::sleep(slot.saturating_duration_since(Instant::now()));
        }
    }
}

/// Scan-wide budget, shared by every host so parallel hosts cannot exceed it.
#[derive(Clone)]
pub struct Limits {
    pub sockets: Arc<Semaphore>,
    pub pacer: Arc<Pacer>,
    pub max_sockets: usize,
    backoff: Arc<AtomicU32>,
}

impl Limits {
    pub fn new(max_concurrent: usize, rate: Option<u32>) -> Self {
        let max_sockets = socket_budget(max_concurrent.max(1));
        Self {
            sockets: Arc::new(Semaphore::new(max_sockets)),
            pacer: Arc::new(Pacer::new(rate)),
            max_sockets,
            backoff: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Records that a retry found answers the first try missed, so the network is dropping
    /// packets. Shared by all hosts, so later hosts start at the safer speed too.
    pub fn note_loss(&self) {
        let _ = self.backoff.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |level| {
            (level < MAX_BACKOFF).then_some(level + 1)
        });
    }

    pub fn backoff(&self) -> u32 {
        self.backoff.load(Ordering::Relaxed)
    }

    pub async fn probe(&self, addr: SocketAddr, wait: Duration, transport: Transport) -> Answer {
        let _permit = self.sockets.acquire().await.expect("semaphore is never closed");
        self.pacer.wait().await;
        match transport {
            Transport::Tcp => connect_once(addr, wait).await,
            Transport::Udp => crate::udp::probe_once(addr, wait).await,
        }
    }
}

pub async fn connect_once(addr: SocketAddr, wait: Duration) -> Answer {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    };
    // Running out of sockets counts as Silent, so the retry pass probes the port again.
    let Ok(socket) = socket else { return Answer::Silent };
    fail_fast(&socket);

    let start = Instant::now();
    match tokio::time::timeout(wait, socket.connect(addr)).await {
        Ok(Ok(stream)) => {
            // Close with RST: thousands of scanned ports must not sit in TIME_WAIT.
            let _ = stream.set_zero_linger();
            // On loopback the OS can pick the target port as our source port. The socket then
            // connects to itself, which looks open but is not a service.
            if stream.local_addr().is_ok_and(|local| local == addr) {
                return Answer::Closed;
            }
            Answer::Open(start.elapsed().as_millis() as u64)
        }
        Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => Answer::Closed,
        _ => Answer::Silent,
    }
}

/// Probes every port, retrying silent ones. Every port appears exactly once in the result.
pub async fn sweep(
    ip: IpAddr,
    ports: &[u16],
    wait: Duration,
    retries: u32,
    limits: &Limits,
    transport: Transport,
) -> Vec<(u16, Answer)> {
    let mut done = Vec::with_capacity(ports.len());
    let mut pending = ports.to_vec();

    for attempt in 0..=retries {
        let answers = sweep_pass(ip, &pending, wait, limits, transport).await;
        let before = done.len();
        pending.clear();
        for (port, answer) in answers {
            match answer {
                Answer::Silent => pending.push(port),
                _ => done.push((port, answer)),
            }
        }
        let recovered = done.len() > before;
        if attempt > 0 && recovered {
            limits.note_loss();
        }
        // Keep retrying only while retries still turn up answers.
        if pending.is_empty() || (attempt > 0 && !recovered) {
            break;
        }
    }

    done.extend(pending.into_iter().map(|port| (port, Answer::Silent)));
    done
}

async fn sweep_pass(
    ip: IpAddr,
    ports: &[u16],
    wait: Duration,
    limits: &Limits,
    transport: Transport,
) -> Vec<(u16, Answer)> {
    // One stream polls on one thread, and socket setup is the cost here, so shard across cores.
    let cores = std::thread::available_parallelism().map_or(4, |n| n.get());
    let sockets = (limits.max_sockets >> limits.backoff()).max(1);
    let workers = cores.min(sockets).min(ports.len()).max(1);
    let in_flight = (sockets / workers).max(1);

    let tasks: Vec<_> = ports
        .chunks(ports.len().div_ceil(workers).max(1))
        .map(|chunk| {
            let chunk = chunk.to_vec();
            let limits = limits.clone();
            tokio::spawn(async move {
                stream::iter(chunk)
                    .map(|port| {
                        let limits = &limits;
                        async move { (port, limits.probe(SocketAddr::new(ip, port), wait, transport).await) }
                    })
                    .buffer_unordered(in_flight)
                    .collect::<Vec<_>>()
                    .await
            })
        })
        .collect();

    let mut answers = Vec::with_capacity(ports.len());
    for task in tasks {
        answers.extend(task.await.expect("sweep worker panicked"));
    }
    answers
}

/// Windows retries a refused connect for about 2s. Without this every closed port looks filtered.
/// Lost SYNs are covered by the retry pass in `sweep`.
#[cfg(windows)]
fn fail_fast(socket: &TcpSocket) {
    use std::os::windows::io::AsRawSocket;

    // _WSAIOW(IOC_VENDOR, 17)
    const SIO_TCP_INITIAL_RTO: u32 = 0x9800_0011;
    const UNSPECIFIED_RTT: u16 = 0xFFFF;
    const NO_SYN_RETRANSMISSIONS: u8 = 0xFE;

    #[repr(C)]
    struct InitialRto {
        rtt: u16,
        max_syn_retransmissions: u8,
    }

    #[link(name = "ws2_32")]
    extern "system" {
        fn WSAIoctl(
            socket: usize,
            code: u32,
            input: *const core::ffi::c_void,
            input_len: u32,
            output: *mut core::ffi::c_void,
            output_len: u32,
            returned: *mut u32,
            overlapped: *mut core::ffi::c_void,
            completion: *mut core::ffi::c_void,
        ) -> i32;
    }

    let params = InitialRto {
        rtt: UNSPECIFIED_RTT,
        max_syn_retransmissions: NO_SYN_RETRANSMISSIONS,
    };
    let mut returned = 0u32;
    // Safe: `params` outlives this synchronous call and the sizes match. Failure only means slower closed ports.
    unsafe {
        WSAIoctl(
            socket.as_raw_socket() as usize,
            SIO_TCP_INITIAL_RTO,
            (&params as *const InitialRto).cast(),
            std::mem::size_of::<InitialRto>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
    }
}

#[cfg(not(windows))]
fn fail_fast(_socket: &TcpSocket) {}

/// Raises the open-file limit if it can, and caps concurrency to what the OS allows.
#[cfg(unix)]
fn socket_budget(wanted: usize) -> usize {
    const RESERVED: u64 = 64; // stdio, data files, capture handles

    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // Safe: both calls only read or write the local `limit`.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return wanted.min(256);
        }
        let needed = wanted as u64 + RESERVED;
        if (limit.rlim_cur as u64) < needed {
            let raised = libc::rlimit {
                rlim_cur: needed.min(limit.rlim_max as u64) as _,
                rlim_max: limit.rlim_max,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &raised) == 0 {
                limit = raised;
            }
        }
    }
    wanted.min((limit.rlim_cur as u64).saturating_sub(RESERVED).max(1) as usize)
}

#[cfg(not(unix))]
fn socket_budget(wanted: usize) -> usize {
    wanted
}

/// Linux stalls a multi-threaded process for an RCU grace period (50ms+) each time its file
/// table doubles, so grow the table once while the process is still single-threaded.
#[cfg(unix)]
pub fn prepare_socket_table(max_sockets: usize) {
    let highest = socket_budget(max_sockets.max(1)) as i32 + 32;
    // Safe: duplicates stderr to an unused high descriptor and closes it again.
    unsafe {
        if libc::dup2(libc::STDERR_FILENO, highest) == highest {
            libc::close(highest);
        }
    }
}

#[cfg(not(unix))]
pub fn prepare_socket_table(_max_sockets: usize) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    async fn closed_port() -> u16 {
        let listener = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
        listener.local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn open_and_closed_ports_are_told_apart() {
        let listener = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
        let open = listener.local_addr().unwrap().port();
        let closed = closed_port().await;
        let wait = Duration::from_secs(1);

        assert!(matches!(connect_once((LOCALHOST, open).into(), wait).await, Answer::Open(_)));
        assert_eq!(connect_once((LOCALHOST, closed).into(), wait).await, Answer::Closed);
    }

    #[tokio::test]
    async fn closed_port_answers_without_os_retries() {
        let closed = closed_port().await;
        let start = Instant::now();
        connect_once((LOCALHOST, closed).into(), Duration::from_secs(5)).await;
        assert!(start.elapsed() < Duration::from_millis(500), "took {:?}", start.elapsed());
    }

    #[tokio::test]
    async fn sweep_reports_every_port_exactly_once() {
        let limits = Limits::new(8, None);
        let ports: Vec<u16> = (40000..40100).collect();
        let mut seen: Vec<u16> = sweep(LOCALHOST, &ports, Duration::from_secs(1), 1, &limits, Transport::Tcp)
            .await
            .into_iter()
            .map(|(port, _)| port)
            .collect();
        seen.sort_unstable();
        assert_eq!(seen, ports);
    }

    #[test]
    fn loss_backs_off_in_steps_and_stops_at_the_floor() {
        let limits = Limits::new(64, None);
        assert_eq!(limits.backoff(), 0);
        for _ in 0..20 {
            limits.note_loss();
        }
        assert_eq!(limits.backoff(), MAX_BACKOFF);
    }

    #[tokio::test]
    async fn pacer_spaces_probes_and_treats_zero_as_unlimited() {
        let pacer = Pacer::new(Some(100));
        let start = Instant::now();
        for _ in 0..4 {
            pacer.wait().await;
        }
        assert!(start.elapsed() >= Duration::from_millis(25));

        let unlimited = Pacer::new(Some(0));
        let start = Instant::now();
        for _ in 0..1000 {
            unlimited.wait().await;
        }
        assert!(start.elapsed() < Duration::from_millis(100));
    }
}
