//! systemd service notifications — `sd_notify` semantics over a unix
//! datagram, with no libsystemd dependency.
//!
//! systemd passes the endpoint in `$NOTIFY_SOCKET` (a filesystem path, or an
//! abstract socket whose name starts with `@`) and, when `WatchdogSec=` is
//! configured, the interval in `$WATCHDOG_USEC`. Every send failure is
//! deliberately swallowed: a notification that cannot reach systemd must
//! never take down a working tunnel.

use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// The notify channel for a running daemon.
pub struct Notify {
    socket: Option<UnixDatagram>,
    watchdog_interval: Option<Duration>,
    next_watchdog: Instant,
}

impl std::fmt::Debug for Notify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notify")
            .field("socket", &self.socket.is_some())
            .field("watchdog_interval", &self.watchdog_interval)
            .finish()
    }
}

impl Notify {
    /// Build a notify channel from the process environment. With no
    /// `$NOTIFY_SOCKET` — a test run, a foreground `vallum run` — the result
    /// sends nothing and `watchdog_interval` is `None`.
    pub fn from_env() -> Self {
        let socket =
            std::env::var_os("NOTIFY_SOCKET").and_then(|value| connect(PathBuf::from(value)));
        let watchdog_interval = std::env::var("WATCHDOG_USEC")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .filter(|usec| *usec > 0)
            .map(Duration::from_micros);
        Self {
            socket,
            watchdog_interval,
            next_watchdog: Instant::now(),
        }
    }

    /// A notify channel pointed at an explicit socket — for tests, where an
    /// environment variable would leak across threads.
    #[must_use]
    pub fn for_socket(socket: Option<UnixDatagram>, watchdog_interval: Option<Duration>) -> Self {
        Self {
            socket,
            watchdog_interval,
            next_watchdog: Instant::now(),
        }
    }

    /// `READY=1`: TUN is up, the UDP socket is bound, the control socket
    /// answers. Sent once after startup completes.
    pub fn ready(&self) {
        let _ = self.send("READY=1");
    }

    /// `STOPPING=1`: the run loop is winding down.
    pub fn stopping(&self) {
        let _ = self.send("STOPPING=1");
    }

    /// `WATCHDOG=1`, at most once per half of the configured interval. A
    /// daemon that stops petting is a daemon systemd restarts, which is the
    /// point: a wedged loop looks identical to a healthy one from outside.
    pub fn pet_watchdog(&mut self) {
        let Some(interval) = self.watchdog_interval else {
            return;
        };
        if Instant::now() < self.next_watchdog {
            return;
        }
        let _ = self.send("WATCHDOG=1");
        self.next_watchdog = Instant::now() + interval / 2;
    }

    fn send(&self, state: &str) -> io::Result<()> {
        match &self.socket {
            Some(socket) => socket.send(state.as_bytes()).map(|_| ()),
            None => Ok(()),
        }
    }
}

/// Connect to `$NOTIFY_SOCKET`. An `@` prefix names an abstract socket: the
/// name passed to `from_abstract_name` excludes that marker byte.
fn connect(path: PathBuf) -> Option<UnixDatagram> {
    #[cfg(target_os = "linux")]
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::SocketAddr;
    // Abstract names are a Linux namespace: off Linux a path is all a socket
    // address can be, so an `@` name simply fails to parse there.
    #[cfg(target_os = "linux")]
    if path.as_os_str().as_bytes().first() == Some(&b'@') {
        return <SocketAddr as std::os::linux::net::SocketAddrExt>::from_abstract_name(
            &path.as_os_str().as_bytes()[1..],
        )
        .ok()
        .and_then(|addr| {
            let socket = UnixDatagram::unbound().ok()?;
            socket.connect_addr(&addr).ok().map(|_| socket)
        });
    }
    let addr = SocketAddr::from_pathname(&path).ok()?;
    let socket = UnixDatagram::unbound().ok()?;
    socket.connect_addr(&addr).ok().map(|_| socket)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ready_and_stopping_reach_the_socket() {
        let dir = std::env::temp_dir().join(format!("vallum-notify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notify.sock");
        let listener = UnixDatagram::bind(&path).unwrap();
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let notifier = UnixDatagram::unbound().unwrap();
        notifier.connect(&path).unwrap();
        let notify = Notify::for_socket(Some(notifier), None);
        notify.ready();
        notify.stopping();
        let mut buf = [0u8; 64];
        let (n, _) = listener.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");
        let (n, _) = listener.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"STOPPING=1");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_socketless_notify_sends_nothing_and_never_panics() {
        let mut notify = Notify::for_socket(None, Some(Duration::from_millis(1)));
        notify.ready();
        notify.stopping();
        notify.pet_watchdog();
    }

    #[test]
    fn watchdog_fires_once_per_half_interval() {
        let dir = std::env::temp_dir().join(format!("vallum-notify-wd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notify.sock");
        let listener = UnixDatagram::bind(&path).unwrap();
        listener
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        // No watchdog interval configured: pets are no-ops.
        let notifier = UnixDatagram::unbound().unwrap();
        notifier.connect(&path).unwrap();
        let mut idle = Notify::for_socket(Some(notifier), None);
        idle.pet_watchdog();
        assert!(listener.recv_from(&mut [0u8; 64]).is_err());
        // With an interval, the first pet fires immediately and the second is
        // throttled until half the interval has passed.
        let notifier = UnixDatagram::unbound().unwrap();
        notifier.connect(&path).unwrap();
        let mut active = Notify::for_socket(Some(notifier), Some(Duration::from_secs(30)));
        let mut buf = [0u8; 64];
        active.pet_watchdog();
        let (n, _) = listener.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"WATCHDOG=1");
        active.pet_watchdog();
        assert!(listener.recv_from(&mut buf).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
