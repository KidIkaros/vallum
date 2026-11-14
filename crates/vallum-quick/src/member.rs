// SPDX-License-Identifier: Apache-2.0

//! The shared member namespace: ADR-0023's exclusive path.
//!
//! A mark applied in an output chain cannot give a member's socket the tunnel's
//! source address — the socket picks its route and source at `connect()` time,
//! before the chain runs (measured; `docs/proof/socket-cgroupv2.md`). A network
//! namespace does not have that problem: the route exists before the socket
//! does. So `[quick] app_class = true` installs one shared namespace, moves the
//! tunnel device into it, and launches members there.
//!
//! The pieces, in the order they execute:
//!
//! - **attach** [`attach`]: create a holder process in a new mount and network
//!   namespace (`unshare --propagation private --mount --net`), bind a private
//!   `resolv.conf` naming the pushed resolvers when `[quick] dns` is set, move
//!   the tunnel device into it, and give it its addresses and a default route.
//!   The host keeps its own routing untouched — that is the split.
//! - **app** [`app_run`]: prove the namespace and the device are there, then
//!   `nsenter` into it and `exec` the command. Membership is being in the
//!   namespace; there is no mark to set and no leaf to sweep.
//! - **detach** [`detach`]: move the device back to this process's namespace
//!   (the host's, where the daemon lives) and stop the holder. A holder that
//!   died took the device with it; the record is removed either way.
//!
//! # When the holder dies
//!
//! Measured in a real `init_net` (`docs/proof/member-netns.md`): the kernel
//! destroys a network namespace's devices with it, so `kill -9` on the holder
//! does not hand the tunnel back — the device ceases to exist and the daemon is
//! left without an interface. Quick cannot recreate a TUN the daemon owns, so
//! recovery is a daemon restart, and the shape of it depends on who owns the
//! daemon: `up` owns the one it spawned and restarts it itself, while `attach`
//! (the systemd form) names the unit to restart. What quick must never do is
//! pretend: a stale record that says "attached" while the device is gone makes
//! every later `app` fail with advice that cannot work.
//!
//! Measured in the lab (`docs/proof/member-netns.md`): a member's fetch arrived
//! from the tunnel's address while a host process kept its physical one, DNS
//! resolved through the tunnel from a private `resolv.conf`, and the daemon and
//! its control plane survived the move.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use vallum_config::Config;

use crate::routes;

const READY_TIMEOUT: Duration = Duration::from_secs(5);
const HOLDER_EXIT_TIMEOUT: Duration = Duration::from_secs(5);

/// The record an attach writes: everything detach needs when the config has
/// been edited since.
///
/// One line per field rather than a serialized struct, the way the route record
/// is one line per command: a file an operator can read, and a parser with one
/// job. `pid` is the holder process, which is also the namespace handle.
///
/// `start` is the holder's `/proc/<pid>/stat` start time, recorded so a pid the
/// kernel has since recycled is not mistaken for the holder — the recovery path
/// kills what the record names, and pids are reused quickly. It is optional so a
/// record written before this field existed still parses.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    pid: u32,
    start: Option<u64>,
    interface: String,
}

fn record_path(interface: &str) -> PathBuf {
    routes::state_dir().join(format!("{interface}.quick-ns"))
}

fn resolv_path(interface: &str) -> PathBuf {
    routes::state_dir().join(format!("{interface}.quick-ns.resolv"))
}

fn log_path(interface: &str) -> PathBuf {
    routes::state_dir().join(format!("{interface}.quick-ns.log"))
}

fn ready_path(interface: &str) -> PathBuf {
    routes::state_dir().join(format!("{interface}.quick-ns.ready"))
}

/// Only a full tunnel can carry the class: the member namespace's default route
/// is the tunnel device, so `allowed_ips` must claim `0.0.0.0/0` (or `::/0`)
/// for the far side to accept what the members send.
///
/// An address is required too: it becomes the namespace's source address, and a
/// namespace with a device and no address routes nothing.
pub(crate) fn check_config(config: &Config) -> Result<(), String> {
    let full = config.peers.iter().any(|peer| {
        peer.allowed_ips
            .iter()
            .filter_map(|string| string.parse().ok())
            .any(|prefix: routes::Prefix| prefix.as_ipnet().prefix_len() == 0)
    });
    if !full {
        return Err(
            "`app_class = true` needs a full tunnel (`allowed_ips` with 0.0.0.0/0 or ::/0): \
             the member namespace routes everything into the tunnel device, and a \
             prefix-list tunnel would drop what it cannot carry"
                .to_owned(),
        );
    }
    if addresses(config).is_empty() {
        return Err(
            "`app_class = true` needs `[interface] address` (or `addresses`): it becomes \
             the source address inside the member namespace, and without one the \
             namespace has no route to give its members"
                .to_owned(),
        );
    }
    Ok(())
}

/// Every address the interface carries, in config order.
pub(crate) fn addresses(config: &Config) -> Vec<String> {
    let mut all: Vec<String> = config.interface.addresses.clone();
    if let Some(address) = &config.interface.address {
        if !all.contains(address) {
            all.insert(0, address.clone());
        }
    }
    all
}

/// The private `resolv.conf` the namespace reads.
///
/// Only `nameserver` lines: a search domain is a resolver policy the tunnel did
/// not push, and inventing one here would be a claim the config did not make.
fn resolv_text(servers: &[String]) -> String {
    let mut text = String::from("# written by vallum-quick for the member namespace\n");
    for server in servers {
        text.push_str(&format!("nameserver {server}\n"));
    }
    text
}

fn parse_record(text: &str) -> Option<Record> {
    let mut pid = None;
    let mut start = None;
    let mut interface = None;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        match (fields.next(), fields.next()) {
            (Some("pid"), Some(value)) => pid = value.parse::<u32>().ok(),
            (Some("start"), Some(value)) => start = value.parse::<u64>().ok(),
            (Some("interface"), Some(value)) => interface = Some(value.to_owned()),
            _ => {}
        }
    }
    Some(Record {
        pid: pid?,
        start,
        interface: interface?,
    })
}

fn render_record(record: &Record) -> String {
    let mut text = format!("pid {}\n", record.pid);
    if let Some(start) = record.start {
        text.push_str(&format!("start {start}\n"));
    }
    text.push_str(&format!("interface {}\n", record.interface));
    text
}

/// A process's start time, in clock ticks since boot, from
/// `/proc/<pid>/stat`'s 22nd field.
///
/// The second field is the executable name in parentheses and may contain
/// spaces, so the split starts after the last `)` rather than tokenizing the
/// whole line. Field 3 (`state`) is the first token after it, which makes the
/// start time the 20th.
fn proc_start(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = stat.rsplit_once(')')?.1;
    tail.split_whitespace().nth(19)?.parse().ok()
}

/// Whether the record still names *our* holder.
///
/// A live pid is not enough: after a crash the kernel can reuse it for an
/// unrelated process, and acting on the record means signalling that pid. When
/// the record carries a start time it is authoritative; a record from before the
/// field existed falls back to the device, which only our holder can own.
fn is_holder(record: &Record) -> bool {
    if !alive(record.pid) {
        return false;
    }
    match record.start {
        Some(start) => proc_start(record.pid) == Some(start),
        None => device_in_namespace(record),
    }
}

fn read_record(interface: &str) -> Option<Record> {
    parse_record(&fs::read_to_string(record_path(interface)).ok()?)
}

fn write_record(interface: &str, pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    let path = record_path(interface);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        &path,
        render_record(&Record {
            pid,
            start: proc_start(pid),
            interface: interface.to_owned(),
        }),
    )?;
    Ok(())
}

/// Whether the tunnel device exists in this process's namespace.
///
/// `up` asks this before it starts a daemon: a tunnel that is not there means the
/// daemon recorded from a previous run cannot serve this config, whatever its pid
/// file says.
pub(crate) fn device_present(interface: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", "dev", interface])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Fail, and forget the record, when the device went with its holder.
///
/// `attach` runs this before it waits for an interface: waiting is pointless for
/// a device that no longer exists, and the generic "nothing started the daemon"
/// message would send the operator looking for a `pre_up` hook instead of
/// restarting the daemon that lost its interface. The record is removed because
/// a record naming a namespace that does not exist is a lie every later `app`
/// repeats.
pub(crate) fn refuse_if_device_lost(
    interface: &str,
    unit: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(record) = read_record(interface) else {
        return Ok(());
    };
    if is_holder(&record) || device_present(&record.interface) {
        return Ok(());
    }
    let _ = fs::remove_file(record_path(interface));
    Err(holder_lost_message(interface, record.pid, unit).into())
}
/// How to get a tunnel interface back once it is gone.
///
/// The two remedies are the two ownership models: `up` starts the daemon it
/// owns, and `attach` (the systemd form) is told which unit to restart. A unit
/// name is never guessed — see [`crate::session::interface_missing`] for why.
fn restart_hint(interface: &str, unit: Option<&str>) -> String {
    match unit {
        Some(unit) => format!(
            "restart the daemon (`systemctl restart vallum@{unit}`) so it creates a new \
             `{interface}`, then attach again"
        ),
        None => format!("restart the daemon so it creates a new `{interface}`, then attach again"),
    }
}

/// The message for the failure quick cannot fix itself: the holder died and took
/// the device with it, so the daemon has no interface to move.
fn holder_lost_message(interface: &str, pid: u32, unit: Option<&str>) -> String {
    format!(
        "the member namespace holder (pid {pid}) is gone and `{interface}` went with it: a \
         network namespace destroys the devices it holds, so the daemon has no interface to \
         move into a new namespace. {}",
        restart_hint(interface, unit)
    )
}

/// The message for a device that is not here and was never recorded as held by
/// a namespace: the daemon that owns it is not running, or has lost it.
fn missing_device_message(interface: &str, unit: Option<&str>) -> String {
    format!(
        "`{interface}` is not in this namespace, so there is nothing to move: the daemon \
         that owns it is not running, or has lost it (a network namespace destroys the \
         devices it holds when its holder dies). {}",
        restart_hint(interface, unit)
    )
}

/// A pid is alive if its `/proc` entry exists. No `kill -0`, no libc: the mount
/// is the same one the process was seen in, and a stale pid cannot be signalled
/// by accident this way.
fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Whether the tunnel device is inside the holder's network namespace — the
/// property `app` depends on and the one a half-finished attach would miss.
fn device_in_namespace(record: &Record) -> bool {
    Command::new("nsenter")
        .args([
            "-t",
            &record.pid.to_string(),
            "-n",
            "--",
            "ip",
            "link",
            "show",
            "dev",
        ])
        .arg(&record.interface)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn run_ip(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("ip").args(args).status()?;
    if !status.success() {
        return Err(format!("`ip {}` failed", args.join(" ")).into());
    }
    Ok(())
}

fn ip_in(pid: u32, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("nsenter")
        .args(["-t", &pid.to_string(), "-n", "--", "ip"])
        .args(args)
        .status()?;
    if !status.success() {
        return Err(format!("`ip {}` failed inside the member namespace", args.join(" ")).into());
    }
    Ok(())
}

/// The holder: `unshare` unshares in its own process, so the pid the caller
/// records is the namespace handle `ip link … netns` and `nsenter -t` both
/// take. It writes a ready token only after the bind mount succeeded, so a
/// failed mount is an attach failure, not a member with the host's resolver.
fn spawn_holder(
    interface: &str,
    resolv: Option<&Path>,
    ready: &Path,
) -> Result<u32, Box<dyn std::error::Error>> {
    let log = fs::File::create(log_path(interface))?;
    let mut command = Command::new("unshare");
    command.args([
        "--propagation",
        "private",
        "--mount",
        "--net",
        "--",
        "bash",
        "-c",
    ]);
    match resolv {
        Some(path) => {
            command
                .arg("mount --bind \"$1\" /etc/resolv.conf || exit 1; : > \"$2\"; exec sleep infinity")
                .arg("_")
                .arg(path)
                .arg(ready);
        }
        None => {
            command
                .arg(": > \"$1\"; exec sleep infinity")
                .arg("_")
                .arg(ready);
        }
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));

    let child = command.spawn()?;
    let pid = child.id();
    let deadline = Instant::now() + READY_TIMEOUT;
    while Instant::now() < deadline {
        if ready.exists() {
            return Ok(pid);
        }
        if !alive(pid) {
            break;
        }
        sleep(Duration::from_millis(50));
    }
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status();
    Err(format!(
        "the member namespace holder did not come up (pid {pid}); see {}",
        log_path(interface).display()
    )
    .into())
}

fn configure(config: &Config, interface: &str, pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    let all = addresses(config);
    run_ip(&["link", "set", interface, "netns", &pid.to_string()])?;
    ip_in(pid, &["link", "set", "lo", "up"])?;
    ip_in(pid, &["link", "set", interface, "up"])?;
    let mut v4 = false;
    let mut v6 = false;
    for address in &all {
        let is_v6 = address.contains(':');
        v4 |= !is_v6;
        v6 |= is_v6;
        if is_v6 {
            ip_in(pid, &["-6", "addr", "replace", address, "dev", interface])?;
        } else {
            ip_in(pid, &["addr", "replace", address, "dev", interface])?;
        }
    }
    if v4 {
        ip_in(pid, &["route", "replace", "default", "dev", interface])?;
    }
    if v6 {
        ip_in(
            pid,
            &["-6", "route", "replace", "default", "dev", interface],
        )?;
    }
    Ok(())
}

/// Put the device back on the host and stop the holder: the reversal of
/// [`attach`], used by detach, rollback and the stale-record path.
fn teardown(interface: &str, pid: u32) {
    // The device lives in the holder's namespace, so the move has to be issued
    // *there*: `ip` resolves names in its own netns, and quick's own namespace
    // has no `vallum0` to look up anymore.
    let self_pid = std::process::id().to_string();
    let moved = Command::new("nsenter")
        .args([
            "-t",
            &pid.to_string(),
            "-n",
            "--",
            "ip",
            "link",
            "set",
            interface,
            "netns",
            &self_pid,
        ])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !moved && alive(pid) {
        eprintln!(
            "vallum-quick: note   `{interface}` could not be moved back out of the \
             member namespace (holder pid {pid}); the daemon has lost its interface \
             and must be restarted"
        );
    }
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status();
    let deadline = Instant::now() + HOLDER_EXIT_TIMEOUT;
    while alive(pid) && Instant::now() < deadline {
        sleep(Duration::from_millis(50));
    }
}

/// Install the member namespace for a config that asked for it.
///
/// Idempotent: a live record whose device is still in the namespace is already
/// attached. A record whose holder died is cleaned up, and then the device
/// decides what happens: if it is still here (a holder can be killed while the
/// kernel keeps the device, e.g. a namespace whose last process exits but whose
/// devices are moved out) the attach simply installs a fresh namespace, and if
/// it is gone the daemon has lost its interface and the error says what to
/// restart. Nothing is left behind in either case, so the record never claims an
/// attachment that does not exist.
pub(crate) fn attach(
    config: &Config,
    interface: &str,
    unit: Option<&str>,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    check_config(config)?;

    if let Some(existing) = read_record(interface) {
        if is_holder(&existing) && device_in_namespace(&existing) {
            return Ok(());
        }
        if !dry_run {
            // Only a pid proven to be the holder is signalled: a crashed run's
            // pid is quickly reused, and the record outlives it.
            if is_holder(&existing) {
                teardown(interface, existing.pid);
            }
            let _ = fs::remove_file(record_path(interface));
            if !device_present(interface) {
                return Err(holder_lost_message(interface, existing.pid, unit).into());
            }
        }
    }

    let servers = config.quick.dns.clone();
    let resolv = (!servers.is_empty()).then(|| resolv_path(interface));

    if dry_run {
        println!("unshare --propagation private --mount --net …   # member namespace holder");
        if let Some(path) = &resolv {
            println!(
                "mount --bind {} /etc/resolv.conf          # inside the holder",
                path.display()
            );
        }
        println!("ip link set {interface} netns <holder>");
        for address in addresses(config) {
            println!("ip addr replace {address} dev {interface}            # inside the holder");
        }
        println!("ip route replace default dev {interface}              # inside the holder");
        return Ok(());
    }

    // No record (or a record already cleaned), but no device either: the daemon
    // is not up, or a crash already removed the interface. Spawning a holder here
    // would only produce a stray `sleep infinity` and a failed move.
    if !device_present(interface) {
        return Err(missing_device_message(interface, unit).into());
    }

    // Nothing before this point has created the state directory: the route
    // install normally does, and the per-app path skips it on purpose.
    fs::create_dir_all(routes::state_dir())?;
    if let Some(path) = &resolv {
        fs::write(path, resolv_text(&servers))?;
    }
    let ready = ready_path(interface);
    let _ = fs::remove_file(&ready);
    let pid = spawn_holder(interface, resolv.as_deref(), &ready)?;
    if let Err(error) = configure(config, interface, pid) {
        teardown(interface, pid);
        return Err(error);
    }
    if let Err(error) = write_record(interface, pid) {
        teardown(interface, pid);
        return Err(error);
    }
    Ok(())
}

/// Remove what [`attach`] installed. Lenient by contract, the way the route
/// teardown is: the holder may already be gone, and a failed step must not
/// strand a record the next attach would honour as live.
pub(crate) fn detach(interface: &str, dry_run: bool) {
    let Some(record) = read_record(interface) else {
        return;
    };
    if dry_run {
        println!(
            "ip link set {} netns {}",
            record.interface,
            std::process::id()
        );
        println!("kill -TERM {}", record.pid);
        return;
    }
    if is_holder(&record) {
        teardown(&record.interface, record.pid);
    } else if !device_present(&record.interface) {
        // The holder died first and the namespace took the device: there is
        // nothing to move back, and the operator should know the tunnel is not
        // coming back without a new daemon rather than find it out from silence.
        eprintln!(
            "vallum-quick: note   the member namespace holder (pid {}) died and took \
             `{}` with it; the daemon has lost its interface and must be restarted",
            record.pid, record.interface
        );
    }
    let _ = fs::remove_file(record_path(interface));
    let _ = fs::remove_file(resolv_path(interface));
    let _ = fs::remove_file(ready_path(interface));
}

/// The verb: launch `cmd` inside the member namespace.
///
/// Refuses loudly when the namespace is not there, because a member launched
/// outside it is exactly the traffic ADR-0023's membership decision exists to
/// prevent — it would look identical to a member that had simply exited.
pub(crate) fn app_run(
    config_path: &Path,
    name: &str,
    cmd: &[String],
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(reason) = valid_app_name(name) {
        return Err(reason.into());
    }
    if cmd.is_empty() {
        return Err("`app CONFIG NAME -- CMD...` needs a command after `--`".into());
    }

    let config = crate::load_normalized(config_path)?;
    let interface = config
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned());

    let Some(record) = read_record(&interface) else {
        return Err(format!(
            "the tunnel is not attached — launching `{name}` now would run outside the \
             tunnel: no `{}` record exists. Refusing rather than launching, per \
             ADR-0023's membership decision",
            record_path(&interface).display()
        )
        .into());
    };
    if !alive(record.pid) {
        return Err(format!(
            "the member namespace for `{interface}` is gone (holder pid {} is not \
             running); reattach before launching `{name}`, because a launch outside \
             the namespace would run outside the tunnel",
            record.pid
        )
        .into());
    }
    if !device_in_namespace(&record) {
        return Err(format!(
            "`{}` is not inside the member namespace (holder pid {}); reattach, \
             because launching `{name}` now would run outside the tunnel",
            record.interface, record.pid
        )
        .into());
    }

    if dry_run {
        println!(
            "member namespace: pid {} (device {})",
            record.pid, record.interface
        );
        println!(
            "command:          nsenter -t {} -n -m -- {}",
            record.pid,
            cmd.join(" ")
        );
        return Ok(());
    }

    // `nsenter` execs the command, so argv reaches it unchanged; the verb waits
    // and exits with the child's code, because `app … -- CMD && rest` is how
    // operators script a launch. A signal death reports as 1: the parent cannot
    // name the signal without a libc dependency, and this crate is stdlib-only.
    let status = Command::new("nsenter")
        .args(["-t", &record.pid.to_string(), "-n", "-m", "--"])
        .args(cmd)
        .status()
        .map_err(|error| {
            format!("launching `{name}` inside the member namespace failed: {error}")
        })?;
    std::process::exit(status.code().unwrap_or(1));
}

/// The member-name allowlist: a name's alphabet, null-free and `..`-free, so a
/// name can be printed in a message and used as a path component without a
/// second rule about where it may appear.
pub(crate) fn valid_app_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("member name must not be empty".into());
    }
    if name.len() > 32 {
        return Err(format!(
            "member name `{name}` is {} bytes; the cap is 32",
            name.len()
        ));
    }
    if name == "." || name == ".." {
        return Err(format!("member name `{name}` is not a usable label"));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Err(format!(
            "member name `{name}` has a character outside `[a-zA-Z0-9_-.]`"
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::env::temp_dir;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    fn config(text: &str) -> Config {
        static CALL: AtomicU32 = AtomicU32::new(0);
        let path = temp_dir().join(format!(
            "vallum-member-test-{}-{}.toml",
            std::process::id(),
            CALL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, text).expect("test config writes");
        let parsed = Config::load(&path).expect("test config parses");
        let _ = fs::remove_file(&path);
        parsed
    }

    fn full_tunnel() -> Config {
        config(
            r#"
[interface]
name = "ei"
private_key = "/boot/signing.key"
address = "10.7.0.2/24"

[quick]
app_class = true

[[peer]]
name = "gw"
public_key = "peer"
allowed_ips = ["0.0.0.0/0"]
"#,
        )
    }

    #[test]
    fn a_full_tunnel_with_an_address_passes() {
        assert!(check_config(&full_tunnel()).is_ok());
    }

    #[test]
    fn a_split_tunnel_refuses() {
        let split = config(
            r#"
[interface]
name = "ei"
private_key = "/boot/signing.key"
address = "10.7.0.2/24"

[quick]
app_class = true

[[peer]]
name = "gw"
public_key = "peer"
allowed_ips = ["10.0.0.0/8"]
"#,
        );
        let reason = check_config(&split).unwrap_err();
        assert!(reason.contains("full tunnel"), "{reason}");
    }

    #[test]
    fn a_config_without_an_address_refuses() {
        let bare = config(
            r#"
[interface]
name = "ei"
private_key = "/boot/signing.key"

[quick]
app_class = true

[[peer]]
name = "gw"
public_key = "peer"
allowed_ips = ["0.0.0.0/0"]
"#,
        );
        let reason = check_config(&bare).unwrap_err();
        assert!(reason.contains("address"), "{reason}");
    }

    #[test]
    fn the_record_round_trips() {
        let record = Record {
            pid: 4242,
            start: Some(9_876_543),
            interface: "vallum0".to_owned(),
        };
        assert_eq!(parse_record(&render_record(&record)), Some(record));
    }

    #[test]
    fn a_record_missing_a_field_is_not_a_record() {
        assert!(parse_record("pid 12\n").is_none());
        assert!(parse_record("interface v0\n").is_none());
        assert!(parse_record("pid not-a-pid\ninterface v0\n").is_none());
    }

    #[test]
    fn an_old_record_without_a_start_time_still_parses() {
        // Records written before the field are on disk after an upgrade; they
        // must keep working, and they are the reason it is optional.
        let record = parse_record("pid 12\ninterface v0\n").expect("old record");
        assert_eq!(record.pid, 12);
        assert_eq!(record.start, None);
        assert_eq!(record.interface, "v0");
    }

    #[test]
    fn the_start_time_is_the_field_after_the_command_name() {
        // A command name with spaces and parentheses in it is the case that
        // makes tokenizing the whole line wrong.
        let stat = "4242 (unshare (net))) S 1 4242 4242 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 \
                    1 0 9876543 12345 678 18446744073709551615";
        let tail = stat.rsplit_once(')').expect("a command name").1;
        let parsed: u64 = tail
            .split_whitespace()
            .nth(19)
            .expect("the 20th field")
            .parse()
            .expect("a number");
        assert_eq!(parsed, 9_876_543);
    }

    #[test]
    fn a_lost_holder_message_names_both_remedies() {
        let named = holder_lost_message("vallum0", 77, Some("laptop"));
        assert!(named.contains("pid 77"), "{named}");
        assert!(named.contains("destroys the devices"), "{named}");
        assert!(named.contains("systemctl restart vallum@laptop"), "{named}");

        // No stem: never invent a unit that may not exist (the lesson from
        // `interface_missing`).
        let unnamed = holder_lost_message("vallum0", 77, None);
        assert!(!unnamed.contains("systemctl restart vallum@"), "{unnamed}");
        assert!(unnamed.contains("restart the daemon"), "{unnamed}");
    }

    #[test]
    fn the_private_resolver_lists_only_pushed_servers() {
        let text = resolv_text(&["10.7.0.1".to_owned(), "10.7.0.2".to_owned()]);
        assert_eq!(
            text,
            "# written by vallum-quick for the member namespace\nnameserver 10.7.0.1\nnameserver 10.7.0.2\n"
        );
    }

    #[test]
    fn addresses_include_the_shorthand_once() {
        let config = config(
            r#"
[interface]
name = "ei"
private_key = "/boot/signing.key"
address = "10.7.0.2/24"
addresses = ["10.7.0.2/24", "fd00:7::2/64"]

[[peer]]
name = "gw"
public_key = "peer"
allowed_ips = ["0.0.0.0/0", "::/0"]
"#,
        );
        assert_eq!(
            addresses(&config),
            vec!["10.7.0.2/24".to_owned(), "fd00:7::2/64".to_owned()]
        );
    }

    #[test]
    fn the_name_alphabet_is_closed() {
        for good in ["web", "a-b_c.d", "0"] {
            assert!(valid_app_name(good).is_ok(), "{good}");
        }
        for bad in ["", ".", "..", "a/b", "a b", "a$b"] {
            assert!(valid_app_name(bad).is_err(), "{bad}");
        }
        assert!(valid_app_name(&"x".repeat(33)).is_err());
    }
}
