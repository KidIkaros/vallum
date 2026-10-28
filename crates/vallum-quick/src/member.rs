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
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    pid: u32,
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
fn addresses(config: &Config) -> Vec<String> {
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
    let mut interface = None;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        match (fields.next(), fields.next()) {
            (Some("pid"), Some(value)) => pid = value.parse::<u32>().ok(),
            (Some("interface"), Some(value)) => interface = Some(value.to_owned()),
            _ => {}
        }
    }
    Some(Record {
        pid: pid?,
        interface: interface?,
    })
}

fn render_record(record: &Record) -> String {
    format!("pid {}\ninterface {}\n", record.pid, record.interface)
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
            interface: interface.to_owned(),
        }),
    )?;
    Ok(())
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
/// attached. A record whose holder died (a reboot, a killed holder) is cleaned
/// up and replaced — the device died with the namespace, so the daemon has to
/// be restarted by its supervisor before this can succeed, and the error says
/// so.
pub(crate) fn attach(
    config: &Config,
    interface: &str,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    check_config(config)?;

    if let Some(existing) = read_record(interface) {
        if alive(existing.pid) && device_in_namespace(&existing) {
            return Ok(());
        }
        if !dry_run {
            if alive(existing.pid) {
                teardown(interface, existing.pid);
            }
            let _ = fs::remove_file(record_path(interface));
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
    if alive(record.pid) {
        teardown(&record.interface, record.pid);
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
