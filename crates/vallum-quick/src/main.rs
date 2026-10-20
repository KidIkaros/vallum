// SPDX-License-Identifier: Apache-2.0

//! `vallum-quick`: the OS-level helper.
//!
//! The daemon owns the tunnel and nothing else. This tool owns the parts that
//! are inherently distribution- and host-specific: routes, DNS, firewall/NAT,
//! and the operator's hooks. It reads the same TOML, including a `[quick]`
//! table the daemon ignores.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use clap::{Parser, Subcommand};
use vallum_config::Config;
use vallum_tunnel::Prefix;

#[derive(Parser)]
#[command(version, about = "Bring a Vallum config up with its routes and DNS")]
struct Cli {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Start the daemon, then add routes, DNS and hooks.
    Up {
        /// The configuration file.
        config: PathBuf,
        /// Print the commands instead of running them.
        #[arg(long)]
        dry_run: bool,
    },
    /// Run the down hooks, remove routes and DNS, and stop the daemon.
    Down {
        /// The configuration file.
        config: PathBuf,
        /// Print the commands instead of running them.
        #[arg(long)]
        dry_run: bool,
    },
    /// Apply routes, DNS and hooks to an interface a supervisor already owns.
    ///
    /// This is the systemd form: `vallum@.service` starts the daemon and
    /// `vallum-quick@.service` runs `attach`, so routes and DNS are applied
    /// without spawning a second daemon or weakening the daemon's sandbox.
    Attach {
        /// The configuration file.
        config: PathBuf,
        /// Print the commands instead of running them.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove what `attach` applied, leaving the daemon running.
    Detach {
        /// The configuration file.
        config: PathBuf,
        /// Print the commands instead of running them.
        #[arg(long)]
        dry_run: bool,
    },
    /// Print the config without its `[quick]` table.
    Strip {
        /// The configuration file.
        config: PathBuf,
    },
    /// Export the running daemon as a config (via `vallum showconf`).
    Save {
        /// The configuration file, for its `control` path.
        config: PathBuf,
        /// Write to this file instead of stdout. Never the config itself.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// Include the private-key path and preshared keys in the export.
        #[arg(long)]
        include_secrets: bool,
        /// Replace the config with the export, keeping a `.bak`.
        #[arg(long)]
        in_place: bool,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let outcome = match &cli.command {
        Action::Up { config, dry_run } => up(config, *dry_run),
        Action::Down { config, dry_run } => down(config, *dry_run),
        Action::Attach { config, dry_run } => attach(config, *dry_run),
        Action::Detach { config, dry_run } => detach(config, *dry_run),
        Action::Strip { config } => strip(config),
        Action::Save {
            config,
            output,
            include_secrets,
            in_place,
        } => save(config, output.as_deref(), *include_secrets, *in_place),
    };
    match outcome {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vallum-quick: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn up(config_path: &Path, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load(config_path)?;
    let interface = config
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned());
    let table = config.quick.table.as_deref().unwrap_or("auto");

    for hook in &config.quick.pre_up {
        run_hook(hook, dry_run)?;
    }

    let result = up_after_pre(&config, config_path, &interface, table, dry_run);
    if result.is_err() {
        // A partially applied `up` must not leave a daemon or routes behind.
        rollback(&config, config_path, &interface, table, dry_run);
    }
    result
}

fn up_after_pre(
    config: &Config,
    config_path: &Path,
    interface: &str,
    table: &str,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // The daemon first: it creates the interface the routes point at.
    let binary = std::env::var("VALLUM_BIN").unwrap_or_else(|_| "vallum".to_owned());
    let mut child = if dry_run {
        println!("{binary} run --config {}", config_path.display());
        None
    } else {
        let child = Command::new(&binary)
            .arg("run")
            .arg("--config")
            .arg(config_path)
            .spawn()?;
        let pidfile = config_path.with_extension("pid");
        if let Err(error) = fs::write(&pidfile, child.id().to_string()) {
            // The pidfile failed after the daemon started; do not leave it
            // orphaned.
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            return Err(error.into());
        }
        Some(child)
    };

    if !dry_run {
        wait_for_interface(interface)?;
    }

    if table != "off" {
        for peer in &config.peers {
            for prefix in &peer.allowed_ips {
                let prefix: Prefix = prefix.parse()?;
                add_route(interface, &prefix, table, dry_run)?;
            }
        }
    }

    if !config.quick.dns.is_empty() {
        set_dns(interface, &config.quick.dns, dry_run)?;
    }

    for hook in &config.quick.post_up {
        run_hook(hook, dry_run)?;
    }

    if let Some(mut child) = child.take() {
        // A short-lived daemon is a failure; report it rather than leaving a
        // pidfile pointing at nothing.
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("vallum exited during startup: {status}").into());
        }
    }
    Ok(())
}

/// Undo whatever a failed `up` may have applied.
fn rollback(config: &Config, config_path: &Path, interface: &str, table: &str, dry_run: bool) {
    if table != "off" {
        for peer in &config.peers {
            for prefix in &peer.allowed_ips {
                if let Ok(prefix) = prefix.parse::<Prefix>() {
                    let _ = del_route(interface, &prefix, table, dry_run);
                }
            }
        }
    }
    if !config.quick.dns.is_empty() {
        let _ = unset_dns(interface, dry_run);
    }
    let pidfile = config_path.with_extension("pid");
    if let Ok(pid) = fs::read_to_string(&pidfile) {
        let pid = pid.trim();
        if dry_run {
            println!("kill -TERM {pid}");
        } else {
            let _ = Command::new("kill").arg("-TERM").arg(pid).status();
        }
    }
    if !dry_run {
        let _ = fs::remove_file(&pidfile);
    }
}

fn down(config_path: &Path, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load(config_path)?;
    let interface = config
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned());
    let table = config.quick.table.as_deref().unwrap_or("auto");

    for hook in &config.quick.pre_down {
        run_hook(hook, dry_run)?;
    }

    if table != "off" {
        for peer in &config.peers {
            for prefix in &peer.allowed_ips {
                let prefix: Prefix = prefix.parse()?;
                del_route(&interface, &prefix, table, dry_run)?;
            }
        }
    }
    if !config.quick.dns.is_empty() {
        unset_dns(&interface, dry_run)?;
    }

    let pidfile = config_path.with_extension("pid");
    if let Ok(pid) = fs::read_to_string(&pidfile) {
        let pid = pid.trim();
        if dry_run {
            println!("kill -TERM {pid}");
        } else {
            let _ = Command::new("kill").arg("-TERM").arg(pid).status();
            let _ = fs::remove_file(&pidfile);
        }
    }

    for hook in &config.quick.post_down {
        run_hook(hook, dry_run)?;
    }
    Ok(())
}

/// Apply the config's host-level work to an interface someone else started.
///
/// `vallum@.service` owns the daemon and `vallum-quick@.service` runs this, so
/// routes and DNS are applied without spawning a second daemon and without
/// widening the daemon's sandbox to let it write `/etc/resolv.conf`.
fn attach(config_path: &Path, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load(config_path)?;
    let interface = config
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned());
    let table = config.quick.table.as_deref().unwrap_or("auto");

    for hook in &config.quick.pre_up {
        run_hook(hook, dry_run)?;
    }

    if !dry_run {
        wait_for_interface(&interface)?;
    }

    for prefix in managed_routes(&config, &interface, table, dry_run)? {
        add_route(&interface, &prefix, table, dry_run)?;
    }

    if !config.quick.dns.is_empty() {
        set_dns(&interface, &config.quick.dns, dry_run)?;
    }

    for hook in &config.quick.post_up {
        run_hook(hook, dry_run)?;
    }
    Ok(())
}

/// Remove what [`attach`] applied, leaving the daemon running.
fn detach(config_path: &Path, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load(config_path)?;
    let interface = config
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned());
    let table = config.quick.table.as_deref().unwrap_or("auto");

    for hook in &config.quick.pre_down {
        run_hook(hook, dry_run)?;
    }

    for prefix in managed_routes(&config, &interface, table, dry_run)? {
        del_route(&interface, &prefix, table, dry_run)?;
    }

    if !config.quick.dns.is_empty() {
        unset_dns(&interface, dry_run)?;
    }

    for hook in &config.quick.post_down {
        run_hook(hook, dry_run)?;
    }
    Ok(())
}

/// The peer prefixes this host must route.
///
/// A prefix the interface's own address already covers is skipped: on a server
/// `allowed_ips = ["10.7.0.2/32"]` is inside the interface's `10.7.0.1/24`, so
/// `attach` is a no-op there and only the client's default route is added.
fn managed_routes(
    config: &Config,
    interface: &str,
    table: &str,
    dry_run: bool,
) -> Result<Vec<Prefix>, Box<dyn std::error::Error>> {
    if table == "off" {
        return Ok(Vec::new());
    }
    let own = interface_networks(interface, dry_run)?;
    let mut routes = Vec::new();
    for peer in &config.peers {
        for prefix in &peer.allowed_ips {
            let prefix: Prefix = prefix.parse()?;
            if own.iter().any(|network| covers(network, &prefix)) {
                continue;
            }
            routes.push(prefix);
        }
    }
    Ok(routes)
}

/// The networks already assigned to the interface.
///
/// Under `--dry-run` the interface may not exist, so nothing is read and every
/// route is printed — the plan the operator is being shown.
fn interface_networks(
    interface: &str,
    dry_run: bool,
) -> Result<Vec<ipnet::IpNet>, Box<dyn std::error::Error>> {
    if dry_run {
        return Ok(Vec::new());
    }
    let output = Command::new("ip")
        .args(["-o", "addr", "show", "dev", interface])
        .output()?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut networks = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        for (index, field) in fields.iter().enumerate() {
            if (*field == "inet" || *field == "inet6") && fields.get(index + 1).is_some() {
                if let Ok(network) = fields[index + 1].parse::<ipnet::IpNet>() {
                    networks.push(network);
                }
            }
        }
    }
    Ok(networks)
}

/// Whether `outer` contains every address in `inner`.
fn covers(outer: &ipnet::IpNet, inner: &Prefix) -> bool {
    let inner = inner.as_ipnet();
    outer.addr().is_ipv4() == inner.addr().is_ipv4()
        && outer.prefix_len() <= inner.prefix_len()
        && outer.contains(&inner.addr())
}

fn save(
    config_path: &Path,
    output: Option<&Path>,
    include_secrets: bool,
    in_place: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if in_place && output.is_some() {
        return Err("--in-place and --output are mutually exclusive".into());
    }
    if in_place && !include_secrets {
        return Err(
            "--in-place needs --include-secrets: without it the export would drop the \
             private-key path and every PSK"
                .into(),
        );
    }
    if !in_place && output.is_some_and(|out| out == config_path) {
        return Err(
            "refusing to overwrite the config; use --in-place, or a different --output".into(),
        );
    }
    let binary = std::env::var("VALLUM_BIN").unwrap_or_else(|_| "vallum".to_owned());
    let mut command = Command::new(&binary);
    command.args(["showconf", "--config"]).arg(config_path);
    if include_secrets {
        command.arg("--include-secrets");
    }
    let result = command.output()?;
    if !result.status.success() {
        return Err(format!(
            "`{binary} showconf` failed: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        )
        .into());
    }
    if in_place {
        let new = PathBuf::from(format!("{}.new", config_path.display()));
        let backup = PathBuf::from(format!("{}.bak", config_path.display()));
        fs::write(&new, &result.stdout)?;
        fs::copy(config_path, &backup)?;
        fs::rename(&new, config_path)?;
        println!(
            "wrote {} (backup {})",
            config_path.display(),
            backup.display()
        );
    } else {
        match output {
            Some(path) => fs::write(path, &result.stdout)?,
            None => print!("{}", String::from_utf8_lossy(&result.stdout)),
        }
    }
    Ok(())
}

/// The daemon-facing form of a config: everything except `[quick]`.
fn strip_quick(text: &str) -> String {
    let mut out = String::new();
    let mut in_quick = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_quick = trimmed == "[quick]";
        }
        if !in_quick {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn strip(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let text = fs::read_to_string(config_path)?;
    print!("{}", strip_quick(&text));
    Ok(())
}

fn add_route(
    interface: &str,
    prefix: &Prefix,
    table: &str,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = Vec::new();
    if matches!(prefix.as_ipnet(), ipnet::IpNet::V6(_)) {
        args.push("-6".to_owned());
    }
    args.extend(["route", "add", &prefix.to_string(), "dev", interface].map(str::to_owned));
    if table != "auto" && table != "off" {
        args.extend(["table".to_owned(), table.to_owned()]);
    }
    ip(&args, dry_run)
}

fn del_route(
    interface: &str,
    prefix: &Prefix,
    table: &str,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = Vec::new();
    if matches!(prefix.as_ipnet(), ipnet::IpNet::V6(_)) {
        args.push("-6".to_owned());
    }
    args.extend(["route", "del", &prefix.to_string(), "dev", interface].map(str::to_owned));
    if table != "auto" && table != "off" {
        args.extend(["table".to_owned(), table.to_owned()]);
    }
    // Deleting a route that is already gone is not a failure.
    let _ = ip(&args, dry_run);
    Ok(())
}

fn ip(args: &[String], dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    if dry_run {
        println!("ip {}", args.join(" "));
        return Ok(());
    }
    let status = Command::new("ip").args(args).status()?;
    if !status.success() {
        return Err(format!("ip {} failed", args.join(" ")).into());
    }
    Ok(())
}

fn set_dns(
    interface: &str,
    servers: &[String],
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if which("resolvconf").is_none() {
        eprintln!("vallum-quick: resolvconf not found; DNS left to the host");
        return Ok(());
    }
    let body: String = servers
        .iter()
        .map(|server| format!("nameserver {server}\n"))
        .collect();
    if dry_run {
        println!("resolvconf -a {interface} <<EOF\n{body}EOF");
        return Ok(());
    }
    let mut child = Command::new("resolvconf")
        .arg("-a")
        .arg(interface)
        .stdin(Stdio::piped())
        .spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(body.as_bytes())?;
    }
    let status = child.wait()?;
    if !status.success() {
        return Err("resolvconf -a failed".into());
    }
    Ok(())
}

fn unset_dns(interface: &str, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    if which("resolvconf").is_none() {
        return Ok(());
    }
    if dry_run {
        println!("resolvconf -d {interface}");
        return Ok(());
    }
    let _ = Command::new("resolvconf").arg("-d").arg(interface).status();
    Ok(())
}

fn run_hook(hook: &str, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    if dry_run {
        println!("sh -c {hook:?}");
        return Ok(());
    }
    let status = Command::new("sh").arg("-c").arg(hook).status()?;
    if !status.success() {
        return Err(format!("hook failed: {hook}").into());
    }
    Ok(())
}

fn wait_for_interface(interface: &str) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..50 {
        let status = Command::new("ip")
            .args(["link", "show", interface])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            return Ok(());
        }
        sleep(Duration::from_millis(100));
    }
    Err(format!("interface `{interface}` did not come up").into())
}

fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn prefix(text: &str) -> Prefix {
        text.parse().unwrap()
    }

    #[test]
    fn a_prefix_is_covered_by_the_interface_address_that_contains_it() {
        let subnet: ipnet::IpNet = "10.7.0.1/24".parse().unwrap();
        assert!(covers(&subnet, &prefix("10.7.0.2/32")));
        assert!(covers(&subnet, &prefix("10.7.0.0/24")));
        assert!(!covers(&subnet, &prefix("10.8.0.0/24")));
        assert!(!covers(&subnet, &prefix("0.0.0.0/0")));
    }

    #[test]
    fn a_default_route_is_never_covered_by_an_interface_address() {
        // The client case: `allowed_ips = ["0.0.0.0/0", "::/0"]` must always be
        // routed, or the tunnel carries nothing.
        let v4: ipnet::IpNet = "10.7.0.2/32".parse().unwrap();
        let v6: ipnet::IpNet = "fd00:7::2/128".parse().unwrap();
        assert!(!covers(&v4, &prefix("0.0.0.0/0")));
        assert!(!covers(&v6, &prefix("::/0")));
    }

    #[test]
    fn families_do_not_cover_each_other() {
        let v4: ipnet::IpNet = "10.7.0.1/24".parse().unwrap();
        let v6: ipnet::IpNet = "fd00:7::1/64".parse().unwrap();
        assert!(!covers(&v4, &prefix("fd00:7::2/128")));
        assert!(!covers(&v6, &prefix("10.7.0.2/32")));
        assert!(covers(&v6, &prefix("fd00:7::2/128")));
    }

    #[test]
    fn managed_routes_is_empty_when_the_table_is_off() {
        let dir = std::env::temp_dir().join(format!("vallum-quick-routes-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.toml");
        fs::write(
            &path,
            "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n[quick]\ntable = \"off\"\n\n\
             [[peer]]\nname = \"p\"\npublic_key = \"k\"\nallowed_ips = [\"10.7.0.2/32\"]\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        let routes = managed_routes(&config, "v0", "off", true).unwrap();
        assert!(routes.is_empty());
    }

    #[test]
    fn strip_removes_the_quick_table_only() {
        let dir = std::env::temp_dir().join(format!("vallum-quick-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.toml");
        fs::write(
            &path,
            "[interface]\nname = \"v0\"\n\n[quick]\ndns = [\"1.1.1.1\"]\n\n[[peer]]\nname = \"p\"\n",
        )
        .unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let out = strip_quick(&text);
        assert!(!out.contains("[quick]"));
        assert!(!out.contains("dns ="));
        assert!(out.contains("[[peer]]"));
    }

    #[test]
    fn save_writes_the_export_and_refuses_the_config_itself() {
        let dir = std::env::temp_dir().join(format!("vallum-quick-save-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let config = dir.join("v.toml");
        let out = dir.join("out.toml");
        fs::write(&config, "[interface]\nname = \"v0\"\n").unwrap();
        std::env::set_var("VALLUM_BIN", "/bin/echo");
        save(&config, Some(&out), false, false).unwrap();
        assert!(fs::read_to_string(&out).unwrap().contains("showconf"));
        assert!(save(&config, Some(&config), false, false).is_err());
        assert!(save(&config, None, false, true).is_err());
        save(&config, None, true, true).unwrap();
        assert!(fs::read_to_string(&config).unwrap().contains("showconf"));
        assert!(config.with_extension("toml.bak").exists());
        std::env::remove_var("VALLUM_BIN");
    }

    #[test]
    fn a_v6_route_uses_ip_dash_six() {
        let prefix: Prefix = "fd00:7::2/128".parse().unwrap();
        assert!(matches!(prefix.as_ipnet(), ipnet::IpNet::V6(_)));
    }
}
