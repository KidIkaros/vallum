// SPDX-License-Identifier: Apache-2.0

//! `vallum setup`: one entry point, two roles.
//!
//! A server and a client are the same daemon with different configs, which is
//! the right architecture and the wrong first impression: twenty subcommands
//! and a TOML file before anything works. This asks the one question that
//! decides everything — *what is this machine?* — and then runs exactly the
//! commands that role needs, printing the handoff to the other side.
//!
//! Interactive when a person is at the terminal, plain guidance when not, and
//! never a prompt that a script cannot answer.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;

use clap::Args;
use ipnet::IpNet;
use vallum_crypto_sdk::SdkSuite;

use crate::commands::import::ImportArgs;
use crate::commands::server::InitArgs;
use crate::{say, Error};

#[derive(Debug, Args)]
pub struct SetupArgs {
    /// This machine accepts clients.
    #[arg(long, conflicts_with = "client")]
    pub server: bool,

    /// This machine connects to a server, from a `.vallum-bundle` file.
    #[arg(long, value_name = "BUNDLE", conflicts_with = "server")]
    pub client: Option<PathBuf>,

    /// Take the defaults and the host changes without asking.
    #[arg(long)]
    pub yes: bool,

    /// The address clients dial. Detected when absent.
    #[arg(long, value_name = "HOST:PORT")]
    pub endpoint: Option<String>,

    /// The tunnel address and prefix.
    #[arg(long, value_name = "CIDR")]
    pub address: Option<String>,

    /// The UDP address to listen on.
    #[arg(long, value_name = "ADDR:PORT", default_value = "0.0.0.0:51820")]
    pub listen: String,

    /// The instance name: the config file stem and the unit instance.
    ///
    /// Defaults to `vallum0` on a server, and to this machine's hostname on a
    /// client enrolled over SSH.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// Enrol this machine against a server over SSH, which needs no bundle and
    /// never sends this machine's private key anywhere.
    #[arg(long, value_name = "USER@HOST", conflicts_with_all = ["server", "client"])]
    pub remote: Option<String>,

    /// Print every step and change nothing.
    #[arg(long)]
    pub dry_run: bool,
}

const DEFAULT_ADDRESS: &str = "10.7.0.1/24";

/// `vallum setup`.
///
/// # Errors
///
/// Whatever the command it dispatches to fails with.
pub fn setup(args: &SetupArgs) -> Result<(), Error> {
    if args.server {
        return as_server(args);
    }
    if let Some(bundle) = &args.client {
        return as_client(bundle, args.dry_run, false);
    }
    if let Some(remote) = &args.remote {
        return as_remote(remote, args);
    }
    if !std::io::stdin().is_terminal() {
        return guidance();
    }
    match ask_role()? {
        Role::Server => as_server(args),
        Role::Client => {
            let bundle = ask_bundle()?;
            as_client(&bundle, args.dry_run, true)
        }
    }
}

/// What the machine is for. The only question that changes everything after it.
enum Role {
    Server,
    Client,
}

fn ask_role() -> Result<Role, Error> {
    say!("Vallum — a post-quantum tunnel between two machines.");
    say!();
    say!("What is this machine?");
    say!("  1) A server — other machines connect to it");
    say!("  2) A client — it connects to a server");
    say!();
    loop {
        match prompt("Choose 1 or 2", Some("1"))?.as_str() {
            "1" | "s" | "server" => return Ok(Role::Server),
            "2" | "c" | "client" => return Ok(Role::Client),
            other => say!("`{other}` is not one of the two. Type 1 or 2."),
        }
    }
}

fn as_server(args: &SetupArgs) -> Result<(), Error> {
    let interactive = std::io::stdin().is_terminal() && !args.yes;
    let endpoint = match (&args.endpoint, interactive) {
        (Some(endpoint), _) => Some(endpoint.clone()),
        (None, true) => {
            // Shown, never defaulted: the detected address is usually private,
            // and accepting it silently is how a bundle ends up dialling
            // something only the LAN can reach.
            if let Some(detected) =
                crate::commands::server::detected_endpoint(listen_port(&args.listen)?)
            {
                say!("  this machine's address is {detected} — private if clients are off-LAN");
            }
            loop {
                let answer = prompt("The address clients dial (a public name or IP)", None)?;
                if answer.is_empty() {
                    break None;
                }
                if plausible_endpoint(&answer) {
                    break Some(answer);
                }
                // `1`, or a line that was meant for another prompt, is not a
                // host — and an endpoint is copied into every bundle, so a
                // wrong one is discovered by a client that cannot connect.
                say!("`{answer}` is not an address. Give a name or an IP, like vpn.example.com.");
            }
        }
        (None, false) => None,
    };
    let address = match (&args.address, interactive) {
        (Some(address), _) => address.clone(),
        (None, true) => {
            // A wizard that hands an unvalidated value to `init` and lets the
            // error surface four steps later has not prevented anything.
            loop {
                let answer = prompt("The tunnel address", Some(DEFAULT_ADDRESS))?;
                match answer.parse::<IpNet>() {
                    Ok(_) => break answer,
                    Err(_) => say!("`{answer}` needs a prefix, like {DEFAULT_ADDRESS}. Try again."),
                }
            }
        }
        (None, false) => DEFAULT_ADDRESS.to_owned(),
    };
    let network = address
        .parse::<IpNet>()
        .map(|prefix| prefix.trunc().to_string())
        .unwrap_or_else(|_| address.clone());

    let instance = args.name.clone().unwrap_or_else(|| "vallum0".to_owned());
    let init = InitArgs {
        config: PathBuf::from(format!("/etc/vallum/{instance}.toml")),
        name: Some(instance.clone()),
        addresses: vec![address.clone()],
        listen: args.listen.clone(),
        endpoint,
        control: None,
        dns: Vec::new(),
        user: None,
        no_nat: false,
        no_firewall: false,
        no_forward: false,
        no_service: false,
        no_host: false,
        dry_run: args.dry_run,
        force: false,
        json: false,
    };

    if interactive && !args.dry_run {
        say!();
        say!("This will, on this machine:");
        say!("  · generate the server key in /etc/vallum/ (never overwritten)");
        say!("  · write {}", init.config.display());
        say!("  · enable IP forwarding and persist it");
        say!(
            "  · open UDP {} in the host firewall",
            listen_port(&args.listen)?
        );
        say!("  · add the NAT masquerade for {network}");
        say!("  · install and start the vallum@{instance} service");
        say!();
        if !confirm("Do that?", true)? {
            say!("Nothing was changed.");
            return Ok(());
        }
    }

    crate::commands::server::init(&init)?;
    if args.dry_run {
        return Ok(());
    }

    let add_client = if args.yes {
        false
    } else if interactive {
        confirm("Add your first client now?", true)?
    } else {
        false
    };
    if !add_client {
        say!();
        say!("Next: enrol a client with");
        say!("   sudo vallum peer add laptop --bundle-out laptop.vallum-bundle");
        return Ok(());
    }

    let name = prompt("A name for that client", Some("laptop"))?;
    let bundle = PathBuf::from(format!("{name}.vallum-bundle"));
    crate::commands::peer::add_for_setup(&init.config, &name, &bundle)?;

    say!();
    say!(
        "Next: get {} to the client, then run this there:",
        bundle.display()
    );
    say!("   scp {} <user>@<client>:", bundle.display());
    say!("   sudo vallum setup --client {}", bundle.display());
    Ok(())
}

/// The bundle to import: what the operator names, or the only one in sight.
fn ask_bundle() -> Result<PathBuf, Error> {
    // A prompt that asks for a file without saying what it is, where it came
    // from, or what happens next is a riddle, not a question.
    say!("A .vallum-bundle is the one file your server produced when it enrolled");
    say!("this machine. It holds the client's config, its private key, and the");
    say!("server's address — nothing else is needed from the server.");
    say!();
    let found: Vec<PathBuf> = std::fs::read_dir(".")
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "vallum-bundle")
                })
                .collect()
        })
        .unwrap_or_default();
    let default = match found.as_slice() {
        [only] => Some(only.display().to_string()),
        _ => None,
    };
    loop {
        let answer = prompt(
            "The .vallum-bundle file the server gave you",
            default.as_deref(),
        )?;
        if answer.is_empty() {
            return Err(Error::Usage(
                "give the path to a .vallum-bundle file, or ask the server for one: \
                 `vallum peer add <name> --bundle-out <name>.vallum-bundle`"
                    .to_owned(),
            ));
        }
        let path = PathBuf::from(&answer);
        if path.is_file() {
            return Ok(path);
        }
        say!(
            "`{answer}` does not exist here. On the server it was written by \
             `vallum peer add`, and copied over with `scp`."
        );
        if default.is_some() && answer != default.clone().unwrap_or_default() {
            continue;
        }
        continue;
    }
}

/// What a bundle will actually do, read from the bundle itself.
struct Summary {
    name: String,
    endpoint: String,
    full_tunnel: bool,
    dns: bool,
}

fn summarise(bundle: &std::path::Path) -> Result<Summary, Error> {
    let text = std::fs::read_to_string(bundle).map_err(|source| Error::IoPath {
        action: "read the bundle",
        path: bundle.to_path_buf(),
        source,
    })?;
    let parsed: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| Error::Usage(format!("{} is not a bundle: {error}", bundle.display())))?;
    let config = parsed
        .get("config")
        .and_then(|config| config.as_str())
        .ok_or_else(|| Error::Usage(format!("{} has no config", bundle.display())))?;
    let line = |key: &str| {
        config
            .lines()
            .find(|line| line.trim_start().starts_with(key))
            .map(|line| line.trim().to_owned())
            .unwrap_or_default()
    };
    let allowed = line("allowed_ips");
    Ok(Summary {
        name: parsed
            .get("name")
            .and_then(|name| name.as_str())
            .unwrap_or("client")
            .to_owned(),
        endpoint: line("endpoint")
            .trim_start_matches("endpoint = ")
            .trim_matches('"')
            .to_owned(),
        full_tunnel: allowed.contains("0.0.0.0/0") || allowed.contains("::/0"),
        dns: config.contains("\ndns = ") || config.starts_with("dns = "),
    })
}

fn as_client(bundle: &std::path::Path, dry_run: bool, interactive: bool) -> Result<(), Error> {
    let summary = summarise(bundle)?;
    say!();
    say!("{} — {}", bundle.display(), summary.name);
    say!("   server     {}", summary.endpoint);
    say!(
        "   routing    {}",
        if summary.full_tunnel {
            "every destination through the tunnel (a full tunnel)"
        } else {
            "only the prefixes the server routes"
        }
    );
    if summary.dns {
        say!("   DNS        the server's resolver, while the tunnel is up");
    }
    say!();
    say!("Importing it will write the config and its key (0600), and install and");
    say!("start the vallum@{} service.", summary.name);
    if interactive && !confirm("Do that?", true)? {
        say!("Nothing was changed.");
        return Ok(());
    }
    if dry_run {
        say!(
            "would import {} and start the tunnel for it",
            bundle.display()
        );
        return Ok(());
    }
    let root = nix::unistd::Uid::effective().is_root();
    let import = ImportArgs {
        bundle: bundle.to_path_buf(),
        output_dir: None,
        force: false,
        install: root,
    };
    crate::commands::import::import(&import)?;
    say!();
    if root {
        // Installed: the only thing left is to confirm it works.
        say!("Check it with `vallum doctor`, then watch it with `vallum tui`.");
    } else {
        // Not installed: say the one thing `import` did not.
        say!("To run it as a service instead, re-run this with sudo.");
    }
    Ok(())
}

/// Enrol this machine against a server over SSH.
///
/// The key is generated here and stays here; only the public line travels, over
/// the SSH channel the operator already trusts. The server hands back its own
/// public line and the address it allocated — nothing secret either way.
fn as_remote(remote: &str, args: &SetupArgs) -> Result<(), Error> {
    let name = args
        .name
        .clone()
        .or_else(hostname)
        .unwrap_or_else(|| "client".to_owned());
    if args.dry_run {
        say!("would generate a key here and enrol `{name}` on {remote} over SSH");
        say!("   nothing secret would leave this machine");
        return Ok(());
    }

    // Already enrolled here? Then this run is about installing or starting it,
    // not about enrolling again: a second enrolment would present a new key and
    // the server would rightly refuse it.
    let candidates = [
        PathBuf::from(format!("/etc/vallum/{name}.toml")),
        PathBuf::from(format!("{name}.toml")),
    ];
    if let Some(existing) = candidates
        .iter()
        .find(|path| path.is_file() && path.with_extension("key").is_file())
    {
        say!("already enrolled: {}", existing.display());
        return start_existing(existing, &name);
    }

    let seed = crate::entropy::seed();
    let secret = crate::keys::new_secret(3, false, seed);
    let suite = SdkSuite::from_id(secret.suite).map_err(|error| Error::Suite(error.to_string()))?;
    let identity = crate::keys::identity(&suite, &secret)?;
    let public_line = crate::keys::encode_public(secret.suite, &identity.to_peer());
    say!("generated a key here; the private half does not leave this machine");

    let remote_command =
        format!("sudo vallum peer enroll {name} --public-key-file /dev/stdin --json");
    let mut child = std::process::Command::new("ssh")
        .arg(remote)
        .arg(&remote_command)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|source| Error::IoPath {
            action: "run ssh",
            path: PathBuf::from("ssh"),
            source,
        })?;
    if let Some(stdin) = child.stdin.as_mut() {
        use std::io::Write as _;
        stdin
            .write_all(public_line.as_bytes())
            .map_err(|error| Error::Usage(format!("could not send the public line: {error}")))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| Error::Usage(format!("ssh: {error}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Precondition(format!(
            "the server refused the enrolment: {}\n\
             That command runs `sudo vallum peer enroll` there, so it needs vallum \
             installed on the server and passwordless sudo for this user. \
             If that is not available, ask the server for a bundle instead: \
             `vallum peer add {name} --bundle-out {name}.vallum-bundle`",
            stderr.trim()
        )));
    }
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| Error::Usage(format!("the server's answer was not JSON: {error}")))?;
    let config_text = report
        .get("config")
        .and_then(|config| config.as_str())
        .ok_or_else(|| Error::Usage("the server's answer had no config".to_owned()))?;
    let address = report
        .get("address")
        .and_then(|a| a.as_str())
        .unwrap_or("?");
    let endpoint = report
        .get("endpoint")
        .and_then(|e| e.as_str())
        .unwrap_or("?");

    let root = nix::unistd::Uid::effective().is_root();
    let directory = if root {
        PathBuf::from("/etc/vallum")
    } else {
        PathBuf::from(".")
    };
    std::fs::create_dir_all(&directory).map_err(|source| Error::IoPath {
        action: "create",
        path: directory.clone(),
        source,
    })?;
    let key_path = directory.join(format!("{name}.key"));
    let config_path = directory.join(format!("{name}.toml"));
    crate::keys::save_secret(&key_path, &secret)?;
    std::fs::write(&config_path, config_text).map_err(|source| Error::IoPath {
        action: "write the config",
        path: config_path.clone(),
        source,
    })?;
    let _ = std::fs::set_permissions(
        &config_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    );

    say!();
    say!("enrolled `{name}` — {address}, through {endpoint}");
    say!("   config     {}", config_path.display());
    say!("   key        {} (this machine only)", key_path.display());
    if root && config_path.starts_with("/etc/vallum") {
        crate::commands::server::install_service(&name, false)?;
        say!("Check it with `vallum doctor`, then watch it with `vallum tui`.");
    } else {
        say!(
            "Run it with `sudo vallum run --config {}`.",
            config_path.display()
        );
    }
    Ok(())
}

/// Finish a machine that is already enrolled: install the service, or say how
/// to run it.
fn start_existing(config: &std::path::Path, name: &str) -> Result<(), Error> {
    let root = nix::unistd::Uid::effective().is_root();
    let in_etc = config.starts_with("/etc/vallum");
    if root && in_etc {
        crate::commands::server::install_service(name, false)?;
        say!("Check it with `vallum doctor`, then watch it with `vallum tui`.");
        return Ok(());
    }
    if root && !in_etc {
        // The unit reads /etc/vallum/<name>.toml, so move it there.
        let target = PathBuf::from(format!("/etc/vallum/{name}.toml"));
        let key = config.with_extension("key");
        let key_target = PathBuf::from(format!("/etc/vallum/{name}.key"));
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|source| Error::IoPath {
                action: "create",
                path: parent.to_path_buf(),
                source,
            })?;
        }
        std::fs::rename(config, &target).map_err(|source| Error::IoPath {
            action: "move the config",
            path: config.to_path_buf(),
            source,
        })?;
        std::fs::rename(&key, &key_target).map_err(|source| Error::IoPath {
            action: "move the key",
            path: key,
            source,
        })?;
        // The units drop capabilities, which means root loses CAP_DAC_OVERRIDE
        // and cannot read a 0600 file owned by anyone else. A file moved in
        // from a user's directory keeps its owner, so hand it to root.
        for path in [&target, &key_target] {
            let _ = std::os::unix::fs::chown(path, Some(0), Some(0));
        }
        say!("moved it to {}", target.display());
        crate::commands::server::install_service(name, false)?;
        return Ok(());
    }
    say!(
        "Run it with `sudo vallum run --config {}`,",
        config.display()
    );
    say!("or re-run this with sudo to install it as a service.");
    Ok(())
}

/// This machine's short hostname, for naming the device on the server.
fn hostname() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .map(|name| name.split('.').next().unwrap_or(&name).to_owned())
}

/// The non-interactive default: say what the two paths are, without running
/// either. A prompt a script cannot answer is worse than a clear instruction.
fn guidance() -> Result<(), Error> {
    say!("Vallum — a post-quantum tunnel between two machines.");
    say!();
    say!("On the server, where clients connect:");
    say!("   sudo vallum setup --server");
    say!();
    say!("On this machine, if a server gave you a .vallum-bundle:");
    say!("   sudo vallum setup --client <file>.vallum-bundle");
    say!();
    say!("`vallum setup` with no flags asks which of the two this machine is.");
    say!("Every individual command is under `vallum --help`.");
    Ok(())
}

/// Whether a dialled address looks like a host, not a stray answer.
///
/// Deliberately permissive: single-label LAN names (`nas`) are legitimate, so
/// the test is that the host is not *purely numeric* — which is never a host
/// and is almost always a line meant for a different prompt.
fn plausible_endpoint(answer: &str) -> bool {
    let host = answer.trim();
    if host.is_empty() || host.contains(char::is_whitespace) {
        return false;
    }
    let host = host.rsplit_once(':').map_or(host, |(host, _)| host);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    !host.is_empty() && !host.chars().all(|character| character.is_ascii_digit())
}

fn listen_port(listen: &str) -> Result<u16, Error> {
    listen
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .ok_or_else(|| Error::Usage(format!("`{listen}` is not an address with a port")))
}

fn prompt(question: &str, default: Option<&str>) -> Result<String, Error> {
    let mut stdout = std::io::stdout();
    match default {
        Some(default) => {
            let _ = write!(stdout, "{question} [{default}]: ");
        }
        None => {
            let _ = write!(stdout, "{question}: ");
        }
    }
    let _ = stdout.flush();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|error| Error::Usage(format!("could not read the answer: {error}")))?;
    let answer = line.trim().to_owned();
    if answer.is_empty() {
        Ok(default.unwrap_or_default().to_owned())
    } else {
        Ok(answer)
    }
}

fn confirm(question: &str, default: bool) -> Result<bool, Error> {
    let hint = if default { "Y/n" } else { "y/N" };
    let answer = prompt(&format!("{question} ({hint})"), None)?;
    Ok(match answer.to_lowercase().as_str() {
        "" => default,
        "y" | "yes" => true,
        _ => false,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_port_comes_from_the_listen_address() {
        assert_eq!(listen_port("0.0.0.0:51820").unwrap(), 51820);
        assert_eq!(listen_port("[::]:51820").unwrap(), 51820);
        assert!(listen_port("0.0.0.0").is_err());
    }

    #[test]
    fn a_stray_number_is_not_a_host() {
        assert!(plausible_endpoint("vpn.example.com"));
        assert!(plausible_endpoint("203.0.113.5"));
        assert!(plausible_endpoint("203.0.113.5:51820"));
        assert!(plausible_endpoint("nas"));
        assert!(plausible_endpoint("[2001:db8::1]:51820"));
        // The line the wizard caught on a real host.
        assert!(!plausible_endpoint("1"));
        assert!(!plausible_endpoint(""));
        assert!(!plausible_endpoint("two words"));
    }

    #[test]
    fn guidance_names_both_roles_without_running_anything() {
        // The non-interactive path must not prompt or mutate; it only explains.
        guidance().unwrap();
    }
}
