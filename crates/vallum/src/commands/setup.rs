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
use std::path::Path;

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

    /// Enrol this machine from a client config the server wrote.
    ///
    /// The client side of `vallum peer add --client-config-out`: the server
    /// writes a config that names the key file it expects beside it, and this
    /// command is what the device runs once it has both. It finds the key,
    /// places the pair where the unit reads them, installs the service and
    /// proves the tunnel.
    ///
    /// The key never leaves this device, which is the whole point of the file
    /// path - so the device must already have it, and this command says so if
    /// it does not.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["server", "client", "remote"])]
    pub client_config: Option<PathBuf>,

    /// Do not install the systemd units; place the files and say how to run it.
    ///
    /// The same switch `vallum server init` has. It is what makes the
    /// receiver usable where there is no systemd - a container, a namespace, or
    /// a machine whose units are managed by something else.
    #[arg(long)]
    pub no_service: bool,

    /// Accept a bundle that carries this client's **private key**.
    ///
    /// A bundle is the one enrolment path where the key existed on another
    /// machine first. Every other path generates it here, so the safe
    /// alternative always exists - which is why a bundle carrying the key is
    /// refused by default rather than warned about.
    #[arg(long)]
    pub allow_shipped_key: bool,

    /// Enrol this machine against a server over SSH, which needs no bundle and
    /// never sends this machine's private key anywhere.
    #[arg(long, value_name = "USER@HOST", conflicts_with_all = ["server", "client", "join", "token"])]
    pub remote: Option<String>,

    /// The server config to edit when enrolling with `--remote` (for a server
    /// whose instance is not `vallum0`).
    #[arg(long, value_name = "FILE", requires = "remote")]
    pub remote_config: Option<PathBuf>,

    /// Enrol with a single-use token, for machines that cannot SSH to the
    /// server. Takes the `vallum1-join:…` ticket `vallum peer invite` prints,
    /// or a bare `host:port` together with --invite-id and --token.
    ///
    /// `-` reads the ticket from stdin, which keeps the token it carries out
    /// of `ps` and out of the shell's history.
    #[arg(long, value_name = "TICKET|HOST:PORT|-", conflicts_with_all = ["server", "client", "remote"])]
    pub join: Option<String>,

    /// The single-use token from `vallum peer invite`, or `-` to read it from
    /// stdin so it stays out of shell history and `ps`.
    #[arg(long, value_name = "TOKEN", requires = "join")]
    pub token: Option<String>,

    /// The invite id from `vallum peer invite` (32 hex characters).
    #[arg(long, value_name = "HEX", requires = "join")]
    pub invite_id: Option<String>,

    /// HTTPS/HTTP API fronting URL for `--join` (e.g. `https://cdn.example.com/_vallum/enroll`)
    /// when UDP enrolment is blocked.
    #[arg(long, value_name = "URL", requires = "join")]
    pub front_url: Option<String>,

    /// Optional HTTP `Host:` header override when enrolling through `--front-url`
    /// (for CDN domain fronting).
    #[arg(long, value_name = "HOST", requires = "front_url")]
    pub front_host: Option<String>,

    /// Refuse unless the server's fingerprint matches this. Printed by
    /// `vallum peer invite`; it is how a client knows it reached the right
    /// server rather than one that answered first.
    ///
    /// It works on the file path too, and there it matters most: a config
    /// copied over email, USB or a chat can be anything, and the fingerprint
    /// is the one thing the operator can check against the server itself.
    #[arg(long, value_name = "FINGERPRINT", requires = "join")]
    pub expect: Option<String>,

    /// The fingerprint to check on the file path. The same value as `--expect`,
    /// but a separate flag, because `--expect` requires `--join` and the file
    /// path has no ticket.
    #[arg(long, value_name = "FINGERPRINT", requires = "client_config")]
    pub expect_server: Option<String>,

    /// On a server, allow devices to enrol with a one-time token (opens UDP
    /// `listen + 1`).
    #[arg(long)]
    pub enroll: bool,

    /// Print every step and change nothing.
    #[arg(long)]
    pub dry_run: bool,
}

/// The address plan `vallum setup --server` offers. It must be the same plan
/// `vallum server init` uses (`server::DEFAULT_ADDRESSES`), or the documented
/// install path produces a /24 - 253 addresses - while the documentation
/// claims the /20's 4,094.
const DEFAULT_ADDRESS: &str = "10.7.0.1/20";

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
        return as_client(bundle, args.dry_run, false, args.allow_shipped_key);
    }
    if let Some(remote) = &args.remote {
        return as_remote(remote, args);
    }
    if let Some(config) = &args.client_config {
        return as_client_config(config, args);
    }
    if let Some(join) = &args.join {
        let ticket = read_ticket_arg(join, std::io::stdin().lock())?;
        return as_join(&ticket, args);
    }
    if !std::io::stdin().is_terminal() {
        return guidance();
    }
    match ask_role()? {
        Role::Server => as_server(args),
        Role::Client => as_interactive_client(args),
    }
}

/// What the machine is for. The only question that changes everything after it.
enum Role {
    Server,
    Client,
}

fn as_interactive_client(args: &SetupArgs) -> Result<(), Error> {
    say!();
    say!("How will this client enrol with the server?");
    say!("  1) Over SSH — generates the key here; nothing secret leaves (recommended)");
    say!("  2) With a one-time invite token (`vallum peer invite` on the server)");
    say!("  3) From a .vallum-bundle file (offline / air-gapped)");
    say!();
    loop {
        match prompt("Choose 1, 2, or 3", Some("1"))?.as_str() {
            "1" | "ssh" | "remote" => {
                let remote = prompt("The server's SSH target (e.g. you@vpn.example.com)", None)?;
                if remote.is_empty() {
                    return Err(Error::Usage(
                        "give an SSH target like you@vpn.example.com".to_owned(),
                    ));
                }
                return as_remote(&remote, args);
            }
            "2" | "token" | "join" => {
                let ticket = prompt(
                    "Paste the join ticket (`vallum1-join:…` from `vallum peer invite`)",
                    None,
                )?;
                let joined = SetupArgs {
                    client_config: None,
                    allow_shipped_key: false,
                    no_service: false,
                    expect_server: None,
                    server: false,
                    client: None,
                    remote: None,
                    remote_config: None,
                    join: Some(ticket.clone()),
                    token: None,
                    invite_id: None,
                    front_url: None,
                    front_host: None,
                    expect: None,
                    enroll: false,
                    endpoint: None,
                    address: None,
                    listen: args.listen.clone(),
                    name: args.name.clone(),
                    yes: args.yes,
                    dry_run: args.dry_run,
                };
                return as_join(&ticket, &joined);
            }
            "3" | "bundle" => {
                let bundle = ask_bundle()?;
                return as_client(&bundle, args.dry_run, true, args.allow_shipped_key);
            }
            other => say!("`{other}` is not one of the three. Type 1, 2, or 3."),
        }
    }
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

/// Ask whether devices may enrol with a one-time token.
///
/// Asked, not assumed: it opens a second UDP port and runs another root
/// service, which is not something to switch on behind an operator's back.
fn ask_enroll(listen: &str) -> Result<bool, Error> {
    if !std::io::stdin().is_terminal() {
        return Ok(false);
    }
    let port = listen_port(listen).unwrap_or(51820).saturating_add(1);
    say!();
    say!("Devices can join in two ways: you hand them a bundle or SSH to them, or");
    say!("they use a one-time token you print with `vallum peer invite`.");
    say!("The token way needs UDP {port} open and a small responder service.");
    match prompt("Allow token enrolment? (y/N)", Some("n"))?.as_str() {
        "y" | "Y" | "yes" => Ok(true),
        _ => Ok(false),
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
        config: crate::host::paths::config_dir().join(format!("{instance}.toml")),
        name: Some(instance.clone()),
        addresses: vec![address.clone()],
        listen: args.listen.clone(),
        endpoint,
        control: None,
        dns: Vec::new(),
        peer_dns: Vec::new(),
        user: None,
        no_nat: false,
        no_firewall: false,
        no_forward: false,
        no_service: false,
        no_host: false,
        dry_run: args.dry_run,
        force: false,
        json: false,
        enroll: args.enroll || (!args.yes && ask_enroll(&args.listen)?),
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
        say!("Next: enrol a client — on that machine, run");
        say!("   sudo vallum setup --remote you@<this-host>");
        say!("or mint a one-time token here with `sudo vallum peer invite <name>`.");
        return Ok(());
    }

    let name = prompt("A name for that client", Some("laptop"))?;
    if init.enroll {
        crate::commands::peer::peer(&crate::commands::peer::PeerArgs {
            command: crate::commands::peer::PeerCommand::Invite(
                crate::commands::peer::InviteArgs {
                    name,
                    config: init.config.clone(),
                    public_key: None,
                    public_key_file: None,
                    ttl: 15,
                    json: false,
                },
            ),
        })?;
        return Ok(());
    }
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
                 `vallum peer add <name> --ship-key --bundle-out <name>.vallum-bundle`"
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

fn as_client(
    bundle: &std::path::Path,
    dry_run: bool,
    interactive: bool,
    allow_shipped_key: bool,
) -> Result<(), Error> {
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
        allow_shipped_key,
        bundle: bundle.to_path_buf(),
        output_dir: None,
        force: false,
        // Joining is the client's own act, not a file handed over by a
        // stranger; the report still prints, the refusal does not apply.
        strict: false,
        allow_hooks: false,
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

/// What a client config and its key look like on this device, once checked.
#[derive(Debug)]
struct ClientFiles {
    /// The instance name: the config file's stem.
    name: String,
    /// The config's text.
    text: String,
    /// Where the private key is.
    key: PathBuf,
    /// The server's public line, as the peer stanza names it.
    ///
    /// This is the trust anchor the operator carries, so it is the one thing
    /// that can be checked against the server itself.
    server_public_line: Option<String>,
}

/// Check a client config and its key without touching anything.
///
/// The validation is separated from the placement so it can be tested without
/// writing to /etc, and so the one thing that can go wrong - a missing key -
/// is reported before anything is moved.
fn resolve_client_files(path: &Path) -> Result<ClientFiles, Error> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::IoPath {
        action: "read the client config",
        path: path.to_path_buf(),
        source,
    })?;
    let config = vallum_config::Config::load(path).map_err(|error| {
        Error::Usage(format!(
            "{} is not a config Vallum can use: {error}",
            path.display()
        ))
    })?;
    let name = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .filter(|stem| !stem.is_empty())
        .unwrap_or_else(|| "vallum0".to_owned());

    // The config names its own key, and the key never leaves this device - so
    // the device is the only party that can have it. If it is not here, the
    // message is the remedy, because there is nothing else the user can do.
    let key = crate::config::resolve_key_path(path, &config.interface.private_key);
    if !key.is_file() {
        return Err(Error::Usage(format!(
            "the config names its private key `{}`, and there is no such file beside it.\n\
             The key never leaves this device, so it has to be made here:\n\
             \n     vallum keygen --output {}\n\
             \n then run this command again.",
            config.interface.private_key.display(),
            key.display(),
        )));
    }

    // The server's public line, from the peer stanza. Taken from the text
    // rather than re-encoded from the parsed key, because the line is what the
    // operator reads off the server and compares.
    let server_public_line = text.split_once("[[peer]]").and_then(|(_, peers)| {
        peers.lines().find_map(|line| {
            let rest = line.trim().strip_prefix("public_key = \"")?;
            rest.split('"').next().map(str::to_owned)
        })
    });

    Ok(ClientFiles {
        name,
        text,
        key,
        server_public_line,
    })
}

/// Enrol this machine from a client config the server wrote.
///
/// This is the receiver the file path never had. Before it, the client side
/// of `peer add --client-config-out` was prose: copy the TOML to
/// /etc/vallum, name the key file exactly as the peer is named, enable two
/// units by hand. Now it is one command.
/// Check a client config's server against a fingerprint the operator was
/// given separately.
///
/// A config that travelled over email, USB or a chat can be anything. The
/// fingerprint is the one thing that can be compared with the server itself,
/// and it is the only trust anchor on the file path that is not simply
/// "whatever this file says".
///
/// Separated from the receiver so the decision is testable without a
/// filesystem or a root.
fn check_server_fingerprint(expect: &str, server_line: Option<&str>) -> Result<String, Error> {
    let server_line = server_line.ok_or_else(|| {
        Error::Usage(
            "the config names no server public line, so there is nothing to check against the \
             fingerprint"
                .to_owned(),
        )
    })?;
    let got = crate::keys::fingerprint(server_line);
    if !got.eq_ignore_ascii_case(expect.trim()) {
        return Err(Error::Precondition(format!(
            "this is not the server you were given a config for.\n\
             \x20 expected {}\n\
             \x20 the config names {}\n\
             Nothing was written. If the server was rebuilt, ask for a new config; \
             if not, treat this as an attack.",
            expect.trim(),
            got
        )));
    }
    Ok(got)
}

fn as_client_config(path: &Path, args: &SetupArgs) -> Result<(), Error> {
    let files = resolve_client_files(path)?;
    let root = nix::unistd::Uid::effective().is_root();
    let name = files.name.clone();

    say!("enrolling `{name}` from {}", path.display());

    // Before anything is written: is this the server the operator meant? A
    // file copied over email, USB or a chat can be anything, and the
    // fingerprint is the one thing that can be checked against the server
    // itself - read it off the server's console, or read it out over a
    // channel you already trust.
    if let Some(expect) = &args.expect_server {
        let got = check_server_fingerprint(expect, files.server_public_line.as_deref())?;
        say!("   ok    server fingerprint {got}");
    }

    if root {
        let directory = crate::host::paths::config_dir().to_path_buf();
        std::fs::create_dir_all(&directory).map_err(|source| Error::IoPath {
            action: "create",
            path: directory.clone(),
            source,
        })?;
        let config_path = directory.join(format!("{name}.toml"));
        let key_path = directory.join(format!("{name}.key"));

        // The key is renamed to sit beside the config, and the config is told
        // the new name: the server named it after the PEER, and the file name
        // is this machine's business.
        let text = vallum_config::with_local_private_key(&files.text, &format!("{name}.key"));
        let text = vallum_config::with_local_fwmark(&text);
        crate::keys::write_private(&config_path, text.as_bytes())?;
        std::fs::copy(&files.key, &key_path).map_err(|source| Error::IoPath {
            action: "copy the private key",
            path: files.key.clone(),
            source,
        })?;
        // The units drop capabilities, so root loses CAP_DAC_OVERRIDE and
        // cannot read a 0600 file owned by anyone else.
        for path in [&config_path, &key_path] {
            let _ = std::os::unix::fs::chown(path, Some(0), Some(0));
        }
        say!("   config     {}", config_path.display());
        say!("   key        {}", key_path.display());
        if args.no_service {
            // The files are placed; the unit is not installed. Where there is
            // no systemd, or the units belong to something else, this is the
            // whole job.
            say!("   service    skipped (--no-service)");
            say!(
                "Run it with `sudo vallum run --config {}`.",
                config_path.display()
            );
            return Ok(());
        }
        crate::commands::server::install_service(&name, false)?;
        let server_address = vallum_config::Config::load(&config_path)
            .ok()
            .and_then(|config| config.peers.first().and_then(|peer| peer.endpoint.clone()));
        prove_tunnel(&name, &config_path, server_address.as_deref());
        say!(
            "Check it with `vallum status --config {}`, then watch it with `vallum tui`.",
            config_path.display()
        );
        return Ok(());
    }

    // Not root: the files stay where they are, and the user is told how to
    // run it - with the config path, not a guess.
    let text = vallum_config::with_local_private_key(&files.text, &format!("{name}.key"));
    let text = vallum_config::with_local_fwmark(&text);
    let config_path = path
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!("{name}.toml"));
    crate::keys::write_private(&config_path, text.as_bytes())?;
    say!("   config     {}", config_path.display());
    say!("   key        {} (this machine only)", files.key.display());
    say!(
        "Run it with `sudo vallum run --config {}`,",
        config_path.display()
    );
    say!("or re-run this with sudo to install it as a service.");
    let _ = args;
    Ok(())
}

/// Name what actually went wrong when the SSH leg of an enrolment fails.
///
/// Three different causes arrive as one exit status, and the old message called
/// all of them "the server refused the enrolment" - which is wrong twice over:
/// the server refused nothing, and the causes need different remedies. A sudo
/// that wants a password, a `vallum` that is not installed, and an ssh
/// connection that failed are three different problems, and the user can only
/// fix the one they are actually having.
/// Quote a value for a POSIX shell.
///
/// ssh passes the remote command to the remote's shell, so a value that is
/// interpolated into that command is shell input. Single quotes make
/// everything inside literal; the only thing that cannot appear inside them
/// is a single quote, so one is closed, escaped and reopened.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn ssh_failure(code: Option<i32>, stderr: &str, remote: &str, name: &str) -> String {
    let text = stderr.to_ascii_lowercase();
    let (reason, remedy) = if code == Some(127) || text.contains("command not found") {
        (
            "the server has no `vallum` on that user's PATH",
            "install it there first (the same installer: sudo ./scripts/install.sh), then enrol again".to_owned(),
        )
    } else if text.contains("terminal is required")
        || text.contains("no tty")
        || text.contains("askpass")
        || text.contains("a password is required")
    {
        (
            "the server's sudo wants a password, and this command runs with no terminal to ask on",
            format!(
                "give that user passwordless sudo for `vallum peer enroll`, or enrol with a \
                 bundle instead: vallum peer add {name} --ship-key --bundle-out {name}.vallum-bundle"
            ),
        )
    } else if code == Some(255) {
        (
            "the ssh connection itself failed",
            format!("check the login first: ssh {remote} true"),
        )
    } else {
        (
            "the server refused the enrolment",
            "the server's own words are below".to_owned(),
        )
    };
    format!(
        "the enrolment of `{name}` over SSH did not work: {reason}.\n\
         {remedy}\n\
         \n   the server said: {stderr}"
    )
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
    if let Some(existing) = existing_enrolment(&name, crate::host::paths::config_dir()) {
        say!("already enrolled: {}", existing.display());
        return start_existing(&existing, &name);
    }

    let seed = crate::entropy::seed();
    let secret = crate::keys::new_secret(3, false, seed);
    let suite = SdkSuite::from_id(secret.suite).map_err(|error| Error::Suite(error.to_string()))?;
    let identity = crate::keys::identity(&suite, &secret)?;
    let public_line = crate::keys::encode_public(secret.suite, &identity.to_peer());
    say!("generated a key here; the private half does not leave this machine");

    let config_flag = match &args.remote_config {
        Some(path) => format!(" --config {}", shell_quote(&path.display().to_string())),
        None => String::new(),
    };
    // ssh runs the remote command through the REMOTE'S SHELL, so every value
    // that goes into it is shell input, not an argument. An unquoted name -
    // which comes from `--name`, and can be anything - was an injection into
    // the host being enrolled: `x; id` ran a second command there, and the
    // config path was the same.
    let remote_command = format!(
        "sudo vallum peer enroll {}{config_flag} --public-key-file /dev/stdin --json",
        shell_quote(&name)
    );
    // `VALLUM_SSH_OPTS` is split on whitespace and passed as literal
    // arguments, never through a shell. `vallum-ops` sets it so the enrolment
    // it runs cannot prompt or hang; sudo/pkexec reset the caller's
    // environment, so a user cannot inject flags into the privileged run.
    let ssh_opts: Vec<String> = std::env::var("VALLUM_SSH_OPTS")
        .unwrap_or_default()
        .split_whitespace()
        .map(String::from)
        .collect();
    let mut child = std::process::Command::new("ssh")
        .args(&ssh_opts)
        // `--` ends ssh's options: a remote that starts with a dash is a
        // hostname, not an option.
        .arg("--")
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
        return Err(Error::Precondition(ssh_failure(
            output.status.code(),
            stderr.trim(),
            remote,
            &name,
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

    let server_address = report
        .get("server_address")
        .and_then(|address| address.as_str());
    // The server tells us whether the peer was actually applied to the running
    // daemon. Ignoring that verdict is how a client ends up holding a config
    // that can never handshake: the enrolment "succeeds", the file is written,
    // and the failure surfaces 35 seconds later as "no handshake within 35s",
    // which points at the client rather than at the server.
    let applied = report.get("applied").and_then(|a| a.as_bool());
    if applied == Some(false) {
        return Err(Error::Precondition(
            "the server accepted the peer but did NOT apply it to the running daemon.\n\
             Its own report says: applied no. The most common cause is that the\n\
             server's vallum daemon is not running, or was started with --no-service.\n\
             On the server: sudo systemctl start vallum@<interface>\n\
             Then enrol the device again."
                .to_owned(),
        ));
    }
    // Before anything is written: is this the server the invite named?
    if let Some(expect) = &args.expect {
        let server_line = config_text
            .lines()
            .find_map(|line| line.trim().strip_prefix("public_key = \""))
            .and_then(|rest| rest.split('"').next())
            .ok_or_else(|| {
                Error::Usage("the answer had no server public line to check".to_owned())
            })?;
        let got = crate::keys::fingerprint(server_line);
        if !got.eq_ignore_ascii_case(expect.trim()) {
            return Err(Error::Precondition(format!(
                "this is not the server the invite named.\n\
                 \x20 expected {}\n\
                 \x20 answered {}\n\
                 Nothing was written. If the server was rebuilt, mint a new invite; \
                 if not, treat this as an attack.",
                expect.trim(),
                got
            )));
        }
        say!("   ok    server fingerprint {got}");
    }
    place_config(
        &name,
        config_text,
        &secret,
        address,
        endpoint,
        server_address,
    )
}

/// Write the enrolled config and its key, and either install the service
/// (as root) or say how to run it.
fn place_config(
    name: &str,
    config_text: &str,
    secret: &crate::keys::SecretFile,
    address: &str,
    endpoint: &str,
    server_address: Option<&str>,
) -> Result<(), Error> {
    let root = nix::unistd::Uid::effective().is_root();
    let directory = if root {
        crate::host::paths::config_dir().to_path_buf()
    } else {
        PathBuf::from(".")
    };
    place_config_in(
        name,
        config_text,
        secret,
        address,
        endpoint,
        server_address,
        &directory,
    )
}

/// `place_config` with the destination named, so a test can watch what lands
/// on disk without changing the process's working directory.
#[allow(clippy::too_many_arguments)]
fn place_config_in(
    name: &str,
    config_text: &str,
    secret: &crate::keys::SecretFile,
    address: &str,
    endpoint: &str,
    server_address: Option<&str>,
    directory: &Path,
) -> Result<(), Error> {
    let root = nix::unistd::Uid::effective().is_root();
    let directory = directory.to_path_buf();
    std::fs::create_dir_all(&directory).map_err(|source| Error::IoPath {
        action: "create",
        path: directory.clone(),
        source,
    })?;
    let key_path = directory.join(format!("{name}.key"));
    let config_path = directory.join(format!("{name}.toml"));
    crate::keys::save_secret(&key_path, secret)?;
    // `fwmark` is this machine's routing detail: a server released before the
    // field existed hands back a config that would refuse to attach.
    let mut config_text = vallum_config::with_local_fwmark(config_text);
    // The server named the key after the PEER; the file is named after this
    // machine's `--name`. Without this the config points at a key that is not
    // there, and the tunnel refuses to start with a file-not-found.
    config_text = vallum_config::with_local_private_key(&config_text, &format!("{name}.key"));

    // Probe path MTU to the server endpoint. If a reduced-MTU link (PPPoE, DS-Lite)
    // is measured, configure `interface.outer_mtu` so large payloads do not hang.
    if !endpoint.is_empty() && endpoint != "?" {
        if let Some(measured) = crate::net::probe_path_mtu_host(endpoint) {
            if measured < crate::config::DEFAULT_OUTER_MTU {
                say!("   ok    path MTU to {endpoint} measured as {measured} bytes (configured interface.outer_mtu = {measured})");
                config_text = vallum_config::with_outer_mtu(&config_text, measured);
            }
        }
    }

    crate::keys::write_private(&config_path, config_text.as_bytes())?;

    say!();
    say!("enrolled `{name}` — {address}, through {endpoint}");
    say!("   config     {}", config_path.display());
    say!("   key        {} (this machine only)", key_path.display());
    if root && config_path.starts_with(crate::host::paths::config_dir()) {
        crate::commands::server::install_service(name, false)?;
        prove_tunnel(name, &config_path, server_address);
        say!("Check it with `vallum doctor`, then watch it with `vallum tui`.");
    } else {
        say!(
            "Run it with `sudo vallum run --config {}`.",
            config_path.display()
        );
    }
    Ok(())
}

/// Prove the tunnel actually carries traffic, rather than trusting that a
/// config was written.
///
/// Three separate failures in this project's dogfooding all ended in
/// "enrolled" followed by "no internet": a unit that could not exec, a config
/// root could not read, and a default route into a dead interface. None of
/// them were visible at the moment of enrolment. So enrolment finishes here:
/// a real handshake, and a real packet, or a named reason why not.
fn prove_tunnel(name: &str, config: &Path, server_address: Option<&str>) {
    let socket = vallum_config::Config::load(config)
        .ok()
        .and_then(|cfg| cfg.interface.control)
        .unwrap_or_else(|| vallum_config::socket_path(name));
    say!();
    say!("proving the tunnel…");
    // Longer than the 25 s keepalive: nothing else makes a fresh client dial.
    // It has no route to the server's tunnel address yet (its own address is a
    // /32), so a ping cannot be the trigger, and a 15 s window ended before the
    // first keepalive ever fired — a working enrolment reported "no handshake"
    // (2026-11-11, found by enrolling from a clean container).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(35);
    let mut handshaked = false;
    while std::time::Instant::now() < deadline {
        if let Ok(response) = crate::control::request(&socket, "get=1\n") {
            if handshake_seen(&response) {
                handshaked = true;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    if !handshaked {
        say!("   fail  no handshake within 35s");
        say!("         likely causes, in order:");
        say!("           · UDP 51820 is filtered on the server (firewall, provider)");
        say!("           · the server's daemon has not applied this peer yet");
        say!("           · the endpoint in this config is not reachable from here");
        say!("           · the server's daemon is not running");
        say!(
            "         `vallum doctor --config {}` checks all three.",
            config.display()
        );
        return;
    }
    say!("   ok    handshake with the server");
    let Some(address) = server_address else {
        return;
    };
    let status = std::process::Command::new("ping")
        .args(["-c", "2", "-W", "1", address])
        .output();
    match status {
        Ok(output) if output.status.success() => say!("   ok    ping {address} (2/2)"),
        Ok(output) => {
            let lost = String::from_utf8_lossy(&output.stdout)
                .lines()
                .find(|line| line.contains("packet loss"))
                .unwrap_or("no reply")
                .to_owned();
            say!("   warn  handshake ok, but ping {address} failed: {lost}");
            say!("         the server may not route its own tunnel address, or ICMP");
            say!("         is filtered; a TCP check through the tunnel settles it.");
        }
        Err(_) => say!("   skip  ping is not installed; handshake is the proof"),
    }
}

/// Whether any peer has completed a handshake, read from the UAPI `get`.
fn handshake_seen(response: &str) -> bool {
    response.lines().any(|line| {
        line.strip_prefix("last_handshake_time_sec=")
            .and_then(|value| value.trim().parse::<u64>().ok())
            .is_some_and(|seconds| seconds > 0)
    })
}

/// Whether this enrolment must say that it is not checking the server's
/// identity.
///
/// A join ticket carries the server's fingerprint, so the ticket path always
/// checks it. The legacy `host:port` path has no fingerprint to check unless
/// one is given with `--expect`, and it used to accept whichever server
/// answered without saying so.
fn warns_about_identity(expect: Option<&str>, ticket_fingerprint: &str) -> bool {
    expect.is_none() && ticket_fingerprint.is_empty()
}

/// The join ticket to enrol with.
///
/// `-` reads it from stdin, which keeps the single-use token inside it out of
/// argv and out of the shell's history. The recommended command used to put
/// the ticket on the command line, where `ps` shows it to every user on the
/// host - and the ticket is the one thing that must not be shared.
fn read_ticket_arg(arg: &str, stdin: impl std::io::BufRead) -> Result<String, Error> {
    if arg != "-" {
        // Only a ticket carries the secret. The legacy `host:port` argument
        // does not, so warning about it would be noise about nothing.
        if arg.starts_with(crate::enroll::TICKET_PREFIX) {
            say!("note: a ticket passed as an argument is visible in `ps` and stays in");
            say!("      shell history; `--join -` reads it from stdin instead");
        }
        return Ok(arg.to_owned());
    }
    let ticket = read_token_arg(Some("-"), stdin)?;
    if ticket.is_empty() {
        return Err(Error::Usage(
            "no ticket on stdin: paste the `vallum1-join:…` line".to_owned(),
        ));
    }
    Ok(ticket)
}

/// Resolve `--token`: `-` reads a line from `stdin` so the token stays out of
/// shell history and `ps`; a literal token warns and returns it.
fn read_token_arg(arg: Option<&str>, mut stdin: impl std::io::BufRead) -> Result<String, Error> {
    match arg {
        Some("-") => {
            let mut line = String::new();
            stdin
                .read_line(&mut line)
                .map_err(|error| Error::Usage(format!("reading the token: {error}")))?;
            Ok(line.trim().to_owned())
        }
        Some(token) => {
            say!("note: a token passed as an argument is visible in `ps` and stays in");
            say!("      shell history; `--token -` reads it from stdin instead");
            Ok(token.to_owned())
        }
        None => Ok(String::new()),
    }
}

/// Enrol with a single-use token — transport B, for machines that cannot SSH.
///
/// `server` is either the `vallum1-join:…` ticket `peer invite` prints, or a
/// bare `host:port` alongside `--invite-id`/`--token`/`--expect` (the form
/// invites printed before tickets existed — kept working).
fn as_join(server: &str, args: &SetupArgs) -> Result<(), Error> {
    let ticket;
    let server = if server.starts_with(crate::enroll::TICKET_PREFIX) {
        if args.token.is_some() || args.invite_id.is_some() || args.expect.is_some() {
            return Err(Error::Usage(
                "a join ticket already carries the id, token, and fingerprint — \
                 drop --invite-id/--token/--expect"
                    .to_owned(),
            ));
        }
        ticket = crate::enroll::JoinTicket::parse(server)?;
        ticket.server.clone()
    } else {
        ticket = crate::enroll::JoinTicket {
            server: server.to_owned(),
            name: String::new(),
            invite_id: args.invite_id.clone().ok_or_else(|| {
                Error::Usage(
                    "--invite-id is needed: `vallum peer invite` prints the whole command"
                        .to_owned(),
                )
            })?,
            token: crate::enroll::Token::parse(&read_token_arg(
                args.token.as_deref(),
                std::io::stdin().lock(),
            )?)?,
            fingerprint: args.expect.clone().unwrap_or_default(),
        };
        server.to_owned()
    };
    let server = server.as_str();
    let name = args
        .name
        .clone()
        .or_else(|| (!ticket.name.is_empty()).then(|| ticket.name.clone()))
        .or_else(hostname)
        .unwrap_or_else(|| "client".to_owned());
    let expect = args
        .expect
        .clone()
        .or_else(|| (!ticket.fingerprint.is_empty()).then(|| ticket.fingerprint.clone()));
    if warns_about_identity(expect.as_deref(), &ticket.fingerprint) {
        // The ticket form always carries the server's fingerprint, so this is
        // only reachable on the legacy `host:port` path. It used to say
        // nothing at all: the client accepted whichever server answered, and
        // sent it the single-use token.
        say!("warning: this enrolment does not check the server's identity.");
        say!("         the client accepts whichever server answers {server}, and the");
        say!("         single-use token is sent to it. Pass --expect <fingerprint> to be");
        say!("         sure you reached the server you meant.");
    }
    if args.dry_run {
        say!("would generate a key here and ask {server} to enrol `{name}`");
        say!("   the token proves the server invited this machine; no secrets travel");
        return Ok(());
    }

    let seed = crate::entropy::seed();
    let secret = crate::keys::new_secret(3, false, seed);
    let suite = SdkSuite::from_id(secret.suite).map_err(|error| Error::Suite(error.to_string()))?;
    let identity = crate::keys::identity(&suite, &secret)?;
    let public_line = crate::keys::encode_public(secret.suite, &identity.to_peer());
    say!("generated a key here; the private half does not leave this machine");
    say!("asking {server} to enrol `{name}`…");

    let answer = if let Some(front_url) = args.front_url.as_deref() {
        crate::enroll::join_via_front(
            front_url,
            args.front_host.as_deref(),
            &ticket.token,
            &ticket.invite_id,
            &name,
            &public_line,
        )?
    } else {
        crate::enroll::join(
            server,
            &ticket.token,
            &ticket.invite_id,
            &name,
            &public_line,
        )?
    };
    let report: serde_json::Value = serde_json::from_str(&answer)
        .map_err(|error| Error::Usage(format!("the server's answer was not JSON: {error}")))?;
    let config_text = report
        .get("config")
        .and_then(|config| config.as_str())
        .ok_or_else(|| Error::Usage("the server's answer had no config".to_owned()))?;
    let address = report
        .get("address")
        .and_then(|address| address.as_str())
        .unwrap_or("?");
    let endpoint = report
        .get("endpoint")
        .and_then(|endpoint| endpoint.as_str())
        .unwrap_or(server);
    let server_address = report
        .get("server_address")
        .and_then(|address| address.as_str());
    // Before anything is written: is this the server the invite named?
    if let Some(expect) = &expect {
        let server_line = config_text
            .lines()
            .find_map(|line| line.trim().strip_prefix("public_key = \""))
            .and_then(|rest| rest.split('"').next())
            .ok_or_else(|| {
                Error::Usage("the answer had no server public line to check".to_owned())
            })?;
        let got = crate::keys::fingerprint(server_line);
        if !got.eq_ignore_ascii_case(expect.trim()) {
            return Err(Error::Precondition(format!(
                "this is not the server the invite named.\n\
                 \x20 expected {}\n\
                 \x20 answered {}\n\
                 Nothing was written. If the server was rebuilt, mint a new invite; \
                 if not, treat this as an attack.",
                expect.trim(),
                got
            )));
        }
        say!("   ok    server fingerprint {got}");
    }
    place_config(
        &name,
        config_text,
        &secret,
        address,
        endpoint,
        server_address,
    )
}

/// An already-enrolled config: `<name>.toml` whose `<name>.key` also exists,
/// checked under the system config directory and the working directory.
/// Either alone is not an enrolment — a config with a missing key would only
/// have setup tried again anyway, and a bare key could be anything.
fn existing_enrolment(name: &str, config_dir: &Path) -> Option<PathBuf> {
    [
        config_dir.join(format!("{name}.toml")),
        PathBuf::from(format!("{name}.toml")),
    ]
    .into_iter()
    .find(|path| path.is_file() && path.with_extension("key").is_file())
}

/// Finish a machine that is already enrolled: install the service, or say how
/// to run it.
fn start_existing(config: &std::path::Path, name: &str) -> Result<(), Error> {
    let root = nix::unistd::Uid::effective().is_root();
    let in_etc = config.starts_with(crate::host::paths::config_dir());
    if root && in_etc {
        crate::commands::server::install_service(name, false)?;
        say!("Check it with `vallum doctor`, then watch it with `vallum tui`.");
        return Ok(());
    }
    if root && !in_etc {
        // The unit reads /etc/vallum/<name>.toml, so move it there.
        let target = crate::host::paths::config_dir().join(format!("{name}.toml"));
        let key = config.with_extension("key");
        let key_target = crate::host::paths::config_dir().join(format!("{name}.key"));
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

/// The one place the product says how a client gets its configuration.
///
/// Three surfaces used to answer this question - `vallum` with no arguments,
/// `vallum setup` with no arguments, and the deployment docs - and they
/// disagreed, in a different order each. A user who asked "how do I get my
/// config" got a different answer depending on where they looked, and the
/// answer they got first was the token path: the one ADR-0034 demoted.
///
/// So the text lives here, once, and every surface prints it.
#[must_use]
pub fn guidance_text() -> String {
    let mut text = String::new();
    text.push_str("Vallum — a post-quantum tunnel between two machines.\n\n");
    text.push_str("On the server, where clients connect:\n");
    text.push_str("   sudo vallum setup --server\n\n");
    text.push_str("On a client, with what the server gave you:\n");
    text.push_str(
        "   sudo vallum setup --client-config laptop.toml   (a config the server wrote)\n",
    );
    text.push_str("   sudo vallum setup --remote you@<server>        (over SSH instead)\n");
    text.push_str("   sudo vallum join vallum1-join:…                (a one-time token)\n");
    text.push_str("   sudo vallum setup --client <file>.vallum-bundle (a bundle file)\n\n");
    text.push_str("Every one of these keeps this machine's private key here.\n");
    text.push_str("`vallum setup` with no flags asks which of the two this machine is.\n");
    text.push_str("Every individual command is under `vallum --help`.");
    text
}

/// The non-interactive default: say what the paths are, without running any
/// of them. A prompt a script cannot answer is worse than a clear instruction.
fn guidance() -> Result<(), Error> {
    for line in guidance_text().lines() {
        say!("{}", line);
    }
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

    /// `vallum join --name X` renames the key file to `X.key`, so the config
    /// must name `X.key` too. It used to keep the server's peer-named path
    /// (`u0009-….key`), and the tunnel then refused to start with a
    /// file-not-found — found by signing up for a tunnel through the desk.
    #[test]
    fn a_named_join_points_the_config_at_the_key_beside_it() {
        let dir = std::env::temp_dir().join(format!("vallum-join-name-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let server_text = "[interface]\nname = \"vallum-u0009\"\nprivate_key = \"u0009-redeem-t.key\"\naddress = \"10.99.90.7/32\"\n\n[[peer]]\nname = \"server\"\npublic_key = \"vallum1:0003:00:-\"\nallowed_ips = [\"10.99.90.0/24\"]\n";
        let secret = crate::keys::new_secret(3, false, [7u8; 32]);
        place_config_in(
            "desk-client",
            server_text,
            &secret,
            "10.99.90.7/32",
            "198.51.100.10:51921",
            None,
            &dir,
        )
        .unwrap();
        let written = std::fs::read_to_string(dir.join("desk-client.toml")).unwrap();
        assert!(
            written.contains("private_key = \"desk-client.key\""),
            "the config must name the key that was written beside it:\n{written}"
        );
        assert!(
            !written.contains("u0009-redeem-t.key"),
            "the peer-named path must be gone"
        );
        assert!(
            dir.join("desk-client.key").exists(),
            "the key file must exist under the new name"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An existing `<name>.toml` + `<name>.key` pair means "already enrolled":
    /// `setup --remote` must not generate a second identity over the first —
    /// the server still knows the first, and the new one is unknown_peer.
    #[test]
    fn an_enrolled_config_and_key_count_as_existing() {
        let dir = std::env::temp_dir().join(format!("vallum-enrol-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let name = format!("t-{}", std::process::id());
        let toml = dir.join(format!("{name}.toml"));
        let key = dir.join(format!("{name}.key"));
        // Neither half alone is an enrolment.
        assert!(existing_enrolment(&name, &dir).is_none());
        std::fs::write(&toml, "[interface]\n").unwrap();
        assert!(existing_enrolment(&name, &dir).is_none());
        std::fs::write(&key, "seed").unwrap();
        assert_eq!(existing_enrolment(&name, &dir), Some(toml));
        std::fs::remove_file(&key).unwrap();
        assert!(existing_enrolment(&name, &dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The bare `host:port` path has no fingerprint to check, and it used to
    /// say nothing about that.
    #[test]
    fn the_bare_join_path_says_it_is_not_checking_the_server() {
        assert!(
            warns_about_identity(None, ""),
            "the bare path must warn: nothing checks the server"
        );
        // A ticket carries the fingerprint, so the ticket path checks it.
        assert!(!warns_about_identity(None, "a1b2c3d4e5f6"));
        // So does an explicit --expect.
        assert!(!warns_about_identity(Some("a1b2c3d4e5f6"), ""));
    }

    /// The ticket carries the single-use token, so it must be able to arrive
    /// on stdin instead of on the command line.
    #[test]
    fn a_ticket_can_come_from_stdin() {
        let ticket = "vallum1-join:192.168.1.1:51821/laptop/abc123/fingerprint";
        let mut cursor = std::io::Cursor::new(format!("{ticket}\n"));
        assert_eq!(
            read_ticket_arg("-", &mut cursor).unwrap(),
            ticket,
            "the ticket must be read from stdin"
        );
    }

    #[test]
    fn an_empty_stdin_is_a_clear_error() {
        let mut cursor = std::io::Cursor::new("\n");
        let error = read_ticket_arg("-", &mut cursor).expect_err("an empty stdin is an error");
        assert!(error.to_string().contains("no ticket on stdin"), "{error}");
    }

    /// The warning is about the secret: a bare `host:port` carries none, so
    /// it must not be warned about.
    #[test]
    fn a_bare_host_is_not_warned_about_as_a_ticket() {
        let mut cursor = std::io::Cursor::new("");
        assert_eq!(
            read_ticket_arg("192.168.1.1:51821", &mut cursor).unwrap(),
            "192.168.1.1:51821"
        );
    }

    /// A ticket in argv is still accepted - it is the only way on some
    /// systems - but the operator is told what it costs.
    #[test]
    fn a_ticket_in_argv_is_accepted_with_a_warning() {
        let ticket = "vallum1-join:192.168.1.1:51821/laptop/abc123/fingerprint";
        let mut cursor = std::io::Cursor::new("");
        assert_eq!(read_ticket_arg(ticket, &mut cursor).unwrap(), ticket);
    }

    /// A name is shell input, not an argument: it reaches the remote's
    /// shell through ssh.
    #[test]
    fn a_name_is_quoted_for_the_remote_shell() {
        assert_eq!(shell_quote("laptop"), "'laptop'");
        assert_eq!(shell_quote("x; id"), "'x; id'");
        assert_eq!(shell_quote("a b"), "'a b'");
        // A single quote is the one character that cannot be inside single
        // quotes, so it is closed, escaped and reopened.
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote("$(id)"), "'$(id)'");
        assert_eq!(shell_quote("`id`"), "'`id`'");
    }

    /// The whole command line, as ssh would receive it.
    #[test]
    fn the_enrol_command_cannot_carry_a_second_command() {
        let name = "laptop; rm -rf /tmp/x";
        let config = format!(" --config {}", shell_quote("/etc/vallum/a b.toml"));
        let command = format!(
            "sudo vallum peer enroll {}{config} --public-key-file /dev/stdin --json",
            shell_quote(name)
        );
        // Every value that could end the command is inside single quotes, so
        // the remote shell sees one command and no more.
        assert!(command.contains("'laptop; rm -rf /tmp/x'"), "{command}");
        assert!(command.contains("'/etc/vallum/a b.toml'"), "{command}");
    }

    /// A client config carries the server's public line, and that line is the
    /// trust anchor the operator can check against the server itself.
    #[test]
    fn the_client_config_carries_the_servers_public_line() {
        let dir = std::env::temp_dir().join(format!("vallum-line-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("laptop.toml");
        std::fs::write(&config, "[interface]\nname = \"laptop\"\nprivate_key = \"laptop.key\"\n\n[[peer]]\nname = \"server\"\npublic_key = \"vallum1:0003:03:-\"\n").unwrap();
        std::fs::write(dir.join("laptop.key"), "key").unwrap();

        let files = resolve_client_files(&config).expect("the config and its key are there");
        assert_eq!(
            files.server_public_line.as_deref(),
            Some("vallum1:0003:03:-"),
            "the peer stanza's public line is what the operator checks"
        );

        // A config with no peer stanza has nothing to check, and says so
        // rather than inventing an anchor.
        let bare = dir.join("bare.toml");
        std::fs::write(
            &bare,
            "[interface]\nname = \"bare\"\nprivate_key = \"bare.key\"\n",
        )
        .unwrap();
        std::fs::write(dir.join("bare.key"), "key").unwrap();
        let files = resolve_client_files(&bare).expect("the config and its key are there");
        assert_eq!(files.server_public_line, None);
    }

    /// The check refuses before anything is written. A config that travelled
    /// over email, USB or a chat can be anything; the fingerprint is the one
    /// thing that can be compared with the server itself.
    #[test]
    fn a_config_naming_the_wrong_server_is_refused() {
        let dir = std::env::temp_dir().join(format!("vallum-expect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let name = "vallum-expect-check";
        let config = dir.join(format!("{name}.toml"));
        std::fs::write(&config, "[interface]\nname = \"laptop\"\nprivate_key = \"laptop.key\"\n\n[[peer]]\nname = \"server\"\npublic_key = \"vallum1:0003:03:-\"\n").unwrap();
        std::fs::write(dir.join("laptop.key"), "key").unwrap();

        let error = check_server_fingerprint("0000000000000000", Some("vallum1:0003:03:-"))
            .expect_err("the fingerprint does not match");
        let message = error.to_string();
        assert!(message.contains("not the server"), "{message}");
        assert!(message.contains("Nothing was written"), "{message}");

        // The right fingerprint passes, and says what it accepted.
        let right = crate::keys::fingerprint("vallum1:0003:03:-");
        let got = check_server_fingerprint(&right, Some("vallum1:0003:03:-"))
            .expect("the fingerprint matches");
        assert_eq!(got, right);

        // A config with no server line has nothing to check against.
        let error = check_server_fingerprint(&right, None).expect_err("nothing to check");
        assert!(
            error.to_string().contains("no server public line"),
            "{error}"
        );
    }

    /// Three causes, three different remedies. The old message called all of
    /// them "the server refused the enrolment".
    #[test]
    fn the_ssh_failure_names_the_cause_that_actually_applies() {
        let sudo = ssh_failure(
            Some(1),
            "sudo: a terminal is required to read the password",
            "vpn.example.com",
            "laptop",
        );
        assert!(sudo.contains("sudo wants a password"), "{sudo}");

        let missing = ssh_failure(
            Some(127),
            "sudo: vallum: command not found",
            "vpn.example.com",
            "laptop",
        );
        assert!(
            missing.contains("no `vallum` on that user's PATH"),
            "{missing}"
        );

        let transport = ssh_failure(
            Some(255),
            "Host key verification failed.",
            "vpn.example.com",
            "laptop",
        );
        assert!(
            transport.contains("ssh connection itself failed"),
            "{transport}"
        );

        for message in [sudo, missing, transport] {
            assert!(
                message.contains("vpn.example.com") || message.contains("laptop"),
                "every message names something to act on: {message}"
            );
        }
    }

    /// The guidance is one text, and it leads with the file path.
    #[test]
    fn the_guidance_leads_with_the_file_path() {
        let text = guidance_text();
        let file = text
            .find("--client-config")
            .expect("the file path is named");
        let ssh = text.find("--remote").expect("ssh is named");
        let token = text.find("vallum1-join").expect("the token is named");
        assert!(file < ssh && ssh < token, "the order is the order: {text}");
    }

    #[test]
    fn the_port_comes_from_the_listen_address() {
        assert_eq!(listen_port("0.0.0.0:51820").unwrap(), 51820);
        assert_eq!(listen_port("[::]:51820").unwrap(), 51820);
        assert!(listen_port("0.0.0.0").is_err());
    }

    #[test]
    fn dash_token_reads_from_stdin_and_trims() {
        let cursor = std::io::Cursor::new(b"a1b2-c3d4-e5f6-0011-2233-4455-6677-8899\n");
        let raw = read_token_arg(Some("-"), cursor).unwrap();
        let parsed = crate::enroll::Token::parse(&raw).unwrap();
        assert_eq!(parsed.display(), "a1b2-c3d4-e5f6-0011-2233-4455-6677-8899");
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
