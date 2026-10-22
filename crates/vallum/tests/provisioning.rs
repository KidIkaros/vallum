// SPDX-License-Identifier: Apache-2.0

//! The provisioning path, driven the way an operator drives it: the binary.
//!
//! These tests run `vallum server init` and `vallum peer` as separate processes
//! against a scratch directory, with `--no-host --no-service` so no root and no
//! systemd are needed. What they prove is the thing a unit test cannot: that the
//! commands a person follows produce configs the daemon accepts, and that the
//! second run of each command converges instead of duplicating.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vallum"))
}

fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("vallum-provisioning-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(command: &mut Command) -> (bool, String, String) {
    let output = command.output().unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn init(dir: &Path) -> PathBuf {
    let config = dir.join("vallum0.toml");
    let (ok, stdout, stderr) = run(bin()
        .args(["server", "init", "--config"])
        .arg(&config)
        .args(["--endpoint", "203.0.113.5", "--no-host", "--no-service"]));
    assert!(ok, "server init failed\nstdout: {stdout}\nstderr: {stderr}");
    config
}

fn keygen(dir: &Path, name: &str) -> String {
    let key = dir.join(format!("{name}.key"));
    let (ok, stdout, stderr) = run(bin()
        .args(["keygen", "--output"])
        .arg(&key)
        .args(["--suite", "3"]));
    assert!(ok, "keygen failed: {stderr}");
    stdout.trim().to_owned()
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn server_init_writes_a_config_and_a_0600_key() {
    let dir = scratch("init");
    let config = init(&dir);

    assert!(config.exists());
    assert!(dir.join("vallum0.key").exists());
    assert_eq!(mode(&config), 0o600, "the config can name a PSK file");
    assert_eq!(mode(&dir.join("vallum0.key")), 0o600);

    let parsed = vallum_config::Config::load(&config).unwrap();
    assert_eq!(parsed.interface.listen.as_deref(), Some("0.0.0.0:51820"));
    assert_eq!(parsed.interface.private_key, PathBuf::from("vallum0.key"));
    assert!(parsed.interface.control.is_some());

    let (ok, stdout, _) = run(bin()
        .args(["peer", "list", "--config"])
        .arg(&config)
        .arg("--json"));
    assert!(ok);
    assert_eq!(stdout.trim(), "[]");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn server_init_never_regenerates_the_key() {
    let dir = scratch("idempotent");
    let config = init(&dir);
    let before = std::fs::read(dir.join("vallum0.key")).unwrap();

    // A second run, with a different endpoint: the config is kept (no --force)
    // and the key must be byte-identical, or every client is invalidated.
    let (ok, _, stderr) = run(bin()
        .args(["server", "init", "--config"])
        .arg(&config)
        .args(["--endpoint", "198.51.100.9", "--no-host", "--no-service"]));
    assert!(ok, "{stderr}");
    assert_eq!(before, std::fs::read(dir.join("vallum0.key")).unwrap());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_client_generated_key_produces_a_client_config_the_daemon_accepts() {
    let dir = scratch("public-key");
    let config = init(&dir);
    let public_line = keygen(&dir, "laptop");
    assert!(public_line.starts_with("vallum1:0003:"));

    let client = dir.join("laptop.toml");
    let (ok, stdout, stderr) = run(bin()
        .args(["peer", "add", "laptop", "--config"])
        .arg(&config)
        .args(["--public-key", &public_line, "--endpoint", "203.0.113.5"])
        .arg("--client-config-out")
        .arg(&client));
    assert!(ok, "{stdout}{stderr}");
    assert!(client.exists());
    assert_eq!(mode(&client), 0o600);

    let parsed = vallum_config::Config::load(&client).unwrap();
    assert_eq!(parsed.interface.private_key, PathBuf::from("laptop.key"));
    assert_eq!(parsed.interface.addresses, vec!["10.7.0.2/32".to_owned()]);
    let peer = &parsed.peers[0];
    assert_eq!(peer.endpoint.as_deref(), Some("203.0.113.5:51820"));
    // The peer was given a v4 tunnel address, so the tunnel carries v4 and the
    // client claims only the v4 default route. Claiming `::/0` on a tunnel with
    // no IPv6 does not create a v6 route — it makes v6 traffic fall through to
    // the real default route and escape outside the tunnel.
    assert_eq!(peer.allowed_ips, vec!["0.0.0.0/0".to_owned()]);

    // The server never saw a private key: only the peer entry exists.
    let server = vallum_config::Config::load(&config).unwrap();
    assert_eq!(server.peers.len(), 1);
    assert!(!dir.join("clients").exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_server_generated_bundle_round_trips_through_import() {
    let dir = scratch("bundle");
    let config = init(&dir);
    let bundle = dir.join("phone.vallum-bundle");

    let (ok, stdout, stderr) = run(bin()
        .args(["peer", "add", "phone", "--config"])
        .arg(&config)
        .args([
            "--endpoint",
            "203.0.113.5",
            "--forget-key",
            "--ship-key",
            "--bundle-out",
        ])
        .arg(&bundle));
    assert!(ok, "{stdout}{stderr}");
    assert!(bundle.exists());
    assert_eq!(mode(&bundle), 0o600, "a bundle contains a private key");

    // Without --ship-key the server refuses to mint a client key at all.
    let (ok, _, stderr) = run(bin()
        .args(["peer", "add", "tablet", "--config"])
        .arg(&config)
        .args(["--endpoint", "203.0.113.5"]));
    assert!(!ok, "peer add generated a key without being asked");
    assert!(stderr.contains("--ship-key"), "{stderr}");

    let imported = dir.join("imported");
    let (ok, stdout, stderr) = run(bin()
        .arg("import-bundle")
        .arg(&bundle)
        .args(["--output-dir"])
        .arg(&imported));
    assert!(ok, "{stdout}{stderr}");

    let client_config = imported.join("phone.toml");
    let client_key = imported.join("phone.key");
    assert!(client_config.exists());
    assert!(client_key.exists());
    assert_eq!(mode(&client_key), 0o600);
    vallum_config::Config::load(&client_config).unwrap();

    // --forget-key means the server keeps no copy of the client's private key.
    assert!(!dir.join("clients/phone.key").exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_duplicate_name_and_an_overlapping_prefix_are_refused() {
    let dir = scratch("refusals");
    let config = init(&dir);
    let laptop = keygen(&dir, "laptop");
    let phone = keygen(&dir, "phone");

    let add = |name: &str, line: &str, extra: &[&str]| {
        let mut command = bin();
        command
            .args(["peer", "add", name, "--config"])
            .arg(&config)
            .args(["--public-key", line, "--no-apply"]);
        command.args(extra);
        run(&mut command)
    };

    let (ok, _, stderr) = add("laptop", &laptop, &[]);
    assert!(ok, "{stderr}");

    // Same name: refused, not duplicated.
    let (ok, _, stderr) = add("laptop", &phone, &[]);
    assert!(!ok);
    assert!(stderr.contains("already exists"), "{stderr}");

    // Same address: refused, because two peers cannot claim one prefix.
    let (ok, _, stderr) = add("phone", &phone, &["--address", "10.7.0.2/32"]);
    assert!(!ok);
    assert!(stderr.contains("overlaps"), "{stderr}");

    // A different address is accepted, and allocated in order.
    let (ok, stdout, stderr) = add("phone", &phone, &[]);
    assert!(ok, "{stdout}{stderr}");
    assert!(stdout.contains("10.7.0.3/32"), "{stdout}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn peer_remove_takes_the_peer_out_and_leaves_the_rest() {
    let dir = scratch("remove");
    let config = init(&dir);
    let laptop = keygen(&dir, "laptop");
    let phone = keygen(&dir, "phone");

    for (name, line) in [("laptop", &laptop), ("phone", &phone)] {
        let (ok, _, stderr) = run(bin()
            .args(["peer", "add", name, "--config"])
            .arg(&config)
            .args(["--public-key", line, "--no-apply"]));
        assert!(ok, "{stderr}");
    }

    let (ok, _, stderr) = run(bin()
        .args(["peer", "remove", "laptop", "--config"])
        .arg(&config)
        .arg("--no-apply"));
    assert!(ok, "{stderr}");

    let parsed = vallum_config::Config::load(&config).unwrap();
    let names: Vec<&str> = parsed.peers.iter().map(|peer| peer.name.as_str()).collect();
    assert_eq!(names, vec!["phone"]);

    // Removing what is not there is an error, so a script notices.
    let (ok, _, _) = run(bin()
        .args(["peer", "remove", "laptop", "--config"])
        .arg(&config)
        .arg("--no-apply"));
    assert!(!ok);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_missing_config_is_a_precondition_not_a_failure() {
    let dir = scratch("missing");
    let missing = dir.join("vallum0.toml");
    let output = bin()
        .args(["peer", "list", "--config"])
        .arg(&missing)
        .output()
        .unwrap();
    // Exit 2: nothing was attempted, so a retry after fixing the environment is
    // safe. A failure (1) would mean something was tried and did not work.
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("server init"), "{stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pinning_requires_an_endpoint_and_is_written_to_the_peer() {
    let dir = scratch("pin");
    let config = init(&dir);
    let phone = keygen(&dir, "phone");

    // A pin with no address has nothing to pin to.
    let (ok, _, stderr) = run(bin()
        .args(["peer", "add", "phone", "--config"])
        .arg(&config)
        .args(["--public-key", &phone, "--pin-endpoint", "--no-apply"]));
    assert!(!ok);
    assert!(
        stderr.contains("--pin-endpoint needs --endpoint"),
        "{stderr}"
    );

    let (ok, _, stderr) = run(bin()
        .args(["peer", "add", "phone", "--config"])
        .arg(&config)
        .args([
            "--public-key",
            &phone,
            "--endpoint",
            "203.0.113.5",
            "--pin-endpoint",
            "--no-apply",
        ]));
    assert!(ok, "{stderr}");

    let parsed = vallum_config::Config::load(&config).unwrap();
    assert!(parsed.peers[0].pin_endpoint);
    assert_eq!(
        parsed.peers[0].endpoint.as_deref(),
        Some("203.0.113.5:51820")
    );

    // The pair is validated at load: a pinned peer with the endpoint removed is
    // refused rather than silently roaming.
    let text = std::fs::read_to_string(&config).unwrap();
    let text = text
        .lines()
        .filter(|line| !line.starts_with("endpoint = "))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&config, text).unwrap();
    let (ok, stdout, stderr) = run(bin().args(["doctor", "--config"]).arg(&config));
    assert!(!ok);
    let report = format!("{stdout}{stderr}");
    assert!(
        report.contains("pin_endpoint needs an endpoint"),
        "{report}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn enroll_hands_back_a_config_and_is_idempotent() {
    let dir = scratch("enroll");
    let config = init(&dir);
    let public_line = keygen(&dir, "laptop");
    let line_file = dir.join("laptop.pub");
    std::fs::write(&line_file, &public_line).unwrap();

    let (ok, stdout, stderr) = run(bin()
        .args(["peer", "enroll", "laptop", "--config"])
        .arg(&config)
        .arg("--public-key-file")
        .arg(&line_file)
        .args(["--json", "--no-apply"]));
    assert!(ok, "{stderr}");
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let address = report["address"].as_str().unwrap().to_owned();
    let client_config = report["config"].as_str().unwrap();
    // The device gets its address, the server's line, and nothing secret.
    assert!(client_config.contains(&address), "{client_config}");
    assert!(client_config.contains("public_key = \"vallum1:0003:"));
    assert!(
        !client_config.contains("seed"),
        "a secret leaked into the config"
    );

    // The same line again: same answer, no second peer, no new address.
    let (ok, stdout, stderr) = run(bin()
        .args(["peer", "enroll", "laptop", "--config"])
        .arg(&config)
        .arg("--public-key-file")
        .arg(&line_file)
        .args(["--json", "--no-apply"]));
    assert!(ok, "{stderr}");
    let again: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(again["address"].as_str().unwrap(), address);
    let parsed = vallum_config::Config::load(&config).unwrap();
    assert_eq!(parsed.peers.len(), 1, "a retry added a second peer");

    // A different key for the same name is refused, and says how to rotate.
    let other = keygen(&dir, "other");
    let other_file = dir.join("other.pub");
    std::fs::write(&other_file, &other).unwrap();
    let (ok, _, stderr) = run(bin()
        .args(["peer", "enroll", "laptop", "--config"])
        .arg(&config)
        .arg("--public-key-file")
        .arg(&other_file)
        .args(["--no-apply"]));
    assert!(!ok, "a different key replaced an existing enrolment");
    assert!(stderr.contains("peer rotate"), "{stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[allow(clippy::zombie_processes)] // the KillOnDrop guard reaps it
fn a_token_enrolment_round_trips_and_refuses_a_second_key() {
    let dir = scratch("join");
    let config = init(&dir);
    // A port of our own: a stale responder from a previous run would answer
    // (or rather, refuse) on a shared one and look like a product failure.
    let port = 55000 + (std::process::id() % 1000) as u16;
    let mut text = std::fs::read_to_string(&config).unwrap();
    // The ticket advertises the public endpoint, so this loopback test has to
    // claim one that is actually routable: itself.
    text = text.replace("203.0.113.5:", "127.0.0.1:");
    text.push_str(&format!("\n[enroll]\nenabled = true\nport = {port}\n"));
    std::fs::write(&config, text).unwrap();
    let rundir = dir.join("run");

    let (ok, stdout, stderr) = run(bin()
        .args(["peer", "invite", "phone", "--config"])
        .arg(&config)
        .arg("--json")
        .env("VALLUM_RUN_DIR", &rundir));
    assert!(ok, "{stderr}");
    let invite: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let token = invite["token"].as_str().unwrap().to_owned();
    let id = invite["id"].as_str().unwrap().to_owned();
    let fingerprint = invite["fingerprint"].as_str().unwrap().to_owned();
    let ticket = invite["ticket"]
        .as_str()
        .expect("the invite carries a join ticket")
        .to_owned();
    assert!(
        ticket.starts_with("vallum1-join:127.0.0.1:"),
        "the ticket names the responder, not the listen port: {ticket}"
    );
    assert!(ticket.ends_with(&fingerprint), "{ticket}");

    let serve = bin()
        .arg("enroll-serve")
        .arg("--config")
        .arg(&config)
        .env("VALLUM_RUN_DIR", &rundir)
        .env("VALLUM_BIN", env!("CARGO_BIN_EXE_vallum"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    // The responder must die with the test, pass or fail.
    struct KillOnDrop(std::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut serve = KillOnDrop(serve);
    std::thread::sleep(std::time::Duration::from_millis(400));
    if let Ok(Some(status)) = serve.0.try_wait() {
        panic!("the responder exited immediately: {status}");
    }

    let client = dir.join("client");
    std::fs::create_dir_all(&client).unwrap();
    // The one-argument form an operator actually uses: the ticket carries
    // responder, invite id, token, and fingerprint in a single string.
    let join_ticket = |ticket: &str| run(bin().args(["join", ticket]).current_dir(&client));
    // The flag form `peer invite` printed before tickets — still supported.
    let join_flags = |id: &str, token: &str, expect: Option<&str>| {
        let mut command = bin();
        command
            .args([
                "setup",
                "--join",
                &format!("127.0.0.1:{port}"),
                "--name",
                "phone",
                "--invite-id",
                id,
                "--token",
                token,
            ])
            .current_dir(&client);
        if let Some(expect) = expect {
            command.args(["--expect", expect]);
        }
        run(&mut command)
    };

    let (ok, stdout, stderr) = join_ticket(&ticket);
    assert!(ok, "stdout {stdout}\nstderr {stderr}");
    assert!(
        stdout.contains(&format!("server fingerprint {fingerprint}")),
        "{stdout}"
    );
    let placed = client.join("phone.toml");
    assert!(placed.exists(), "the client config was not written");
    let parsed = vallum_config::Config::load(&placed).unwrap();
    assert_eq!(
        parsed.peers.len(),
        1,
        "the client config has its server peer"
    );
    // The peer the server recorded is the key the client generated.
    let server_config = vallum_config::Config::load(&config).unwrap();
    assert_eq!(server_config.peers.len(), 1);
    let (ok, client_line, stderr) = run(bin()
        .args(["pubkey", "--private-key"])
        .arg(client.join("phone.key")));
    assert!(ok, "{stderr}");
    assert_eq!(
        server_config.peers[0].public_key.as_deref(),
        Some(client_line.trim()),
        "the server recorded a different key than the client generated"
    );

    // The same token with a different key is refused, and says so.
    let (ok, _, stderr) = join_flags(&id, &token, None);
    assert!(!ok, "a second key enrolled under a spent token");
    assert!(stderr.contains("different key"), "{stderr}");

    // A wrong token gets silence, then a clear timeout.
    let (ok, _, stderr) = join_flags(&id, "aaaa-bbbb-cccc-dddd-eeee-ffff-0000-1111", None);
    assert!(!ok);
    assert!(stderr.contains("no answer"), "{stderr}");

    // A ticket whose fingerprint was forged refuses before writing — but a
    // probe like this still spends the invite, so it needs its own.
    let (ok, stdout, stderr) = run(bin()
        .args(["peer", "invite", "burner", "--config"])
        .arg(&config)
        .arg("--json")
        .env("VALLUM_RUN_DIR", &rundir));
    assert!(ok, "{stderr}");
    let probe: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let probe_ticket = probe["ticket"].as_str().unwrap();
    let forged = format!(
        "{}ffffee001122",
        probe_ticket.trim_end_matches(|c: char| c.is_ascii_hexdigit())
    );
    let (ok, _, stderr) = join_ticket(&forged);
    assert!(!ok, "a ticket with a forged fingerprint enrolled");
    assert!(
        stderr.contains("not the server the invite named"),
        "{stderr}"
    );
    // And the client wrote nothing for it.
    assert!(
        !client.join("burner.toml").exists(),
        "a refused join wrote a config"
    );

    drop(serve);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_pinned_invite_only_enrols_the_key_it_named() {
    let dir = scratch("pinned");
    let config = init(&dir);
    let port = 56000 + (std::process::id() % 1000) as u16;
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(&format!("\n[enroll]\nenabled = true\nport = {port}\n"));
    std::fs::write(&config, text).unwrap();
    let rundir = dir.join("run");

    // The device generates its key here, and the operator pins it.
    let pinned_line = keygen(&dir, "phone");
    let pinned_file = dir.join("phone.pub");
    std::fs::write(&pinned_file, &pinned_line).unwrap();
    let (ok, stdout, stderr) = run(bin()
        .args(["peer", "invite", "phone", "--config"])
        .arg(&config)
        .arg("--public-key-file")
        .arg(&pinned_file)
        .arg("--json")
        .env("VALLUM_RUN_DIR", &rundir));
    assert!(ok, "{stderr}");
    let invite: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let id = invite["id"].as_str().unwrap().to_owned();
    let token = invite["token"].as_str().unwrap().to_owned();

    let serve = bin()
        .arg("enroll-serve")
        .arg("--config")
        .arg(&config)
        .env("VALLUM_RUN_DIR", &rundir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    struct KillOnDrop(std::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let serve = KillOnDrop(serve);
    std::thread::sleep(std::time::Duration::from_millis(400));

    // A different key — what an attacker holding only the token would have.
    let client = dir.join("client");
    std::fs::create_dir_all(&client).unwrap();
    let (ok, _, stderr) = run(bin()
        .args([
            "setup",
            "--join",
            &format!("127.0.0.1:{port}"),
            "--name",
            "phone",
            "--invite-id",
            &id,
            "--token",
            &token,
        ])
        .current_dir(&client));
    assert!(!ok, "a pinned invite enrolled a different key");
    assert!(stderr.contains("bound to a different key"), "{stderr}");
    assert!(!client.join("phone.toml").exists());

    drop(serve);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn peer_invites_lists_live_invites_without_leaking_tokens_and_prunes_expired_ones() {
    let dir = scratch("invites");
    let config = init(&dir);
    let rundir = dir.join("run");

    let (ok, stdout, stderr) = run(bin()
        .args(["peer", "invite", "laptop", "--config"])
        .arg(&config)
        .arg("--json")
        .env("VALLUM_RUN_DIR", &rundir));
    assert!(ok, "{stderr}");
    let created: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let secret_token = created["token"].as_str().unwrap();

    // Write an already-expired invite into the same directory to verify pruning.
    let expired_path = rundir.join("enroll-vallum0-00000000000000000000000000000000.json");
    std::fs::write(
        &expired_path,
        "{\"version\":2,\"id\":\"00000000000000000000000000000000\",\"name\":\"stale\",\"token_hex\":\"00000000000000000000000000000000\",\"expires\":1}",
    )
    .unwrap();

    let (ok, stdout, stderr) = run(bin()
        .args(["peer", "invites", "--config"])
        .arg(&config)
        .arg("--json")
        .env("VALLUM_RUN_DIR", &rundir));
    assert!(ok, "{stderr}");
    assert!(
        !stdout.contains(secret_token),
        "peer invites must never print the secret token: {stdout}"
    );
    assert!(
        !expired_path.exists(),
        "expired invite file was not pruned by peer invites"
    );
    let listed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = listed.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"].as_str(), Some("laptop"));
    assert_eq!(arr[0]["spent"].as_bool(), Some(false));

    let _ = std::fs::remove_dir_all(&dir);
}
