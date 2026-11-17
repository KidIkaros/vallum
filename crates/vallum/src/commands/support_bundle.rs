// SPDX-License-Identifier: Apache-2.0

//! `vallum support-bundle`: collect what a support conversation would ask for.
//!
//! The gap this closes is not "we have no diagnostics". `vallum status --json`
//! and `vallum doctor --json` already answer almost everything, and
//! `vallum metrics` exposes the counters. The gap is that a user on a broken
//! tunnel has to know which five commands to run, in which order, and then
//! paste six outputs into a chat window. In practice they paste one, and the
//! conversation starts by asking for the others.
//!
//! So this is a *collector*, deliberately dumb: it runs those commands, writes
//! the results side by side, and says what it chose to leave out. It makes no
//! judgement about the failure — a bundle that guessed would be wrong in the
//! same way the tunnel is.
//!
//! # What must not be in here
//!
//! A support bundle is the most likely place for a private key to escape: it is
//! built to be sent to someone else. So the rule is structural, not careful:
//!
//! * Key *files* are never read. The config names them by path
//!   (`private_key = "laptop.key"`), and the path is what goes in the bundle.
//! * `preshared_key = "…"` is the one secret that can sit inline in a config, so
//!   [`redact_config`] rewrites it. It is redacted by *key name*, not by pattern
//!   — a clever regex over quoted strings eventually misses one.
//! * Every command whose output is collected is one of `status`/`doctor`/`show`/
//!   `metrics`, none of which prints key material (`show --json` carries the
//!   public line and a fingerprint).
//!
//! The bundle states all of that in its own `README.txt`, so the person
//! receiving it can see what was withheld rather than having to trust it.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Args;

use vallum_config::redact_secrets;

use crate::{say, Error};

#[derive(Debug, Args)]
pub struct SupportBundleArgs {
    /// The configuration file to report on.
    ///
    /// Defaults to the installer's path, which is the one a user who was
    /// following the docs will have. A path that does not exist still produces a
    /// bundle: "there is no configuration here" is the answer to a real
    /// question, and it is the usual answer on a host where setup never ran.
    #[arg(long, short, value_name = "FILE", default_value = crate::host::paths::DEFAULT_CONFIG)]
    pub config: PathBuf,

    /// Where to write the bundle. A directory; the archive lands beside it.
    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,

    /// How many lines of the unit's journal to include.
    ///
    /// 500 is about an hour of a quiet daemon and a few minutes of a noisy one.
    /// The journal is the only part of a bundle that can contain anything — a
    /// pasted config, a public endpoint — so more is not better here.
    #[arg(long, value_name = "N", default_value_t = 500)]
    pub journal_lines: usize,

    /// Leave the journal out.
    ///
    /// For a user who would rather not send log text at all: everything else is
    /// still enough to tell a platform fault from a config fault.
    #[arg(long)]
    pub no_journal: bool,
}

/// `vallum support-bundle`.
///
/// # Errors
///
/// If the output directory cannot be created or written. A *command* that fails
/// is not an error: its failure is recorded in the bundle, because a `doctor`
/// that returned 3 is a finding, not a reason to produce nothing.
pub fn support_bundle(args: &SupportBundleArgs) -> Result<(), Error> {
    let stamp = utc_stamp();
    let host = hostname();
    let dir = match &args.out {
        Some(path) => path.clone(),
        None => PathBuf::from(format!("vallum-support-{host}-{stamp}")),
    };
    if dir.exists() {
        return Err(Error::Usage(format!(
            "`{}` already exists; pick another --out or remove it",
            dir.display()
        )));
    }
    fs::create_dir_all(&dir).map_err(|source| Error::IoPath {
        action: "create the bundle directory",
        path: dir.clone(),
        source,
    })?;

    let exe = std::env::current_exe().map_err(Error::Io)?;
    let config = args.config.display().to_string();

    // Each entry: the file name, and how it is produced. `collect` never aborts
    // the bundle — it writes the command's own failure to the same file, so the
    // reader sees "doctor exited 3" where the check output would have been
    // instead of an empty file that looks like a clean run.
    let mut written: Vec<(&str, String)> = Vec::new();

    for (name, argv) in [
        ("status.json", vec!["status", "--config", &config, "--json"]),
        ("doctor.json", vec!["doctor", "--config", &config, "--json"]),
        ("show.json", vec!["show", "--config", &config, "--json"]),
        ("metrics.txt", vec!["metrics", "--config", &config]),
    ] {
        let (body, code) = run_capture(&exe, &argv);
        let body = if code == 0 {
            body
        } else {
            format!(
                "# `vallum {}` exited {code}\n# the output below is what it printed\n\n{body}",
                argv[0]
            )
        };
        // Every collected file goes through the same redaction as the config.
        // Not because these commands are expected to print a secret — they are
        // not — but because a *failure* message quotes whatever it choked on:
        // a `toml` parse error on a misplaced `preshared_key` printed the key
        // itself, and that is exactly the text a support bundle exists to carry.
        let body = redact_secrets(&body);
        write(&dir, name, &body)?;
        written.push((name, body));
    }

    let config_body = read_redacted_config(&args.config);
    write(&dir, "config.toml", &config_body)?;
    written.push(("config.toml", config_body));

    let facts = host_facts();
    write(&dir, "host.txt", &facts)?;
    written.push(("host.txt", facts));

    if args.no_journal {
        let note = "# the journal was left out on request (--no-journal)\n";
        write(&dir, "journal.txt", note)?;
        written.push(("journal.txt", note.to_owned()));
    } else {
        let journal = journal_tail(&config, args.journal_lines);
        write(&dir, "journal.txt", &journal)?;
        written.push(("journal.txt", journal));
    }

    let readme = readme_text(&dir, &args.config, args.no_journal);
    write(&dir, "README.txt", &readme)?;

    say!();
    say!("   collected:");
    for (name, body) in &written {
        say!("     {:<14} {:>7} bytes", name, body.len());
    }
    say!();
    say!("   no private keys, no preshared keys, no config secrets.");
    say!(
        "   the config is included with `preshared_key` redacted; key files are named, never read."
    );

    let archive = archive(&dir);
    say!();
    match archive {
        Ok(path) => {
            say!("   wrote {}", path.display());
            say!("   send that file; it is the whole bundle.");
        }
        Err(reason) => {
            say!("   no archive: {reason}");
            say!(
                "   the directory {} is complete; send it as-is.",
                dir.display()
            );
        }
    }
    say!();
    say!("   read README.txt in the bundle before sending it: it lists what is in here.");
    Ok(())
}

/// Run one of this binary's own subcommands and capture stdout and stderr.
///
/// `current_exe` rather than the internal function, on purpose: the bundle must
/// contain exactly what the user would have seen if they had typed the command,
/// including a failure. Calling the internal path could drift from the CLI
/// surface without anyone noticing.
fn run_capture(exe: &Path, argv: &[&str]) -> (String, i32) {
    match Command::new(exe).args(argv).output() {
        Ok(output) => {
            let mut body = String::from_utf8_lossy(&output.stdout).into_owned();
            let err = String::from_utf8_lossy(&output.stderr);
            if !err.trim().is_empty() {
                body.push_str("\n# stderr\n");
                body.push_str(&err);
            }
            (body, output.status.code().unwrap_or(-1))
        }
        Err(error) => (
            format!("# could not run `{}`: {error}\n", argv.join(" ")),
            -1,
        ),
    }
}

/// The config, redacted, or a note that says *why* it is not here.
///
/// The three cases are different diagnoses and get different sentences:
/// **not found** means setup never ran (or used another path), **permission
/// denied** means the command is not running as root and the reader should
/// re-run it with `sudo`, and anything else is reported verbatim. One message
/// for all three would send a user to the wrong fix — which is what this
/// function did before it was allowed to read the error kind.
fn read_redacted_config(path: &Path) -> String {
    match fs::read_to_string(path) {
        Ok(text) => redact_secrets(&text),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => format!(
            "# could not read {}: {error}\n\
             # the config is readable only by the operator's account. Re-run this\n\
             # command as root (`sudo vallum support-bundle`) to include it — the\n\
             # rest of this bundle is still valid without it.\n",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => format!(
            "# {} does not exist: {error}\n\
             # this host has no configuration at that path — `vallum setup` has not\n\
             # been run here, or it wrote somewhere else (`--config` to point at it).\n",
            path.display()
        ),
        Err(error) => format!(
            "# could not read {}: {error}\n\
             # the rest of this bundle does not depend on it.\n",
            path.display()
        ),
    }
}

/// Platform facts that decide whether a tunnel *can* work, independent of config.
fn host_facts() -> String {
    let mut out = String::new();
    let _ = writeln!(out, "vallum {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(
        out,
        "target {} / {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let _ = writeln!(out, "collected {}", utc_stamp());
    let _ = writeln!(out, "uname {}", uname());
    for (label, path) in [
        ("os-release", "/etc/os-release"),
        ("kernel", "/proc/version"),
    ] {
        if let Ok(text) = fs::read_to_string(path) {
            for line in text.lines().take(12) {
                let _ = writeln!(out, "{label}: {line}");
            }
        }
    }
    for entry in ["/run/systemd/system", "/.dockerenv"] {
        let _ = writeln!(
            out,
            "{entry} {}",
            if Path::new(entry).exists() {
                "present"
            } else {
                "absent"
            }
        );
    }
    let _ = writeln!(
        out,
        "mtu probed by `vallum doctor --probe-mtu` when requested"
    );
    out
}

fn uname() -> String {
    match Command::new("uname").arg("-srm").output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        _ => "unavailable".to_owned(),
    }
}

/// The tail of the unit's journal, or the reason there is none.
///
/// The unit name is derived the same way the installer derives it (`vallum@<stem>`
/// where the stem is the config file without `.toml`), so this finds the journal
/// on a host where the operator renamed nothing — and says so plainly when it
/// does not, rather than returning an empty file.
fn journal_tail(config: &str, lines: usize) -> String {
    let stem = Path::new(config).file_stem().map_or_else(
        || "vallum".to_owned(),
        |stem| stem.to_string_lossy().into_owned(),
    );
    let unit = format!("vallum@{stem}");
    let argv = [
        "-u",
        &unit,
        "-n",
        &lines.to_string(),
        "--no-pager",
        "--output=short-iso",
    ];
    match Command::new("journalctl").args(argv).output() {
        Ok(output) => {
            let body = String::from_utf8_lossy(&output.stdout).into_owned();
            if body.trim().is_empty() {
                format!(
                    "# `journalctl -u {unit}` printed nothing.\n\
                     # Either the unit is not installed under that name, or its journal\n\
                     # is empty. `systemctl list-units 'vallum*'` shows what does exist.\n"
                )
            } else {
                body
            }
        }
        Err(error) => format!(
            "# `journalctl` is not available: {error}\n\
             # the rest of this bundle does not depend on it.\n"
        ),
    }
}

/// Say what is in the bundle, and — the part that matters — what is not.
fn readme_text(dir: &Path, config: &Path, no_journal: bool) -> String {
    format!(
        "Vallum support bundle\n\
         =====================\n\n\
         Collected {} into {}.\n\n\
         What is in here\n\
         ---------------\n\
         status.json   `vallum status --config {} --json` — the client verdict:\n\
         \x20             in-tunnel / blocked / leaking, and why.\n\
         doctor.json   `vallum doctor --config {} --json` — platform, config,\n\
         \x20             control socket, helper tools, and the resolved MTU.\n\
         show.json     `vallum show --config {} --json` — device and peer state\n\
         \x20             as the daemon reports it.\n\
         metrics.txt   the Prometheus exposition, so counters can be compared\n\
         \x20             with what the server sees.\n\
         config.toml   the configuration file, with `preshared_key` redacted.\n\
         host.txt      kernel, distribution, container detection, version.\n\
         journal.txt   the last lines of {} — {}.\n\n\
         What is NOT in here\n\
         -------------------\n\
         * Private keys. `private_key = \"…\"` in a config is a *path*; the path\n\
         \x20 is included, the key file is never opened.\n\
         * Preshared keys. Redacted in config.toml as `preshared_key = \"<redacted>\"`.\n\
         * Enrolment tickets, account tokens, and join URIs.\n\
         * Traffic content. Nothing on this host records it.\n\n\
         If a command failed, its output file starts with a `#` line saying so\n\
         and how it exited — a failed check is a finding, not a missing file.\n\n\
         Send the archive file (`vallum-support-*.tar.gz`) beside this directory.\n",
        utc_stamp(),
        dir.display(),
        config.display(),
        config.display(),
        config.display(),
        unit_name(config),
        if no_journal {
            "left out on request (--no-journal)".to_owned()
        } else {
            "the daemon's own log".to_owned()
        },
    )
}

fn unit_name(config: &Path) -> String {
    let stem = config.file_stem().map_or_else(
        || "vallum".to_owned(),
        |stem| stem.to_string_lossy().into_owned(),
    );
    format!("vallum@{stem} from the journal")
}

fn write(dir: &Path, name: &str, body: &str) -> Result<(), Error> {
    let path = dir.join(name);
    fs::write(&path, body).map_err(|source| Error::IoPath {
        action: "write a bundle file",
        path,
        source,
    })
}

/// One file to send. `tar` is the OS's, not ours: adding an archiver dependency
/// to the daemon binary for this would be a poor trade, and every host that can
/// run this command has `tar`.
///
/// The error carries a *reason* rather than being a bare failure: "tar is not
/// installed" and "tar ran and failed" are different problems, and only one of
/// them is fixed by sending the directory instead.
fn archive(dir: &Path) -> Result<PathBuf, String> {
    let name = dir
        .file_name()
        .map_or_else(|| "bundle".to_owned(), |n| n.to_string_lossy().into_owned());
    let target = dir.with_file_name(format!("{name}.tar.gz"));
    // `dir` is usually relative, and `Path::parent` of `foo` is the empty path,
    // which `tar -C` reads as an empty filename. `.` is the same directory.
    let parent = match dir.parent() {
        Some(path) if !path.as_os_str().is_empty() => path.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let output = Command::new("tar")
        .arg("-czf")
        .arg(&target)
        .arg("-C")
        .arg(&parent)
        .arg(&name)
        .output();
    match output {
        Ok(output) if output.status.success() => Ok(target),
        Ok(output) => Err(format!(
            "tar exited {}: {}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        )),
        Err(error) => Err(format!("`tar` could not be run: {error}")),
    }
}

fn utc_stamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    // Manual conversion: the crate has no date library, and a bundle filename
    // only needs to sort. Days since the epoch → y/m/d.
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's `civil_from_days`, the standard days-to-date conversion.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|name| name.trim().replace('.', "-"))
        .unwrap_or_else(|_| "host".to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::civil_from_days;
    use vallum_config::redact_secrets as redact_config;

    #[test]
    fn a_preshared_key_is_the_only_thing_redacted() {
        // The one secret that can sit inline in a config file. Everything else —
        // the private key *path*, the public keys, the endpoints — is what makes
        // the bundle useful, so over-redacting is its own failure.
        let text = "[interface]\n\
                    name = \"server\"\n\
                    private_key = \"server.key\"\n\
                    address = \"10.99.90.1/24\"\n\
                    \n\
                    [[peer]]\n\
                    name = \"laptop\"\n\
                    public_key = \"abc123\"\n\
                    preshared_key = \"0011223344556677889900112233445566778899001122334455667788990011\"\n";
        let redacted = redact_config(text);
        assert!(redacted.contains("preshared_key = \"<redacted>\""));
        assert!(!redacted.contains("0011223344556677"));
        assert!(redacted.contains("private_key = \"server.key\""));
        assert!(redacted.contains("public_key = \"abc123\""));
        assert!(redacted.contains("address = \"10.99.90.1/24\""));
    }

    #[test]
    fn indentation_and_comments_around_a_secret_survive() {
        let text = "  preshared_key = \"deadbeef\"\n# a comment\n";
        let redacted = redact_config(text);
        assert_eq!(redacted, "  preshared_key = \"<redacted>\"\n# a comment\n");
    }

    #[test]
    fn a_config_without_secrets_is_copied_byte_for_byte() {
        let text = "[interface]\nname = \"laptop\"\nprivate_key = \"laptop.key\"\n";
        assert_eq!(redact_config(text), text);
    }

    #[test]
    fn the_bundle_stamp_is_a_sortable_utc_date() {
        // 2026-11-18T00:00:00Z, and the day before, so an off-by-one in the
        // conversion cannot pass by landing on the right date once.
        assert_eq!(civil_from_days(20_775), (2026, 11, 18));
        assert_eq!(civil_from_days(20_774), (2026, 11, 17));
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }
}
