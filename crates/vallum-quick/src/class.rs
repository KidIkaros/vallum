// SPDX-License-Identifier: Apache-2.0

//! Per-app classification (ADR-0023): one `socket cgroupv2` rule, one mark,
//! and a launch verb — the entire v1 surface.
//!
//! The design is `docs/per-app-split-tunnelling-PLAN.md`, and every mechanism
//! here was measured before it was written: the probe
//! (`docs/proof/socket-cgroupv2.md`) established the rule form — `level N`
//! with the class's cgroup-relative path, which must exist before any rule
//! names it — and the gate phase in `scripts/e2e-netns.sh` keeps the
//! member-only counting assertion alive on every e2e run.
//!
//! The pieces, in the order they execute:
//!
//! - **resolve** [`resolve_class`]: the tier probe. Tier 1, `/sys/fs/cgroup`
//!   writable (the root case); tier 2, the first delegated
//!   `user@<uid>.service` subtree (the laptop case). Neither → the caller
//!   names it and moves on; a machine that cannot carry the class must not
//!   silently lose it.
//! - **install** [`attach_class`]: the class directory is created once and
//!   never removed, the record is written *before* the `nft -f` runs (the
//!   same write-then-run pattern routes use), and both families get the rule:
//!
//!   ```text
//!   add rule ip  vallumapps cls socket cgroupv2 level N "<rel>" meta mark set 5140
//!   add rule ip6 vallum6app cls socket cgroupv2 level N "<rel>" meta mark set 5140
//!   ```
//!
//!   **No new `ip rule`.** The policy table's lookup rule is
//!   `not fwmark <interface mark>`, so a packet marked [`CLASS_MARK`] —
//!   different from the daemon's own mark by construction — matches `not`,
//!   lands in the same policy table, and inherits fail-closed routing whole:
//!   when the watchdog blackholes the policy table, class-marked packets
//!   blackhole with it. That is the economy ADR-0023 decided, and v1 adds
//!   no guard code of its own.
//! - **launch** [`app_run`]: the verb moves itself into the leaf, then
//!   spawns the command as a plain child — no shell, no argv re-cooking, no
//!   `unsafe` (the workspace forbids it) — and the child is born inside the
//!   leaf by cgroup inheritance.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use vallum_config::Config;

use crate::routes;

/// The routing mark members carry.
///
/// It only has to differ from `[interface] fwmark`: a collision would
/// classify the daemon's own datagrams into the tunnel they are trying to
/// escape — the exact bug the `not fwmark` rule exists to prevent — so
/// [`check_config`] refuses a config that uses it. 5140 sits outside the
/// 4660/51820/51820-adjacent neighborhood the interface marks and policy
/// tables live in.
pub(crate) const CLASS_MARK: u32 = 5140;

const V4_TABLE: &str = "vallumapps";
const V6_TABLE: &str = "vallum6app";
const CHAIN: &str = "cls";
const CLASS_NAME: &str = "vallum-apps";
const CG_ROOT: &str = "/sys/fs/cgroup";

fn table_name(family: &str) -> Option<&'static str> {
    match family {
        "ip" => Some(V4_TABLE),
        "ip6" => Some(V6_TABLE),
        _ => None,
    }
}

/// Where the class lives, and how `nft` addresses it.
///
/// `rel` is the cgroup-relative path, no leading `/`: `vallum-apps` on tier
/// 1, the full `user.slice/…/user@<uid>.service/vallum-apps` on tier 2. The
/// number of `/`-separated components in `rel` is the rule's `level` — the
/// depth-N form the probe measured as the only one that fires.
#[derive(Debug, Clone)]
pub(crate) struct Class {
    pub(crate) dir: PathBuf,
    pub(crate) rel: String,
}

impl Class {
    /// The rule's `level`: the depth of the cgroup-relative path.
    fn level(&self) -> usize {
        self.rel.split('/').count()
    }
}

/// The tier probe, the same one the gate phase runs.
///
/// The directory is **created once and never removed**: it exists across
/// detach and reboot so a re-attach's rule-add is valid without ceremony;
/// only member leaves come and go.
///
/// An existing directory counts as ours — a previous attach's, or the gate's
/// own scratch class in a shared namespace. The rule-add that names the path
/// is what validates the pairing, every time, on the kernel's behalf.
pub(crate) fn resolve_class() -> Result<Class, String> {
    // Tier 1 first, so a root context never lands on tier 2: the class at
    // the hierarchy root is the more privileged form, and its rel path is a
    // single component.
    let tier1 = Path::new(CG_ROOT).join(CLASS_NAME);
    match fs::create_dir(&tier1) {
        Ok(()) => {
            return Ok(Class {
                dir: tier1,
                rel: CLASS_NAME.to_owned(),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Ok(Class {
                dir: tier1,
                rel: CLASS_NAME.to_owned(),
            })
        }
        // Not writable in this context (mapped credentials, non-root): tier 2.
        Err(_) => {}
    }

    // Tier 2: the first delegated subtree this context may write. The gate's
    // glob is `/sys/fs/cgroup/user.slice/*/user@*.service`; the middle
    // component is `user-<uid>.slice`.
    let user_slice = Path::new(CG_ROOT).join("user.slice");
    let Ok(slices) = fs::read_dir(&user_slice) else {
        return Err(format!(
            "no writable cgroup v2 subtree here: `{CG_ROOT}` is not writable for \
             this context and `{}` does not exist or is not readable",
            user_slice.display()
        ));
    };
    for slice in slices.flatten() {
        if !slice.file_name().to_string_lossy().starts_with("user-") {
            continue;
        }
        let Ok(services) = fs::read_dir(slice.path()) else {
            continue;
        };
        for service in services.flatten() {
            if !service.file_name().to_string_lossy().starts_with("user@") {
                continue;
            }
            let dir = service.path().join(CLASS_NAME);
            let claimed = match fs::create_dir(&dir) {
                Ok(()) => true,
                Err(error) => error.kind() == std::io::ErrorKind::AlreadyExists,
            };
            if claimed {
                let rel = rel_of(&dir);
                return Ok(Class { dir, rel });
            }
        }
    }
    Err(format!(
        "no writable cgroup v2 subtree here: `{CG_ROOT}` and every \
         `user@*.service` session were refused for this context"
    ))
}

/// The cgroup-relative form of a class directory: the `/sys/fs/cgroup` mount
/// prefix off, exactly the string `nft` compares against.
fn rel_of(dir: &Path) -> String {
    dir.strip_prefix(CG_ROOT)
        .map(|rest| rest.to_string_lossy().into_owned())
        .unwrap_or_else(|_| CLASS_NAME.to_owned())
}

/// Whether this config may claim the class, and if not, the reason.
///
/// Full tunnel and `[interface] fwmark` are both required — the same pair
/// `routes::policy_for` needs for the policy machinery the class rides — and
/// the mark must not be [`CLASS_MARK`] itself. Split tunnels are refused
/// outright: ADR-0023 names exactly one class for v1, and riding a
/// prefix-list tunnel's `[quick] table` re-opens the routing questions that
/// decision deferred.
///
/// The check is pure on the config on purpose: `attach` only reaches here
/// after the route machinery has judged the same config against the live
/// interface, so the class adds a refusal, not a re-derivation of prefix
/// coverage — and unit tests can state each refusal without a subprocess.
pub(crate) fn check_config(config: &Config) -> Result<(), String> {
    let full = config.peers.iter().any(|peer| {
        peer.allowed_ips
            .iter()
            .filter_map(|string| string.parse().ok())
            .any(|prefix: routes::Prefix| prefix.as_ipnet().prefix_len() == 0)
    });
    if !full {
        return Err(
            "`app_class = true` rides a full tunnel only (ADR-0023 keeps one class \
             per machine): this config adds no default route (0.0.0.0/0 or ::/0), \
             so there is no class to ride"
                .to_owned(),
        );
    }
    let Some(mark) = config.interface.fwmark.filter(|mark| *mark != 0) else {
        return Err(
            "a full tunnel needs `[interface] fwmark` before it can carry \
             `app_class = true`: the class rides the policy routing, and the \
             mark is what installs it"
                .to_owned(),
        );
    };
    if mark == CLASS_MARK {
        return Err(format!(
            "`app_class` would set routing mark {CLASS_MARK} and this config's \
             `[interface] fwmark` is the same mark — a collision would classify \
             the daemon's own datagrams into the tunnel they are trying to \
             escape; set `[interface] fwmark` to something else"
        ));
    }
    Ok(())
}

/// Which other interface, if any, has claimed the class on this machine.
///
/// Two configs with `app_class = true` attached at once would fight over one
/// mark and one rule; the class is a machine resource, so the second attach
/// is refused with the first interface's name. A free function over the
/// record directory so tests drive it without touching process state.
fn class_holder(state_dir: &Path, interface: &str) -> Option<String> {
    for entry in fs::read_dir(state_dir).ok()? {
        let Ok(entry) = entry else { continue };
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Some(holder) = name.strip_suffix(".quick-class") else {
            continue;
        };
        if holder != interface {
            return Some(holder.to_owned());
        }
    }
    None
}

/// The class record an attach writes, before the `nft -f` that consumes it.
fn record_text(rel: &str) -> String {
    format!("nft ip {V4_TABLE} {rel}\nnft ip6 {V6_TABLE} {rel}\n")
}

/// The state-dir sibling of `routes::state_path`, per the plan's record.
fn class_record_path(interface: &str) -> PathBuf {
    routes::state_dir().join(format!("{interface}.quick-class"))
}

/// Everything installable about the class, in install order.
///
/// Called from `attach_host_side` after routes and DNS succeed, so a partial
/// tunnel never leaves an installed rule pointing at nothing.
pub(crate) fn attach_class(
    config: &Config,
    interface: &str,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Refuse the config first: every refusal in `check_config` must leave
    // nothing behind for teardown to guess about.
    if let Err(reason) = check_config(config) {
        return Err(reason.into());
    }

    let class = match resolve_class() {
        Ok(class) => class,
        // Deliberately not an error: a machine that cannot carry the class
        // installs everything else as today, and the note says so.
        Err(reason) => {
            eprintln!(
                "note   this machine cannot carry the per-app class (ADR-0023): \
                 {reason}; everything else installs as today"
            );
            return Ok(());
        }
    };

    // One interface per machine, judged against the records that survive
    // reboot in the state dir.
    if let Some(holder) = class_holder(&routes::state_dir(), interface) {
        return Err(format!(
            "interface `{holder}` already holds the per-app class — one mark per \
             machine is the ADR-0023 constraint; detach it first"
        )
        .into());
    }

    // Empty strays from crashed launches: the plan's "the next attach sweeps
    // empty leaves under the class dir" is exactly this call.
    sweep_empty_leaves(&class);

    // The class directory exists before any rule names it: nft validates the
    // path at rule-add time, and the probe caught two runs lying to
    // themselves about exactly this ordering.
    fs::create_dir_all(&class.dir)?;

    if dry_run {
        print!("{}", render_file(&class));
        return Ok(());
    }

    // Record first, then run — the write-then-run pattern `apply_routes`
    // uses, for the same reason: a crash between the two costs a stray
    // record and a spurious delete, never a table nothing knows about.
    let record_path = class_record_path(interface);
    fs::write(&record_path, record_text(&class.rel))?;
    if let Err(error) = nft_apply(&render_file(&class)) {
        let _ = fs::remove_file(&record_path);
        return Err(error);
    }
    Ok(())
}

/// The `nft -f` payload: one file, both families, one rule each.
///
/// Slashes are unnameable in the argv grammar (the probe: `unexpected /`), so
/// the class rules speak only through a file.
fn render_file(class: &Class) -> String {
    let level = class.level();
    format!(
        "add table ip {V4_TABLE}\n\
         add chain ip {V4_TABLE} {CHAIN} {{ type route hook output priority filter ; }}\n\
         add rule ip {V4_TABLE} {CHAIN} socket cgroupv2 level {level} \"{}\" meta mark set {CLASS_MARK}\n\
         add table ip6 {V6_TABLE}\n\
         add chain ip6 {V6_TABLE} {CHAIN} {{ type route hook output priority filter ; }}\n\
         add rule ip6 {V6_TABLE} {CHAIN} socket cgroupv2 level {level} \"{}\" meta mark set {CLASS_MARK}\n",
        class.rel, class.rel,
    )
}

fn nft_apply(payload: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!("vallum-class-{}.nft", std::process::id()));
    fs::File::create(&path)?.write_all(payload.as_bytes())?;
    let status = Command::new("nft").arg("-f").arg(&path).status();
    let _ = fs::remove_file(&path);
    let status = status.map_err(|error| format!("`nft -f` could not run: {error}"))?;
    if !status.success() {
        // The class directory exists and is named by this payload, so a
        // refusal here is the kernel's judgment on the rule itself, not the
        // missing-path failure the probe caught.
        return Err(format!(
            "`nft -f` refused the class rule (exit status: {status}); the payload \
             names `{CLASS_NAME}` and the directory exists, so this is a rule \
             rejection, not a missing-path failure"
        )
        .into());
    }
    Ok(())
}

/// Sweep every leaf this machine forgot about.
///
/// `remove_dir` is the whole implementation on purpose: the kernel refuses
/// anything non-empty, so a leaf holding a live descendant survives its own
/// sweep by construction — no pid bookkeeping, no discovery pass.
fn sweep_empty_leaves(class: &Class) {
    let Ok(entries) = fs::read_dir(&class.dir) else {
        return;
    };
    for entry in entries.flatten() {
        let _ = fs::remove_dir(entry.path());
    }
}

/// Undo what [`attach_class`] installed, plus its record.
///
/// Lenient by contract, the way `run_lenient` teardown is: the tables may
/// already be gone (a reboot, a nested namespace), and a failed delete must
/// not strand the record where the next attach would wrongly honor it as a
/// live claim. A record whose deletes could not even start (`nft` missing)
/// is reported and kept: the only thing worse than a stale record is a
/// silently forgotten one.
pub(crate) fn detach_class(interface: &str, dry_run: bool) {
    let record_path = class_record_path(interface);
    let Ok(text) = fs::read_to_string(&record_path) else {
        return;
    };
    for line in parse_record(&text) {
        if dry_run {
            println!("nft delete table {} {}", line.family, line.table);
            continue;
        }
        // `-a`: the plan's own delete form.
        if let Err(error) = Command::new("nft")
            .arg("-a")
            .arg("delete")
            .arg("table")
            .arg(&line.family)
            .arg(&line.table)
            .status()
        {
            eprintln!(
                "note   `nft delete table {} {}` could not run: {error}; the record stays",
                line.family, line.table
            );
            return;
        }
    }
    if !dry_run {
        let _ = fs::remove_file(&record_path);
    }
}

struct RecordLine {
    family: String,
    table: String,
    rel: String,
}

/// A record as lines, filtered to the ones this crate could have written.
///
/// A line is exactly `nft <family> <table> <rel-path>`, the family names one
/// of this crate's two tables, and anything else is damage or a stranger's
/// line: named as such and skipped, the same contract
/// `routes::RoutePlan::parse` keeps for verbs it did not write.
fn parse_record(text: &str) -> Vec<RecordLine> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            if words.next() != Some("nft") {
                return None;
            }
            let family = words.next()?;
            let table = words.next()?;
            if table_name(family) != Some(table) {
                eprintln!(
                    "vallum-quick: ignoring a line the class record could not have \
                     written: {line}"
                );
                return None;
            }
            let rel = words.collect::<Vec<_>>().join(" ");
            if rel.is_empty() {
                return None;
            }
            Some(RecordLine {
                family: family.to_owned(),
                table: table.to_owned(),
                rel,
            })
        })
        .collect()
}

/// Whether the tunnel this interface names is actually up, in the one way
/// the class's machinery requires: the route record exists, and the policy
/// rule the class's `not fwmark` ride leans on is still in `ip rule`.
///
/// This is the leak-guard refusal the plan's verb sketch names: "the tunnel
/// is not attached — launching now would run outside the tunnel".
fn preflight_attached(interface: &str, table: &str) -> Result<(), Box<dyn std::error::Error>> {
    let record_path = routes::state_path(interface);
    if routes::read_plan(&record_path).is_none() {
        return Err(format!(
            "the tunnel is not attached — launching now would run outside the \
             tunnel: no `{}` record exists. Refusing rather than launching, \
             per ADR-0023's membership decision",
            record_path.display(),
        )
        .into());
    }
    let policy_table = if table == "auto" {
        routes::POLICY_TABLE
    } else {
        table
    };
    let output = Command::new("ip")
        .arg("rule")
        .output()
        .map_err(|error| format!("`ip rule` could not run: {error}"))?;
    let rules = String::from_utf8_lossy(&output.stdout);
    let present = rules.lines().any(|line| {
        line.contains("fwmark") && line.contains("lookup") && line.contains(policy_table)
    });
    if !present {
        return Err(format!(
            "the tunnel is not attached — launching now would run outside the \
             tunnel: no rule names policy table `{policy_table}` in `ip rule` \
             any more. Refusing rather than launching, per ADR-0023's \
             membership decision"
        )
        .into());
    }
    Ok(())
}

/// The verb: `app NAME -- CMD...`.
///
/// Refuses loudly — never launches — when the machine about to run `CMD`
/// cannot observe the class: an unknowing direct user would look exactly like
/// an exiting user, and that silence is the regression this verb exists to
/// prevent.
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
        return Err("`app NAME -- CMD...` needs a command after `--`".into());
    }

    let config = crate::load_normalized(config_path)?;
    let interface = config
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned());
    let table = config.quick.table.as_deref().unwrap_or("auto").to_owned();

    // Attached: route record plus policy rule, both checked before anything
    // that could launch.
    preflight_attached(&interface, &table)?;

    let class = resolve_class().map_err(|reason| {
        format!(
            "refusing to launch `{name}` outside the class: {reason}. A launch \
             that skips the class is exactly the traffic ADR-0023's membership \
             decision was made to prevent"
        )
    })?;

    // Liveness: a chain listing at exit 0 does not prove the rule still
    // exists — a deleted rule leaves the chain listable (plan, "the liveness
    // question"). The grep of the rule's own predicate text is the one cheap
    // faithful check, per family in the record.
    let record = fs::read_to_string(class_record_path(&interface)).map_err(|error| {
        format!(
            "refusing to launch `{name}` outside the class: the class record for \
             `{interface}` is missing ({error}) — the class was never installed \
             by attach, or its state was lost; reattach first"
        )
    })?;
    for line in parse_record(&record) {
        if line.rel != class.rel {
            return Err(format!(
                "refusing to launch `{name}` outside the class: the record's class \
                 path `{}` differs from this resolution's `{}` — the machine's \
                 cgroup layout changed since attach; reattach first",
                line.rel, class.rel,
            )
            .into());
        }
        let output = Command::new("nft")
            .arg("list")
            .arg("chain")
            .arg(&line.family)
            .arg(&line.table)
            .arg(CHAIN)
            .output()
            .map_err(|error| format!("`nft list chain` could not run: {error}"))?;
        let listing = String::from_utf8_lossy(&output.stdout);
        let live =
            output.status.success() && listing.contains("cgroupv2") && listing.contains(&class.rel);
        if !live {
            return Err(format!(
                "refusing to launch `{name}` outside the class: the rule in \
                 `{} {} {CHAIN}` does not list a `cgroupv2` rule naming `{}` — \
                 the kernel saw a ruleset reset, or the class was torn down out \
                 of band; reattach first, because launching now would arrive \
                 without being counted or steered, and that regression must not \
                 be silent",
                line.family, line.table, class.rel,
            )
            .into());
        }
    }

    if dry_run {
        println!(
            "cgroup leaf:      {}",
            class.dir.join(format!("{name}-<pid>")).display()
        );
        println!("cgroup rel path:  {} (level {})", class.rel, class.level());
        println!("command:          {}", cmd.join(" "));
        return Ok(());
    }

    // Launch-bound membership, in the form the workspace's `unsafe_code =
    // "forbid"` policy allows and the plan's `pre_exec` sketch would have
    // reached: the verb moves *itself* into the leaf, then spawns the
    // command as a plain child. The child is born into the leaf by cgroup
    // inheritance, so every descendant it forks joins the class the same
    // way; argv is preserved exactly (no shell, no quoting layer); and the
    // verb keeps the wait the plan named. The one form the plan recorded
    // cannot be used verbatim because `pre_exec` is inherently `unsafe`.
    let pid = std::process::id();
    let leaf = class.dir.join(format!("{name}-{pid}"));
    fs::create_dir(&leaf).map_err(|error| {
        format!(
            "entering the class failed: {error}; the leaf would be `{}` — \
             a `Permission denied` here means this context cannot write the \
             class dir, which on tier 1 means the launch must run with the \
             privileges attach ran with",
            leaf.display()
        )
    })?;
    if let Err(error) = fs::write(leaf.join("cgroup.procs"), pid.to_string()) {
        // The leaf was ours a moment ago; an empty one is not worth
        // remembering.
        let _ = fs::remove_dir(&leaf);
        return Err(format!("moving into the class failed: {error}").into());
    }
    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .spawn()
        .map_err(|error| {
            let _ = fs::remove_dir(&leaf);
            format!("launching `{name}` failed before it could run: {error}")
        })?;
    let status = child
        .wait()
        .map_err(|error| format!("waiting on `{name}` failed: {error}"))?;
    if fs::remove_dir(&leaf).is_err() {
        // The leaf outlived its launch: whatever is inside is still classed,
        // and the next attach sweeps it once it is empty. The note names the
        // leaf, the way the launch made it precise.
        eprintln!(
            "note   leaf `{}` outlived its launch (a descendant is still inside); \
             it stays until it exits, then the next attach sweeps it",
            leaf.display()
        );
    }

    // The parent exits with the child's exit code, because the whole verb is
    // "launch this": operators script `app ... -- CMD && rest`. A child
    // killed by a signal reports as 1 — the parent cannot name the signal
    // without a libc dependency, and the crate is stdlib-only by policy.
    std::process::exit(status.code().unwrap_or(1));
}

/// The member-name allowlist: cgroup-name legality, plus the null-free and
/// dot-dot-free properties, in one closed alphabet.
///
/// `[a-zA-Z0-9_[.-]]` capped at 32 bytes, per the plan, with the whole-name
/// forms `.` and `..` refused before the kernel is asked what they mean.
pub(crate) fn valid_app_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("member name must not be empty".into());
    }
    if name.len() > 32 {
        return Err(format!(
            "member name `{name}` is {} bytes; the cap is 32 (cgroup name legality)",
            name.len()
        ));
    }
    if name == "." || name == ".." {
        return Err(format!("member name `{name}` is not a cgroup name"));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Err(format!(
            "member name `{name}` has a character outside the cgroup-name \
             alphabet, which is `[a-zA-Z0-9_-.]` here"
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::env::temp_dir;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A config parsed through the same `deny_unknown_fields` schema the
    /// daemon reads — no test-only schema, no invented shape.
    fn config(text: &str) -> Config {
        // The pid is shared by every test thread; the counter is not.
        static CALL: AtomicU32 = AtomicU32::new(0);
        let path = temp_dir().join(format!(
            "vallum-class-test-{}-{}.toml",
            std::process::id(),
            CALL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, text).expect("test config writes");
        let parsed = Config::load(&path).expect("test config parses");
        let _ = fs::remove_file(&path);
        parsed
    }

    fn full_tunnel(fwmark: u32) -> Config {
        config(&format!(
            r#"
[interface]
name = "ei"
private_key = "/boot/signing.key"
fwmark = {fwmark}

[quick]
app_class = true

[[peer]]
name = "gw"
public_key = "peer"
allowed_ips = ["0.0.0.0/0", "::/0"]
"#
        ))
    }

    fn split_tunnel() -> Config {
        config(
            r#"
[interface]
name = "ei"
private_key = "/boot/signing.key"
fwmark = 51820

[quick]
app_class = true

[[peer]]
name = "gw"
public_key = "peer"
allowed_ips = ["10.0.0.0/8"]
"#,
        )
    }

    #[test]
    fn split_tunnel_refuses() {
        let reason = check_config(&split_tunnel()).unwrap_err();
        assert!(reason.contains("full tunnel"), "{reason}");
    }

    #[test]
    fn mark_collision_refuses() {
        let reason = check_config(&full_tunnel(CLASS_MARK)).unwrap_err();
        assert!(reason.contains(&CLASS_MARK.to_string()), "{reason}");
    }

    #[test]
    fn full_tunnel_with_its_own_mark_passes() {
        check_config(&full_tunnel(51820)).expect("a well-formed full tunnel accepts the class");
    }

    #[test]
    fn app_name_alphabet_is_closed() {
        for good in ["a", "browser", "browser.tab-2", "x_y.z-1", "0"] {
            valid_app_name(good).unwrap_or_else(|error| panic!("{good} should be valid: {error}"));
        }
        for bad in [
            "",
            ".",
            "..",
            "with space",
            "with/slash",
            "a-member-name-that-is-certainly-longer-than-thirty-two-bytes",
        ] {
            assert!(valid_app_name(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn record_lines_are_strictly_ours() {
        let text = record_text("user.slice/user-1000.slice/user@1000.service/vallum-apps");
        assert_eq!(
            text,
            "nft ip vallumapps user.slice/user-1000.slice/user@1000.service/vallum-apps\n\
             nft ip6 vallum6app user.slice/user-1000.slice/user@1000.service/vallum-apps\n"
        );
        let lines = parse_record(&text);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].family, "ip");
        assert_eq!(lines[0].table, V4_TABLE);
        assert_eq!(lines[1].family, "ip6");
        assert_eq!(lines[1].table, V6_TABLE);

        // A stranger's line is named and skipped, never executed.
        let mixed = format!("{text}nft ip evil wrap\nnot nft at all\n");
        assert_eq!(parse_record(&mixed).len(), 2);
    }

    #[test]
    fn class_holder_sees_other_interfaces_only() {
        let dir = temp_dir().join(format!("vallum-class-holder-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("holder test dir");
        fs::write(dir.join("other.quick-class"), "nft ip x y\n").expect("record");
        assert_eq!(class_holder(&dir, "ei"), Some("other".to_owned()));
        assert_eq!(class_holder(&dir, "other"), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rule_naming_has_both_families_and_a_live_level() {
        let class = Class {
            dir: PathBuf::from("/sys/fs/cgroup/user.slice/u/user@1000.service/vallum-apps"),
            rel: "user.slice/u/user@1000.service/vallum-apps".to_owned(),
        };
        let file = render_file(&class);
        assert!(file.contains("add table ip vallumapps"));
        assert!(file.contains("add table ip6 vallum6app"));
        assert!(file.contains("type route hook output priority filter"));
        // The tier-2 path is four components deep, and every rule says so.
        assert_eq!(file.matches("level 4").count(), 2);
        assert!(file.contains(&format!("meta mark set {CLASS_MARK}")));
    }
}
