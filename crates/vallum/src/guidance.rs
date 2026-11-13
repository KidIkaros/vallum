// SPDX-License-Identifier: Apache-2.0

//! Next-step guidance: what this machine most wants its operator to do.
//!
//! Consoles should not make an operator memorise the lifecycle — the machine
//! knows which stage it is in, so it can say so. [`suggest`] turns a flat bag
//! of facts (each surface collects them from wherever it already looks: the
//! control socket, systemd state, the filesystem) into a short, ordered list
//! of suggestions. Every suggestion carries the action that resolves it, so a
//! surface can render a button rather than an instruction.
//!
//! The rules are deliberately conservative: a suggestion that is wrong once is
//! worse than no suggestion at all, so each one is phrased as an observation
//! plus an offer, never a demand.

use serde::Serialize;

/// How much the suggestion wants attention.
///
/// `Act` is a machine that cannot do its job until something happens.
/// `Warn` is a machine doing its job in a way that will surprise the operator
/// later. `Info` is ambient: progress notes and quiet confirmations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Tone {
    Act,
    Warn,
    Info,
}

/// The button a surface renders beside a suggestion.
///
/// Variants name console capabilities, not binaries: `SyncHost` means "the
/// `vallum-ops sync` verb", `FinalizePeer` means the peer command the surface
/// already exposes. Surfaces without a capability ignore the suggestion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum Action {
    JoinNetwork,
    SetupServer,
    StartService,
    EnableService,
    RestartService,
    DisableUnits,
    InvitePeer,
    CloseEnrolment,
    FinalizePeer(String),
    PingPeer,
    SyncHost,
    OpenLogs,
    HealthCheck,
    EditConfig,
    CopyPublicLine,
}

/// A single next step, ordered by how much it matters.
#[derive(Clone, Debug, Serialize)]
pub struct Suggestion {
    /// Stable identifier for tests and for surfaces that want to dismiss or
    /// pin particular rules.
    pub id: &'static str,
    pub tone: Tone,
    /// One line; fits in a status strip.
    pub title: String,
    /// The "why" — the sentence that teaches the operator what this state
    /// means, so the console is also the manual.
    pub detail: String,
    pub action: Option<Action>,
}

/// What role a configuration gives the machine.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub enum Role {
    /// Peers carry fixed endpoints — this machine dials out.
    Client,
    /// A declared public endpoint or enrolment section — peers dial in.
    Server,
    /// No config yet, or not enough of one to tell.
    #[default]
    Unknown,
}

/// The handful of facts about one peer that guidance reasons over.
#[derive(Clone, Debug, Default)]
pub struct PeerFact {
    pub name: String,
    /// Fixed endpoint set: a client-shaped peer the daemon must dial.
    pub has_endpoint: bool,
    /// Seconds since the last completed handshake; `None` when never.
    pub handshake_age_secs: Option<u64>,
    /// A staged rotation still accepting the previous key.
    pub rotating: bool,
}

/// Everything a surface knows about the machine, gathered however it gathers
/// it. Fields are optional where a surface cannot see them — guidance works
/// with partial facts and simply skips rules it cannot evaluate.
#[derive(Clone, Debug, Default)]
pub struct Facts {
    /// A config exists at all (`/etc/vallum/*.toml` or a known path).
    pub config_present: bool,
    pub role: Role,
    /// The tunnel unit is running per systemd.
    pub unit_active: Option<bool>,
    /// The tunnel unit starts at boot.
    pub unit_enabled: Option<bool>,
    /// The control socket answers.
    pub daemon_reachable: Option<bool>,
    /// The kernel interface exists.
    pub interface_present: Option<bool>,
    pub peers: Vec<PeerFact>,
    /// The enrolment responder is running — an open invitation door.
    pub enrolment_open: Option<bool>,
    /// A full-tunnel trial is armed (dead-man or guard unit active).
    pub trial_armed: Option<bool>,
    /// Reported restart count of the unit, when systemd exposes it.
    pub unit_restarts: Option<u64>,
    /// `vallum-ops sync --check` says installed binaries differ from the
    /// source tree; `None` on hosts without a trusted source tree.
    pub sync_stale: Option<bool>,
    /// SSH targets the operator's config already knows, for hint quality.
    pub ssh_hosts: usize,
}

/// The peer table's answer to "what kind of machine is this" when the config
/// cannot be read: a machine that dials fixed endpoints is a client; one with
/// only roaming peers is a server; an empty table says nothing.
#[must_use]
pub fn infer_role(peers: &[PeerFact]) -> Role {
    if peers.iter().any(|peer| peer.has_endpoint) {
        Role::Client
    } else if peers.is_empty() {
        Role::Unknown
    } else {
        Role::Server
    }
}

/// How many suggestions a surface is asked to show at once.
const MAX_SUGGESTIONS: usize = 3;

/// A handshake older than this many seconds is treated as suspicious for a
/// peer with a fixed endpoint — keepalive traffic should have refreshed it.
const STALE_HANDSHAKE_SECS: u64 = 360;

/// Unit restarts beyond this count are worth a look even when it is running.
const NOISY_RESTARTS: u64 = 3;

/// The machine's next steps, most important first.
///
/// At most [`MAX_SUGGESTIONS`] entries — a wall of advice teaches nothing.
pub fn suggest(facts: &Facts) -> Vec<Suggestion> {
    let mut out = Vec::new();

    // Nothing can be guided until a machine has an identity. Both first steps
    // are valid; join is listed first because most machines are clients.
    if !facts.config_present {
        out.push(Suggestion {
            id: "unenrolled-join",
            tone: Tone::Act,
            title: "this machine is not part of a network".into(),
            detail: "Joining takes a one-time ticket from your server's \
                     operator — paste it and the machine enrols itself."
                .into(),
            action: Some(Action::JoinNetwork),
        });
        out.push(Suggestion {
            id: "unenrolled-host",
            tone: Tone::Info,
            title: "…or make this machine the server".into(),
            detail: "A server needs a public address peers can dial. If this \
                     machine has one, hosting takes under a minute."
                .into(),
            action: Some(Action::SetupServer),
        });
        return out;
    }

    // The unit is the machine's voice; nothing else matters while it is down.
    if facts.unit_active == Some(false) {
        out.push(Suggestion {
            id: "service-down",
            tone: Tone::Act,
            title: "the tunnel is installed but not running".into(),
            detail: "Until the service starts there is no interface, no \
                     handshake and no traffic — one click is the whole fix."
                .into(),
            action: Some(Action::StartService),
        });
    }

    // systemd says up, the daemon says nothing: the unhealthiest state of all.
    if facts.unit_active == Some(true) && facts.daemon_reachable == Some(false) {
        out.push(Suggestion {
            id: "daemon-silent",
            tone: Tone::Warn,
            title: "the unit is up but the daemon is not answering".into(),
            detail: "The socket is quiet, so nothing on this screen is live. \
                     A restart usually clears it; the log says why it stopped."
                .into(),
            action: Some(Action::RestartService),
        });
    }

    // A machine that is running but will not come back after reboot.
    if facts.unit_active == Some(true) && facts.unit_enabled == Some(false) {
        out.push(Suggestion {
            id: "not-enabled",
            tone: Tone::Info,
            title: "the tunnel runs but will not return after a reboot".into(),
            detail: "Enable the unit once and the machine rejoins the network \
                     by itself every boot."
                .into(),
            action: Some(Action::EnableService),
        });
    }

    // An open responder is a standing invitation — close the door.
    if facts.enrolment_open == Some(true) {
        out.push(Suggestion {
            id: "enrolment-open",
            tone: Tone::Warn,
            title: "enrolment is open — the responder is listening".into(),
            detail: "While it listens, anyone holding a ticket can enrol. \
                     Close it once your devices have joined."
                .into(),
            action: Some(Action::CloseEnrolment),
        });
    }

    // A staged rotation is a second live identity; retire it on purpose.
    for peer in &facts.peers {
        if peer.rotating {
            out.push(Suggestion {
                id: "rotation-staged",
                tone: Tone::Act,
                title: format!("rotation for `{}` is staged, not finished", peer.name),
                detail: "Both keys are accepted until the rotation is \
                         finalised. Finish it once the peer has reconnected \
                         on its new key."
                    .into(),
                action: Some(Action::FinalizePeer(peer.name.clone())),
            });
        }
    }

    // Empty peer tables mean different things by role.
    if facts.daemon_reachable == Some(true) && facts.peers.is_empty() {
        match facts.role {
            Role::Server => out.push(Suggestion {
                id: "server-no-peers",
                tone: Tone::Act,
                title: "the server is up but nobody can reach it".into(),
                detail: "No device is enrolled. Mint a one-time invite and \
                         hand it to the first device — the ticket carries \
                         everything it needs."
                    .into(),
                action: Some(Action::InvitePeer),
            }),
            Role::Client => out.push(Suggestion {
                id: "client-no-peers",
                tone: Tone::Warn,
                title: "the tunnel has nowhere to send traffic".into(),
                detail: "This config names no peers, so packets have no \
                         destination. Rejoin with a fresh ticket or fix the \
                         config by hand."
                    .into(),
                action: Some(Action::EditConfig),
            }),
            Role::Unknown => {}
        }
    }

    // Fixed-endpoint peers that stopped answering: the failure an operator
    // notices last and should notice first.
    for peer in &facts.peers {
        let stale = match peer.handshake_age_secs {
            Some(age) => age > STALE_HANDSHAKE_SECS,
            None => facts.daemon_reachable == Some(true) && peer.has_endpoint,
        };
        if peer.has_endpoint && stale {
            let age = peer
                .handshake_age_secs
                .map(describe_age)
                .unwrap_or_else(|| "never".to_owned());
            out.push(Suggestion {
                id: "handshake-stale",
                tone: Tone::Warn,
                title: format!("no handshake with `{}` ({age})", peer.name),
                detail: "The peer is not answering — check it is reachable \
                         and both ends still trust the same keys."
                    .into(),
                action: Some(Action::PingPeer),
            });
            break; // one stale-peer line is enough; the rest will rhyme
        }
    }

    // A flap count worth noticing even while the unit reads active.
    if let Some(restarts) = facts.unit_restarts {
        if restarts > NOISY_RESTARTS && facts.unit_active == Some(true) {
            out.push(Suggestion {
                id: "noisy-restarts",
                tone: Tone::Info,
                title: format!("the daemon has restarted {restarts} times"),
                detail: "It is up now, but repeated restarts usually mean a \
                         config the daemon keeps rejecting. The log names it."
                    .into(),
                action: Some(Action::OpenLogs),
            });
        }
    }

    // Developer-facing: the tree and the host disagree.
    if facts.sync_stale == Some(true) {
        out.push(Suggestion {
            id: "sync-stale",
            tone: Tone::Info,
            title: "the installed build is behind the source tree".into(),
            detail: "This host tracks a development checkout — sync brings \
                     the installed binaries, units and tools up to date."
                .into(),
            action: Some(Action::SyncHost),
        });
    }

    // The calm state: one quiet line so the surface has something honest to
    // show instead of an empty panel.
    if out.is_empty() && facts.daemon_reachable == Some(true) {
        out.push(Suggestion {
            id: "healthy",
            tone: Tone::Info,
            title: "everything looks healthy".into(),
            detail: "Handshakes are fresh, units are in their intended state, \
                     and nothing needs attention."
                .into(),
            action: None,
        });
    }

    out.truncate(MAX_SUGGESTIONS);
    out
}

/// `4930` becomes `"82 min ago"`; ages under a minute read "just now".
fn describe_age(secs: u64) -> String {
    if secs < 60 {
        "just now".to_owned()
    } else if secs < 3600 {
        format!("{} min ago", secs / 60)
    } else {
        format!("{} h ago", secs / 3600)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn running_client() -> Facts {
        Facts {
            config_present: true,
            role: Role::Client,
            unit_active: Some(true),
            unit_enabled: Some(true),
            daemon_reachable: Some(true),
            interface_present: Some(true),
            peers: vec![PeerFact {
                name: "vps".into(),
                has_endpoint: true,
                handshake_age_secs: Some(40),
                rotating: false,
            }],
            ..Facts::default()
        }
    }

    fn ids(facts: &Facts) -> Vec<&'static str> {
        suggest(facts).iter().map(|s| s.id).collect()
    }

    #[test]
    fn a_bare_machine_is_offered_both_first_steps() {
        let facts = Facts::default();
        assert_eq!(ids(&facts), ["unenrolled-join", "unenrolled-host"]);
    }

    #[test]
    fn a_stopped_service_is_the_first_thing_fixed() {
        let facts = Facts {
            unit_active: Some(false),
            ..running_client()
        };
        assert_eq!(ids(&facts)[0], "service-down");
    }

    #[test]
    fn a_silent_daemon_is_a_warning_not_a_start_button() {
        let facts = Facts {
            daemon_reachable: Some(false),
            ..running_client()
        };
        assert!(ids(&facts).contains(&"daemon-silent"));
        assert!(!ids(&facts).contains(&"service-down"));
    }

    #[test]
    fn an_open_responder_is_flagged() {
        let facts = Facts {
            enrolment_open: Some(true),
            ..running_client()
        };
        assert!(ids(&facts).contains(&"enrolment-open"));
    }

    #[test]
    fn a_staged_rotation_asks_for_finalize() {
        let mut facts = running_client();
        facts.peers[0].rotating = true;
        let suggestions = suggest(&facts);
        let staged = suggestions
            .iter()
            .find(|s| s.id == "rotation-staged")
            .expect("rotation suggestion");
        assert_eq!(staged.action, Some(Action::FinalizePeer("vps".into())));
    }

    #[test]
    fn a_server_without_peers_is_asked_to_invite() {
        let facts = Facts {
            role: Role::Server,
            peers: vec![],
            ..running_client()
        };
        assert!(ids(&facts).contains(&"server-no-peers"));
    }

    #[test]
    fn a_fresh_handshake_is_not_flagged_stale() {
        assert!(!ids(&running_client()).contains(&"handshake-stale"));
    }

    #[test]
    fn an_old_handshake_is_flagged_stale() {
        let mut facts = running_client();
        facts.peers[0].handshake_age_secs = Some(STALE_HANDSHAKE_SECS + 1);
        assert!(ids(&facts).contains(&"handshake-stale"));
    }

    #[test]
    fn a_peer_that_never_shook_hands_is_flagged() {
        let mut facts = running_client();
        facts.peers[0].handshake_age_secs = None;
        assert!(ids(&facts).contains(&"handshake-stale"));
    }

    #[test]
    fn a_stale_checkout_suggests_sync() {
        let facts = Facts {
            sync_stale: Some(true),
            ..running_client()
        };
        assert!(ids(&facts).contains(&"sync-stale"));
    }

    #[test]
    fn a_healthy_machine_reports_calm() {
        assert_eq!(ids(&running_client()), ["healthy"]);
    }

    #[test]
    fn suggestions_are_capped() {
        // Stop the service, open enrolment, stage a rotation and staleness —
        // more than MAX_SUGGESTIONS rules fire, the list stays short.
        let mut facts = running_client();
        facts.unit_active = Some(false);
        facts.enrolment_open = Some(true);
        facts.peers[0].rotating = true;
        facts.peers[0].handshake_age_secs = None;
        facts.sync_stale = Some(true);
        assert!(suggest(&facts).len() <= MAX_SUGGESTIONS);
        assert_eq!(ids(&facts)[0], "service-down");
    }
}
