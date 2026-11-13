// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::app::{App, DeviceView, Form};
use super::qr;
use crate::uapi::Response;

#[test]
fn a_device_view_parses_the_get_response() {
    let response = Response {
        device: vec![
            ("vallum_interface".to_owned(), "vallum0".to_owned()),
            ("vallum_listen".to_owned(), "0.0.0.0:51820".to_owned()),
            ("vallum_suite".to_owned(), "0x0003".to_owned()),
            (
                "vallum_fingerprint".to_owned(),
                "0011223344556677".to_owned(),
            ),
            ("vallum_address".to_owned(), "10.7.0.1/24".to_owned()),
            ("vallum_batching".to_owned(), "true".to_owned()),
            ("vallum_datagrams_sent".to_owned(), "10".to_owned()),
            ("vallum_datagrams_failed".to_owned(), "0".to_owned()),
            ("vallum_packets_delivered".to_owned(), "9".to_owned()),
            ("vallum_packets_failed".to_owned(), "0".to_owned()),
            ("vallum_handshakes_established".to_owned(), "1".to_owned()),
            ("vallum_handshakes_refused".to_owned(), "0".to_owned()),
            ("vallum_reassembled".to_owned(), "4".to_owned()),
            ("vallum_fragments_dropped".to_owned(), "0".to_owned()),
            ("vallum_fragments_rate_limited".to_owned(), "2".to_owned()),
            ("vallum_handshake_dropped_stale".to_owned(), "1".to_owned()),
        ],
        peers: vec![vec![
            ("vallum_name".to_owned(), "laptop".to_owned()),
            (
                "vallum_fingerprint".to_owned(),
                "8899aabbccddeeff".to_owned(),
            ),
            ("allowed_ip".to_owned(), "10.7.0.2/32".to_owned()),
            ("tx_bytes".to_owned(), "100".to_owned()),
            ("rx_bytes".to_owned(), "200".to_owned()),
            ("vallum_window_sent".to_owned(), "12".to_owned()),
            ("vallum_window_received".to_owned(), "14".to_owned()),
            ("vallum_last_received_ms".to_owned(), "350".to_owned()),
            ("vallum_dropped_after_auth".to_owned(), "1".to_owned()),
            (
                "vallum_last_rejected_source".to_owned(),
                "192.0.2.9".to_owned(),
            ),
            ("vallum_epoch".to_owned(), "3".to_owned()),
        ]],
    };
    let device = DeviceView::from_response(&response);
    assert_eq!(device.interface, "vallum0");
    assert_eq!(device.suite_id, 3);
    assert!(device.batching);
    assert_eq!(
        device
            .stats
            .map(|s| (s.fragments_rate_limited, s.handshake_dropped_stale)),
        Some((2, 1))
    );
    assert_eq!(device.peers[0].name, "laptop");
    assert_eq!(device.peers[0].allowed_ips, vec!["10.7.0.2/32"]);
    assert_eq!(device.peers[0].window_sent, 12);
    assert_eq!(device.peers[0].window_received, 14);
    assert_eq!(device.peers[0].last_received_ms, Some(350));
    assert_eq!(device.peers[0].dropped_after_auth, 1);
    assert_eq!(
        device.peers[0].last_rejected_source.as_deref(),
        Some("192.0.2.9")
    );
    assert_eq!(device.peers[0].epoch, 3);
}

#[test]
fn the_device_form_prefills_the_port() {
    let device = DeviceView {
        listen: "10.99.0.1:51820".to_owned(),
        fwmark: 7,
        ..DeviceView::default()
    };
    let form = Form::device(&device);
    assert_eq!(form.field("listen port"), "51820");
    assert_eq!(form.field("fwmark"), "7");
}

#[test]
fn peer_forms_expose_and_preserve_the_peer_name() {
    let add = Form::add_peer();
    assert_eq!(add.field("name"), "");

    let peer = super::app::PeerView {
        name: "work-laptop".to_owned(),
        ..super::app::PeerView::default()
    };
    let edit = Form::edit_peer(0, &peer);
    assert_eq!(edit.field("name"), "work-laptop");
}

#[test]
fn form_text_can_be_corrected_without_erasing_the_whole_field() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = App::new(Vec::new());
    app.form = Some(Form::add_peer());
    for character in ['c', 'a', 't'] {
        super::input::handle(
            &mut app,
            KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE),
        );
    }
    super::input::handle(&mut app, KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
    );
    assert_eq!(app.form.as_ref().map(|form| form.field("name")), Some("ct"));
}

#[test]
fn form_validation_stays_visible_and_points_to_the_invalid_field() {
    use ratatui::{backend::TestBackend, Terminal};

    let mut app = App::new(Vec::new());
    let device = DeviceView {
        listen: "0.0.0.0:51820".to_owned(),
        ..DeviceView::default()
    };
    let mut form = Form::device(&device);
    form.fields[0].value = "not-a-port".to_owned();
    app.form = Some(form);

    super::actions::submit_form(&mut app);

    let form = app.form.as_ref().expect("invalid form remains open");
    let error = form.error.as_ref().expect("field error remains visible");
    assert_eq!(error.field, Some("listen port"));
    assert_eq!(error.message, "listen port is not a number");
    assert_eq!(form.field("listen port"), "not-a-port");
    assert!(app.toast.is_none());

    let mut terminal = Terminal::new(TestBackend::new(100, 24)).expect("test terminal");
    terminal
        .draw(|frame| super::ui::draw(frame, &app))
        .expect("draw invalid form");
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("! listen port is not a number"));
}

#[test]
fn masked_form_fields_hide_values_and_do_not_reveal_length() {
    use ratatui::{backend::TestBackend, Terminal};

    let mut app = App::new(Vec::new());
    let mut form = Form::add_peer();
    form.fields[5].value = "very-secret-psk".to_owned();
    form.focus = 5;
    form.cursor = form.fields[5].value.chars().count();
    app.form = Some(form);

    let mut terminal = Terminal::new(TestBackend::new(100, 24)).expect("test terminal");
    terminal
        .draw(|frame| super::ui::draw(frame, &app))
        .expect("draw form");
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(!text.contains("very-secret-psk"));
    assert!(text.contains("************|"));
}

#[test]
fn empty_dashboard_explains_how_to_connect_or_start_an_interface() {
    use ratatui::{backend::TestBackend, Terminal};

    let mut terminal = Terminal::new(TestBackend::new(100, 24)).expect("test terminal");
    terminal
        .draw(|frame| super::ui::draw(frame, &App::new(Vec::new())))
        .expect("draw dashboard");
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("No tunnel on this machine yet"));
    assert!(text.contains("What is this machine?"));
    assert!(text.contains("vallum setup --server"));
    assert!(!text.contains("No device data"));
}

#[test]
fn dashboard_shows_dataplane_status_without_control_implementation_flags() {
    use ratatui::{backend::TestBackend, Terminal};

    let mut interface = super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/run/vallum/vallum0.sock"),
    );
    interface.set_device(DeviceView {
        interface: "vallum0".to_owned(),
        listen: "[::]:51820".to_owned(),
        suite: "0x0003".to_owned(),
        fingerprint: "0011223344556677".to_owned(),
        offload: true,
        batching: false,
        ..DeviceView::default()
    });
    interface.set_service_state(Some(super::app::ServiceState::Active));
    let app = App::new(vec![interface]);
    let mut terminal = Terminal::new(TestBackend::new(120, 30)).expect("test terminal");
    terminal
        .draw(|frame| super::ui::draw(frame, &app))
        .expect("draw dashboard");
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("Vallum ❯ TUNNEL CONTROL"));
    assert!(text.contains("offload on"));
    assert!(text.contains("UDP batching off"));
    assert!(text.contains("CONTROL LIVE"));
    assert!(text.contains("systemd active"));
    assert!(!text.contains("can_set"));
}

#[test]
fn the_guard_pill_appears_only_when_full_tunnel_is_armed() {
    use ratatui::{backend::TestBackend, Terminal};

    fn frame(egress: &str, guard: Option<super::app::ServiceState>) -> String {
        let mut interface = super::app::Interface::new(
            "vallum0".to_owned(),
            None,
            std::path::PathBuf::from("/run/vallum/vallum0.sock"),
        );
        interface.set_device(super::app::DeviceView {
            interface: "vallum0".to_owned(),
            egress: egress.to_owned(),
            ..super::app::DeviceView::default()
        });
        interface.set_service_state(Some(super::app::ServiceState::Active));
        interface.set_guard_state(guard);
        let app = App::new(vec![interface]);
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).expect("test terminal");
        terminal
            .draw(|f| super::ui::draw(f, &app))
            .expect("draw dashboard");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    // Full tunnel armed: the guard's state is shown, both ways.
    assert!(frame("full", Some(super::app::ServiceState::Active)).contains("GUARD ON"));
    assert!(frame("full", Some(super::app::ServiceState::Inactive)).contains("GUARD OFF"));
    // Split: the guard is not needed, so no pill at all.
    assert!(!frame("split", Some(super::app::ServiceState::Active)).contains("GUARD"));
}

#[test]
fn handshake_freshness_labels_use_documented_boundaries() {
    use super::app::HandshakeFreshness;

    let now = 1_800_000_000;
    let mut peer = super::app::PeerView::default();
    assert_eq!(
        App::handshake_freshness_at(&peer, now),
        HandshakeFreshness::Never
    );

    peer.last_handshake = Some((now - 299, 0));
    assert_eq!(
        App::handshake_freshness_at(&peer, now),
        HandshakeFreshness::Recent
    );
    peer.last_handshake = Some((now - 300, 0));
    assert_eq!(
        App::handshake_freshness_at(&peer, now),
        HandshakeFreshness::Aging
    );
    peer.last_handshake = Some((now - 3599, 0));
    assert_eq!(
        App::handshake_freshness_at(&peer, now),
        HandshakeFreshness::Aging
    );
    peer.last_handshake = Some((now - 3600, 0));
    assert_eq!(
        App::handshake_freshness_at(&peer, now),
        HandshakeFreshness::Old
    );
}

#[test]
fn handshake_age_is_read_against_the_frame_s_clock_not_the_host_s() {
    let now = 1_800_000_000;
    let mut peer = super::app::PeerView::default();
    assert_eq!(App::handshake_age_at(&peer, now), "—");

    peer.last_handshake = Some((now - 14, 0));
    assert_eq!(App::handshake_age_at(&peer, now), "14s");
    // The same peer, a minute later on the same pinned clock: the text moves
    // because the clock did, and not because the wall clock happened to.
    assert_eq!(App::handshake_age_at(&peer, now + 60), "1m");
    peer.last_handshake = Some((now - 3600, 0));
    assert_eq!(App::handshake_age_at(&peer, now), "1h");
    // A stamp from the future reads as no time at all rather than wrapping.
    peer.last_handshake = Some((now + 5, 0));
    assert_eq!(App::handshake_age_at(&peer, now), "0s");
}

#[test]
fn peer_verdict_names_a_next_step_only_where_one_exists() {
    let now = 1_800_000_000;
    let mut peer = super::app::PeerView::default();

    // Never, no endpoint: the far end has never called home.
    assert_eq!(
        App::peer_verdict_at(&peer, now),
        "no handshake yet — the far end has never connected; check it is running"
    );
    // Never, with an endpoint: the path itself is suspect.
    peer.endpoint = "203.0.113.7:51820".to_owned();
    assert_eq!(
        App::peer_verdict_at(&peer, now),
        "no handshake yet — check the far end is running and reachable at this endpoint"
    );
    // Healthy peers read as healthy, not as an absence of warnings.
    peer.last_handshake = Some((now - 14, 0));
    assert_eq!(
        App::peer_verdict_at(&peer, now),
        "live — last handshake 14s ago"
    );
    // Quiet names the idle case so it does not read as a fault.
    peer.last_handshake = Some((now - 600, 0));
    assert!(App::peer_verdict_at(&peer, now).starts_with("quiet — last handshake 10m ago;"));
    // Stale with no keepalive names keepalive; with one it does not.
    peer.last_handshake = Some((now - 7200, 0));
    assert!(App::peer_verdict_at(&peer, now).contains("keepalive is set if it roams"));
    peer.keepalive = Some(25);
    assert!(!App::peer_verdict_at(&peer, now).contains("keepalive"));
    // Rotation overrides everything: the open rotation is the news.
    peer.rotating = true;
    assert!(App::peer_verdict_at(&peer, now).contains("rotation in progress"));
}

#[test]
fn service_state_labels_are_limited_to_known_systemd_states() {
    use super::app::ServiceState;

    assert_eq!(ServiceState::parse("active\n"), Some(ServiceState::Active));
    assert_eq!(
        ServiceState::parse("inactive"),
        Some(ServiceState::Inactive)
    );
    assert_eq!(ServiceState::parse("failed"), Some(ServiceState::Failed));
    assert_eq!(ServiceState::parse("unknown"), None);
}

#[test]
fn narrow_dashboard_keeps_peer_traffic_and_security_state_visible() {
    use ratatui::{backend::TestBackend, Terminal};

    let peer = super::app::PeerView {
        name: "remote-build-runner".to_owned(),
        fingerprint: "8899aabbccddeeff".to_owned(),
        endpoint: "192.0.2.24:51820".to_owned(),
        allowed_ips: vec!["10.7.0.2/32".to_owned()],
        keepalive: Some(25),
        tx_bytes: 2048,
        rx_bytes: 1024,
        preshared_key: true,
        ..super::app::PeerView::default()
    };
    let mut interface = super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/run/vallum/vallum0.sock"),
    );
    interface.set_device(DeviceView {
        interface: "vallum0".to_owned(),
        peers: vec![peer],
        ..DeviceView::default()
    });
    let app = App::new(vec![interface]);
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("test terminal");
    terminal
        .draw(|frame| super::ui::draw(frame, &app))
        .expect("draw narrow dashboard");
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("keepalive 25s"));
    assert!(text.contains("NEVER"));
    assert!(text.contains("rx 1.0K / tx 2.0K"));
    assert!(text.contains("PSK configured"));
}

#[test]
fn expanded_peer_table_fits_ipv6_endpoints_and_transfer_totals() {
    use ratatui::{backend::TestBackend, Terminal};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let peers = vec![super::app::PeerView {
        name: "field-laptop".to_owned(),
        fingerprint: "7766554433221100".to_owned(),
        endpoint: "[2001:db8::12]:51820".to_owned(),
        allowed_ips: vec!["10.7.0.3/32".to_owned()],
        last_handshake: Some((now.saturating_sub(10 * 60), 0)),
        tx_bytes: 72_000,
        rx_bytes: 543_210,
        epoch: 2,
        ..super::app::PeerView::default()
    }];
    let mut interface = super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/run/vallum/vallum0.sock"),
    );
    interface.set_device(DeviceView {
        interface: "vallum0".to_owned(),
        peers,
        ..DeviceView::default()
    });
    let app = App::new(vec![interface]);
    let mut terminal = Terminal::new(TestBackend::new(160, 36)).expect("test terminal");
    terminal
        .draw(|frame| super::ui::draw(frame, &app))
        .expect("draw wide dashboard");
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("[2001:db8::12]:51820"));
    assert!(text.contains("530.5K/70.3K"));
    assert!(text.contains("AGING"));
}

#[test]
fn disconnected_control_marks_the_retained_snapshot_as_stale() {
    use ratatui::{backend::TestBackend, Terminal};

    let mut interface = super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/tmp/vallum-control-socket-that-does-not-exist"),
    );
    interface.set_device(DeviceView {
        interface: "vallum0".to_owned(),
        ..DeviceView::default()
    });
    let mut app = App::new(vec![interface]);
    super::actions::refresh(&mut app);
    assert!(app
        .current()
        .is_some_and(|interface| { interface.device.is_some() && interface.error.is_some() }));

    let mut terminal = Terminal::new(TestBackend::new(120, 30)).expect("test terminal");
    terminal
        .draw(|frame| super::ui::draw(frame, &app))
        .expect("draw stale dashboard");
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("CONTROL STALE"));
    assert!(text.contains("PEERS (stale snapshot)"));
}

#[test]
fn escape_closes_the_qr_modal() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let mut app = App::new(Vec::new());
    app.qr = Some(qr::QrState {
        frames: vec!["frame".to_owned()],
        index: 0,
        last: std::time::Instant::now(),
        hash: "hash".to_owned(),
        path: "/tmp/x".to_owned(),
        kind: qr::QrKind::Bundle,
    });
    super::input::handle(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.qr.is_none());
}

#[test]
fn an_unspecified_endpoint_is_rejected() {
    let device = DeviceView {
        listen: "0.0.0.0:51820".to_owned(),
        public_line: "vallum1:0003:00:-".to_owned(),
        ..DeviceView::default()
    };
    let peer = super::app::PeerView {
        allowed_ips: vec!["10.7.0.2/32".to_owned()],
        ..super::app::PeerView::default()
    };
    assert!(super::bundle::build(
        &device,
        &peer,
        std::path::Path::new("/tmp/none"),
        "0.0.0.0:51820"
    )
    .is_err());
}

#[test]
fn a_bundle_splits_into_qr_frames() {
    let data = format!("{{\"version\":1,\"config\":\"{}\"}}", "x".repeat(2500));
    let state = qr::encode(&data, "/tmp/test.vallum-bundle").expect("encode");
    assert!(state.frames.len() > 1);
    assert!(state.frames.len() <= 16);
    let lines = qr::render(state.current()).expect("render");
    assert!(!lines.is_empty());
    let app = App::new(Vec::new());
    assert_eq!(app.selected, 0);
}

#[test]
fn lowercase_q_quits_dashboard() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = App::new(Vec::new());
    assert!(!app.quit);
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
    );
    assert!(app.quit);
}

#[test]
fn peer_removal_confirm_includes_peer_identity() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let peer = super::app::PeerView {
        name: "test-laptop".to_owned(),
        allowed_ips: vec!["10.7.0.5/32".to_owned()],
        fingerprint: "0123456789abcdef".to_owned(),
        ..super::app::PeerView::default()
    };
    let mut interface = super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/run/vallum/vallum0.sock"),
    );
    interface.set_device(DeviceView {
        interface: "vallum0".to_owned(),
        peers: vec![peer],
        ..DeviceView::default()
    });
    let mut app = App::new(vec![interface]);
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
    );
    assert!(app.confirm.is_some());
    if let Some(confirm) = &app.confirm {
        match &confirm.action {
            super::app::ConfirmAction::RemovePeer { index, label } => {
                assert_eq!(*index, 0);
                assert!(label.contains("test-laptop"));
                assert!(label.contains("10.7.0.5/32"));
            }
            _ => panic!("expected RemovePeer action"),
        }
    }
}

#[test]
fn peer_filtering_and_navigation() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let peer1 = super::app::PeerView {
        name: "alice-laptop".to_owned(),
        allowed_ips: vec!["10.7.0.2/32".to_owned()],
        ..super::app::PeerView::default()
    };
    let peer2 = super::app::PeerView {
        name: "bob-phone".to_owned(),
        allowed_ips: vec!["10.7.0.3/32".to_owned()],
        ..super::app::PeerView::default()
    };
    let mut interface = super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/run/vallum/vallum0.sock"),
    );
    interface.set_device(DeviceView {
        interface: "vallum0".to_owned(),
        peers: vec![peer1, peer2],
        ..DeviceView::default()
    });
    let mut app = App::new(vec![interface]);
    assert_eq!(app.filtered_peers().len(), 2);

    // Enter filter mode
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE),
    );
    assert!(app.filtering);

    // Type "bob"
    for c in ['b', 'o', 'b'] {
        super::input::handle(
            &mut app,
            KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE),
        );
    }
    assert_eq!(app.peer_filter, "bob");
    assert_eq!(app.filtered_peers().len(), 1);
    assert_eq!(
        app.current_peer().map(|p| p.name.as_str()),
        Some("bob-phone")
    );
    assert_eq!(app.current_peer_original_index(), Some(1));

    // Commit filter
    super::input::handle(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(!app.filtering);
    assert_eq!(app.filtered_peers().len(), 1);

    // Clear filter with Esc
    super::input::handle(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.peer_filter, "");
    assert_eq!(app.filtered_peers().len(), 2);

    // Type again and clear with Ctrl-U in filter mode
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE),
    );
    for c in ['a', 'l', 'i', 'c', 'e'] {
        super::input::handle(
            &mut app,
            KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE),
        );
    }
    assert_eq!(app.peer_filter, "alice");
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.peer_filter, "");
    assert_eq!(app.filtered_peers().len(), 2);
}

#[test]
fn forgiving_ip_prefix_format() {
    let prefixes =
        super::actions::parse_prefixes("10.7.0.2, 192.168.1.0/24 2001:db8::1").expect("parse");
    assert_eq!(prefixes.len(), 3);
    assert_eq!(prefixes[0].to_string(), "10.7.0.2/32");
    assert_eq!(prefixes[1].to_string(), "192.168.1.0/24");
    assert_eq!(prefixes[2].to_string(), "2001:db8::1/128");
}

#[test]
fn scrolling_in_logs_and_diff() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = App::new(Vec::new());
    app.view = super::app::View::Logs;
    app.logs = (0..50).map(|i| format!("log line {i}")).collect();

    assert_eq!(app.logs_scroll, 0);
    super::input::handle(&mut app, KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    assert_eq!(app.logs_scroll, 1);
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
    );
    assert_eq!(app.logs_scroll, 11);
    super::input::handle(&mut app, KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
    assert_eq!(app.logs_scroll, 10);
    super::input::handle(&mut app, KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
    assert_eq!(app.logs_scroll, 0);
}

#[test]
fn peer_sorting_cycles_and_orders() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let p_charlie = super::app::PeerView {
        name: "charlie".to_owned(),
        rx_bytes: 100,
        tx_bytes: 100,
        last_handshake: Some((1000, 0)),
        ..super::app::PeerView::default()
    };
    let p_alice = super::app::PeerView {
        name: "alice".to_owned(),
        rx_bytes: 500,
        tx_bytes: 500,
        last_handshake: Some((3000, 0)),
        ..super::app::PeerView::default()
    };
    let p_bob = super::app::PeerView {
        name: "bob".to_owned(),
        rx_bytes: 300,
        tx_bytes: 300,
        last_handshake: Some((2000, 0)),
        ..super::app::PeerView::default()
    };

    let mut interface = super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/run/vallum/vallum0.sock"),
    );
    interface.set_device(DeviceView {
        interface: "vallum0".to_owned(),
        peers: vec![p_charlie, p_alice, p_bob],
        ..DeviceView::default()
    });
    let mut app = App::new(vec![interface]);

    // Natural sort order (original order: charlie, alice, bob)
    assert_eq!(app.sort_mode, super::app::SortMode::Natural);
    let names: Vec<&str> = app
        .filtered_peers()
        .iter()
        .map(|p| p.1.name.as_str())
        .collect();
    assert_eq!(names, vec!["charlie", "alice", "bob"]);

    // Press 'o' -> RecentHandshake (most recent first: alice 3000, bob 2000, charlie 1000)
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE),
    );
    assert_eq!(app.sort_mode, super::app::SortMode::RecentHandshake);
    let names: Vec<&str> = app
        .filtered_peers()
        .iter()
        .map(|p| p.1.name.as_str())
        .collect();
    assert_eq!(names, vec!["alice", "bob", "charlie"]);

    // Press 'o' -> Transfer (highest total first: alice 1000, bob 600, charlie 200)
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE),
    );
    assert_eq!(app.sort_mode, super::app::SortMode::Transfer);
    let names: Vec<&str> = app
        .filtered_peers()
        .iter()
        .map(|p| p.1.name.as_str())
        .collect();
    assert_eq!(names, vec!["alice", "bob", "charlie"]);

    // Press 'o' -> Name (alphabetical: alice, bob, charlie)
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE),
    );
    assert_eq!(app.sort_mode, super::app::SortMode::Name);
    let names: Vec<&str> = app
        .filtered_peers()
        .iter()
        .map(|p| p.1.name.as_str())
        .collect();
    assert_eq!(names, vec!["alice", "bob", "charlie"]);

    // Press 'o' -> Natural again
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE),
    );
    assert_eq!(app.sort_mode, super::app::SortMode::Natural);
    let names: Vec<&str> = app
        .filtered_peers()
        .iter()
        .map(|p| p.1.name.as_str())
        .collect();
    assert_eq!(names, vec!["charlie", "alice", "bob"]);
}

#[test]
fn endpoint_missing_port_validation() {
    // Empty is ok (optional)
    assert_eq!(super::actions::parse_endpoint("").unwrap(), None);
    assert_eq!(super::actions::parse_endpoint("  ").unwrap(), None);

    // Missing port errors
    let err = super::actions::parse_endpoint("192.168.1.1").unwrap_err();
    assert!(err.contains("must include a port"));

    let err = super::actions::parse_endpoint("[2001:db8::1]").unwrap_err();
    assert!(err.contains("must include a port"));

    let err = super::actions::parse_endpoint("vpn.example.com").unwrap_err();
    assert!(err.contains("must include a port"));

    // Valid socket addresses succeed
    let endpoint = super::actions::parse_endpoint("192.168.1.1:51820").unwrap();
    assert_eq!(endpoint.unwrap().to_string(), "192.168.1.1:51820");

    let endpoint = super::actions::parse_endpoint("[2001:db8::1]:51820").unwrap();
    assert_eq!(endpoint.unwrap().to_string(), "[2001:db8::1]:51820");
}

#[test]
fn base64_rfc4648_test_vectors() {
    assert_eq!(super::actions::base64_encode(b""), "");
    assert_eq!(super::actions::base64_encode(b"f"), "Zg==");
    assert_eq!(super::actions::base64_encode(b"fo"), "Zm8=");
    assert_eq!(super::actions::base64_encode(b"foo"), "Zm9v");
    assert_eq!(super::actions::base64_encode(b"foob"), "Zm9vYg==");
    assert_eq!(super::actions::base64_encode(b"fooba"), "Zm9vYmE=");
    assert_eq!(super::actions::base64_encode(b"foobar"), "Zm9vYmFy");
}

#[test]
fn interface_rate_history_collects_samples() {
    let mut iface = super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/run/vallum/vallum0.sock"),
    );
    assert!(iface.rx_history.is_empty());

    let dev1 = super::app::DeviceView {
        interface: "vallum0".to_owned(),
        peers: vec![super::app::PeerView {
            rx_bytes: 1000,
            tx_bytes: 500,
            ..super::app::PeerView::default()
        }],
        ..super::app::DeviceView::default()
    };
    iface.set_device(dev1);

    let dev2 = super::app::DeviceView {
        interface: "vallum0".to_owned(),
        peers: vec![super::app::PeerView {
            rx_bytes: 2000,
            tx_bytes: 1000,
            ..super::app::PeerView::default()
        }],
        ..super::app::DeviceView::default()
    };
    iface.set_device(dev2);

    assert_eq!(iface.rx_history.len(), 1);
    assert_eq!(iface.tx_history.len(), 1);
}

#[test]
fn mouse_events_handle_scroll_and_click() {
    use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

    let p1 = super::app::PeerView {
        name: "peer1".to_owned(),
        ..super::app::PeerView::default()
    };
    let p2 = super::app::PeerView {
        name: "peer2".to_owned(),
        ..super::app::PeerView::default()
    };
    let mut iface = super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/run/vallum/vallum0.sock"),
    );
    iface.set_device(super::app::DeviceView {
        interface: "vallum0".to_owned(),
        peers: vec![p1, p2],
        ..super::app::DeviceView::default()
    });
    let mut app = App::new(vec![iface]);

    assert_eq!(app.peer_selected, 0);

    // Mouse scroll down selects next peer
    let scroll_down = MouseEvent {
        kind: MouseEventKind::ScrollDown,
        column: 10,
        row: 10,
        modifiers: crossterm::event::KeyModifiers::NONE,
    };
    super::input::handle_mouse(&mut app, scroll_down);
    assert_eq!(app.peer_selected, 1);

    // Mouse scroll up selects previous peer
    let scroll_up = MouseEvent {
        kind: MouseEventKind::ScrollUp,
        column: 10,
        row: 10,
        modifiers: crossterm::event::KeyModifiers::NONE,
    };
    super::input::handle_mouse(&mut app, scroll_up);
    assert_eq!(app.peer_selected, 0);

    // Mouse click on row 9 selects peer 1
    let click_row = MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 10,
        row: 9,
        modifiers: crossterm::event::KeyModifiers::NONE,
    };
    super::input::handle_mouse(&mut app, click_row);
    assert_eq!(app.peer_selected, 1);
}

#[test]
fn space_bar_invokes_toggle_service() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let iface = super::app::Interface::new(
        "vallum0".to_owned(),
        Some(std::path::PathBuf::from("/tmp/nonexistent.toml")),
        std::path::PathBuf::from("/run/vallum/vallum0.sock"),
    );
    let mut app = App::new(vec![iface]);
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE),
    );
    assert!(app.toast.is_some());
}

#[test]
fn bracketed_paste_inserts_text_into_active_form_field() {
    let mut app = App::new(Vec::new());
    app.form = Some(super::app::Form::add_peer());

    // Paste into first field (name)
    super::input::handle_paste(&mut app, "laptop-corp\r\n".to_owned());
    let form = app.form.as_ref().expect("form still open");
    assert_eq!(form.fields[0].value, "laptop-corp");
    assert_eq!(form.cursor, 11);

    // Paste additional text
    super::input::handle_paste(&mut app, "-01".to_owned());
    let form = app.form.as_ref().expect("form still open");
    assert_eq!(form.fields[0].value, "laptop-corp-01");
    assert_eq!(form.cursor, 14);
}

#[test]
fn bracketed_paste_appends_to_search_filter() {
    let mut app = App::new(Vec::new());
    app.filtering = true;

    super::input::handle_paste(&mut app, "staging-node\n".to_owned());
    assert_eq!(app.peer_filter, "staging-node");
}

#[test]
fn yank_peer_address_copies_allowed_ips() {
    let peer = super::app::PeerView {
        name: "worker".to_owned(),
        allowed_ips: vec!["10.7.0.99/32".to_owned()],
        ..super::app::PeerView::default()
    };
    let mut iface = super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/run/vallum/vallum0.sock"),
    );
    iface.set_device(DeviceView {
        interface: "vallum0".to_owned(),
        peers: vec![peer],
        ..DeviceView::default()
    });
    let mut app = App::new(vec![iface]);
    super::actions::yank_peer_address(&mut app);
    let toast = app.toast.expect("toast after yanking address");
    assert!(toast.message.contains("10.7.0.99/32"));
}

#[test]
fn import_bundle_form_defaults() {
    let form = super::app::Form::import_bundle("/etc/vallum");
    assert_eq!(form.fields.len(), 2);
    assert_eq!(form.fields[0].label, "bundle file");
    assert_eq!(form.fields[1].value, "/etc/vallum");
}

#[test]
fn vim_scroll_navigation_in_logs_help_and_diff() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = App::new(Vec::new());

    // 1. Logs view
    app.view = super::app::View::Logs;
    app.logs = (0..50).map(|i| format!("log line {i}")).collect();
    app.logs_scroll = 15;
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE),
    );
    assert_eq!(app.logs_scroll, 0);
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('G'), KeyModifiers::NONE),
    );
    assert_eq!(app.logs_scroll, 40);

    // 2. Help view
    app.view = super::app::View::Help;
    app.help_scroll = 5;
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE),
    );
    assert_eq!(app.help_scroll, 0);
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('G'), KeyModifiers::NONE),
    );
    assert_eq!(app.help_scroll, 100);

    // 3. Diff view
    app.view = super::app::View::Diff;
    app.diff = Some(super::app::DiffView {
        backup: std::path::PathBuf::from("/tmp/backup.toml"),
        rows: (0..30)
            .map(|i| super::app::DiffRow {
                left: Some(format!("left {i}")),
                right: Some(format!("right {i}")),
                kind: super::app::DiffKind::Equal,
            })
            .collect(),
    });
    app.diff_scroll = 8;
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE),
    );
    assert_eq!(app.diff_scroll, 0);
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('G'), KeyModifiers::NONE),
    );
    assert_eq!(app.diff_scroll, 20);
}

#[test]
fn smart_search_filter_freshness_and_psk() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let peer_recent = super::app::PeerView {
        name: "charlie".to_owned(),
        last_handshake: Some((now.saturating_sub(60), 0)),
        preshared_key: true,
        ..super::app::PeerView::default()
    };
    let peer_never = super::app::PeerView {
        name: "david".to_owned(),
        last_handshake: None,
        preshared_key: false,
        ..super::app::PeerView::default()
    };
    let mut iface = super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/run/vallum/vallum0.sock"),
    );
    iface.set_device(DeviceView {
        interface: "vallum0".to_owned(),
        peers: vec![peer_recent, peer_never],
        ..DeviceView::default()
    });
    let mut app = App::new(vec![iface]);

    // Match by freshness keyword "recent"
    app.peer_filter = "recent".to_owned();
    assert_eq!(app.filtered_peers().len(), 1);
    assert_eq!(app.filtered_peers()[0].1.name, "charlie");

    // Match by freshness keyword "never"
    app.peer_filter = "never".to_owned();
    assert_eq!(app.filtered_peers().len(), 1);
    assert_eq!(app.filtered_peers()[0].1.name, "david");

    // Match by "psk"
    app.peer_filter = "psk".to_owned();
    assert_eq!(app.filtered_peers().len(), 1);
    assert_eq!(app.filtered_peers()[0].1.name, "charlie");
}

#[test]
fn rate_label_scales_units_accurately() {
    assert_eq!(super::ui::rate_label(0.0), "0.0 B/s");
    assert_eq!(super::ui::rate_label(512.4), "512.4 B/s");
    assert_eq!(super::ui::rate_label(1024.0), "1.0 KB/s");
    assert_eq!(super::ui::rate_label(2560.0), "2.5 KB/s");
    assert_eq!(super::ui::rate_label(5.5 * 1024.0 * 1024.0), "5.5 MB/s");
    assert_eq!(
        super::ui::rate_label(1.5 * 1024.0 * 1024.0 * 1024.0),
        "1.5 GB/s"
    );
}

#[test]
fn ping_peer_handles_no_peer_or_no_ip_gracefully() {
    let mut app = App::new(Vec::new());
    super::actions::ping_peer(&mut app);
    assert!(app
        .toast
        .as_ref()
        .is_some_and(|t| t.message.contains("no peer selected")));

    let peer = super::app::PeerView {
        name: "test-peer".to_owned(),
        allowed_ips: Vec::new(),
        ..super::app::PeerView::default()
    };
    let mut iface = super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/run/vallum/vallum0.sock"),
    );
    iface.set_device(DeviceView {
        interface: "vallum0".to_owned(),
        peers: vec![peer],
        ..DeviceView::default()
    });
    let mut app = App::new(vec![iface]);
    super::actions::ping_peer(&mut app);
    assert!(app
        .toast
        .as_ref()
        .is_some_and(|t| t.message.contains("has no allowed IPs to ping")));
}

#[test]
fn question_mark_and_f1_open_help_and_return_to_the_dashboard() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = App::new(Vec::new());
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
    );
    assert_eq!(app.view, super::app::View::Help);
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
    );
    assert_eq!(app.view, super::app::View::Dashboard);

    super::input::handle(&mut app, KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE));
    assert_eq!(app.view, super::app::View::Help);
    super::input::handle(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.view, super::app::View::Dashboard);
}

#[test]
fn lowercase_r_refreshes_and_capital_r_toggles_auto_refresh() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = App::new(Vec::new());
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE),
    );
    assert!(app
        .toast
        .as_ref()
        .is_some_and(|toast| toast.message.contains("refreshed")));

    assert_eq!(app.refresh_rate, 1000);
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('R'), KeyModifiers::NONE),
    );
    assert_eq!(app.refresh_rate, 0);
    assert!(app
        .toast
        .as_ref()
        .is_some_and(|toast| toast.message.contains("auto-refresh off")));
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('R'), KeyModifiers::NONE),
    );
    assert_eq!(app.refresh_rate, 1000);
}

#[test]
fn long_form_values_render_as_a_single_line_window() {
    // A generated public line is ~800 chars; it must not push the remaining
    // fields, the hint, or the footer off the form.
    let long = format!("vallum1:0003:{}", "a".repeat(780));
    let short = super::ui::field_value_display(&long, 0, 40, false);
    assert_eq!(short.chars().count(), 40);
    assert!(short.ends_with('…'));

    // Focused, cursor at the start: the window begins at the value start.
    let focused_start = super::ui::field_value_display(&long, 0, 40, true);
    assert!(focused_start.starts_with("|vallum1:0003:"));
    assert!(focused_start.ends_with('…'));

    // Focused, cursor near the end: the window follows the cursor.
    let cursor = long.chars().count();
    let focused_end = super::ui::field_value_display(&long, cursor, 40, true);
    assert!(focused_end.starts_with('…'));
    assert!(focused_end.ends_with('|'));

    // UTF-8 values index by char, not byte.
    let utf8 = "héllo wörld";
    let display = super::ui::field_value_display(utf8, 2, 40, true);
    assert_eq!(display, "hé|llo wörld");
}

#[test]
fn colon_opens_the_command_palette_and_enter_runs_the_selected_action() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = App::new(Vec::new());
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE),
    );
    assert!(app.palette.is_some());

    // "qui" narrows to "quit"; Enter runs it without typing a binding.
    for c in ['q', 'u', 'i'] {
        super::input::handle(
            &mut app,
            KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE),
        );
    }
    let commands = super::keymap::matching_commands("qui");
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].action, super::keymap::Action::Quit);

    super::input::handle(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.quit);
    assert!(app.palette.is_none());
}

#[test]
fn palette_esc_closes_and_arrows_move_the_highlight() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = App::new(Vec::new());
    app.palette = Some(super::app::PaletteState::default());
    super::input::handle(&mut app, KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    assert_eq!(app.palette.as_ref().expect("palette open").selected, 1);
    super::input::handle(&mut app, KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
    assert_eq!(app.palette.as_ref().expect("palette open").selected, 0);
    super::input::handle(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.palette.is_none());
}

#[test]
fn palette_commands_match_names_and_keywords() {
    use super::keymap::{matching_commands, Action};

    assert_eq!(matching_commands("").len(), super::keymap::COMMANDS.len());
    assert_eq!(matching_commands("add peer")[0].action, Action::AddPeer);
    // Keyword hit: "reachability" is a keyword of "ping peer".
    let ping = matching_commands("reachab");
    assert_eq!(ping.len(), 1);
    assert_eq!(ping[0].action, Action::Ping);
    assert!(matching_commands("zzz-nothing").is_empty());
}

#[test]
fn keymap_overrides_rebind_unbind_and_warn_on_unknown_actions() {
    use super::keymap::{Action, KeyMap};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let dir = std::env::temp_dir().join(format!(
        "vallum-keymap-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("tui-keys.toml");
    std::fs::write(
        &path,
        "add_peer = \"n\"\nhelp = [\"F1\", \"h\"]\nquit = \"none\"\nbogus_action = \"z\"\n",
    )
    .expect("write keymap");

    let (map, warning) = KeyMap::load(Some(&path));
    let key = |c| KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE);
    // Rebound: 'n' adds a peer; the default 'a' no longer does.
    assert_eq!(map.action_for(&key('n')), Some(Action::AddPeer));
    assert_eq!(map.action_for(&key('a')), None);
    // Multi-binding override.
    assert_eq!(map.action_for(&key('h')), Some(Action::Help));
    assert_eq!(
        map.action_for(&KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE)),
        Some(Action::Help)
    );
    // '?' was replaced by the help override.
    assert_eq!(map.action_for(&key('?')), None);
    // Unbound: 'q' and 'Q' no longer quit.
    assert_eq!(map.action_for(&key('q')), None);
    // Untouched defaults survive.
    assert_eq!(map.action_for(&key('o')), Some(Action::Sort));
    let warning = warning.expect("warning for bogus_action");
    assert!(warning.contains("bogus_action"));

    // Bad TOML falls back to defaults with a warning.
    std::fs::write(&path, "not = [valid").expect("write bad keymap");
    let (map, warning) = KeyMap::load(Some(&path));
    assert!(warning.is_some());
    assert_eq!(map.action_for(&key('a')), Some(Action::AddPeer));

    // Missing file: defaults, no warning.
    let (map, warning) = KeyMap::load(Some(&dir.join("missing.toml")));
    assert_eq!(map.action_for(&key('a')), Some(Action::AddPeer));
    let _ = warning; // a missing --keys file warns but must not break defaults
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn clipboard_report_distinguishes_what_actually_happened() {
    use super::actions::clipboard_report;

    assert_eq!(clipboard_report(&[]), "no clipboard channel worked");
    let osc_only = clipboard_report(&["OSC 52"]);
    assert!(osc_only.contains("OSC 52"));
    assert!(!osc_only.starts_with("copied via"));
    assert_eq!(clipboard_report(&["wl-copy"]), "copied via wl-copy");
    assert_eq!(
        clipboard_report(&["OSC 52", "xclip"]),
        "copied via OSC 52 + xclip"
    );
}

#[test]
fn poll_ping_reports_results_and_survives_worker_loss() {
    let mut app = App::new(Vec::new());
    let (sender, receiver) = std::sync::mpsc::channel::<String>();
    app.pending_ping = Some(receiver);

    // No result yet: stays pending, no toast.
    app.poll_ping();
    assert!(app.pending_ping.is_some());
    assert!(app.toast.is_none());

    sender
        .send("ping 10.7.0.2: reply in 0.42 ms".to_owned())
        .expect("send");
    app.poll_ping();
    assert!(app.pending_ping.is_none());
    assert!(app
        .toast
        .as_ref()
        .is_some_and(|t| t.message.contains("reply in 0.42 ms")));

    // A dead worker is reported rather than hanging forever.
    let (sender, receiver) = std::sync::mpsc::channel::<String>();
    app.pending_ping = Some(receiver);
    drop(sender);
    app.poll_ping();
    assert!(app.pending_ping.is_none());
    assert!(app
        .toast
        .as_ref()
        .is_some_and(|t| t.message.contains("ping worker exited")));
}

#[test]
fn qr_render_packs_half_blocks_with_a_quiet_zone_and_fits_in_modal() {
    use ratatui::{backend::TestBackend, Terminal};

    let lines =
        qr::render("VALLUM1:1/1:e8a12c4b:{\"v\":1,\"iface\":\"vallum0\"}").expect("render qr");
    let cols = lines[0].chars().count();
    // 2 vertical modules per row -> rows == cols.div_ceil(2)
    assert_eq!(lines.len(), cols.div_ceil(2));
    // Top and bottom rows are inside the 2-module quiet zone -> solid '█' plate
    assert!(lines.first().unwrap().chars().all(|c| c == '█'));
    assert!(lines.last().unwrap().chars().all(|c| c == '█'));
    for line in &lines {
        assert!(line.starts_with("██"));
        assert!(line.ends_with("██"));
    }

    let mut app = App::new(Vec::new());
    app.qr = Some(qr::QrState {
        frames: vec!["VALLUM1:1/1:e8a12c4b:{\"v\":1,\"iface\":\"vallum0\"}".to_owned()],
        index: 0,
        last: std::time::Instant::now(),
        hash: "e8a12c4b".to_owned(),
        path: "/etc/vallum/client.vallum-bundle".to_owned(),
        kind: qr::QrKind::Bundle,
    });
    let mut terminal = Terminal::new(TestBackend::new(120, 32)).expect("test terminal");
    terminal
        .draw(|frame| super::ui::draw(frame, &app))
        .expect("draw qr modal");
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("OPTICAL CLIENT PROVISIONING"));
    assert!(text.contains("SECRET MATERIAL"));
    assert!(text.contains("e8a12c4b"));
    assert!(text.contains("vallum import-bundle /etc/vallum/client.vallum-bundle"));
}

#[test]
fn peer_fingerprint_falls_back_to_public_line_when_omitted_by_uapi() {
    let response = Response {
        device: vec![("vallum_interface".to_owned(), "vallum0".to_owned())],
        peers: vec![vec![
            ("vallum_name".to_owned(), "gateway-us-east".to_owned()),
            (
                "vallum_public_line".to_owned(),
                "vallum1:0003:8b7e6d5c4b3a2918:AQIDBA==".to_owned(),
            ),
        ]],
    };
    let device = DeviceView::from_response(&response);
    assert_eq!(device.peers[0].fingerprint, "8b7e6d5c4b3a2918");
}

#[test]
fn palette_window_stays_anchored_on_first_page_and_matches_categories() {
    use super::keymap::{matching_commands, window_start, Action};

    assert_eq!(window_start(28, 0, 14), 0);
    assert_eq!(window_start(28, 3, 14), 0);
    assert_eq!(window_start(28, 13, 14), 0);
    assert_eq!(window_start(28, 14, 14), 1);
    assert_eq!(window_start(28, 27, 14), 14);

    // A "BUNDLE" search also finds the client-setup command by keyword, which
    // is the point of keywords; the category itself has exactly two members.
    let bundle_cmds: Vec<_> = matching_commands("BUNDLE")
        .into_iter()
        .filter(|command| command.category == "BUNDLE")
        .collect();
    assert_eq!(bundle_cmds.len(), 2);
    assert_eq!(bundle_cmds[0].action, Action::ExportBundle);
    assert_eq!(bundle_cmds[1].action, Action::ImportBundle);
    assert!(matching_commands("BUNDLE")
        .iter()
        .any(|command| command.action == Action::SetupClient));
}

#[test]
fn fitts_law_footer_and_header_clicks_trigger_actions_and_palette_accepts_paste() {
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

    let mut app = App::new(Vec::new());
    // Bottom-left `: commands` pill on row 30 (height 32 -> nav row is 30)
    super::input::handle_mouse_at(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 4,
            row: 30,
            modifiers: KeyModifiers::NONE,
        },
        (120, 32),
    );
    assert!(app.palette.is_some());

    // Paste into open palette
    super::input::handle_paste(&mut app, "add peer\n".to_owned());
    assert_eq!(
        app.palette.as_ref().map(|p| p.input.as_str()),
        Some("add peer")
    );
    app.palette = None;

    // Click 'a add' capsule on action row 31 ("Space toggle  " is 14 cols -> 'a add' starts at 14)
    super::input::handle_mouse_at(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 15,
            row: 31,
            modifiers: KeyModifiers::NONE,
        },
        (120, 32),
    );
    assert!(app.form.is_some());
    app.form = None;

    // Header row-1 interface tab click accounts for the status badge width
    let iface0 = super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/run/vallum/vallum0.sock"),
    );
    let iface1 = super::app::Interface::new(
        "vallum1".to_owned(),
        None,
        std::path::PathBuf::from("/run/vallum/vallum1.sock"),
    );
    let mut app = App::new(vec![iface0, iface1]);
    assert_eq!(app.selected, 0);
    // Badge " ◌ NO UNIT " (11) + " " (1) + " [1/2] vallum0 " (15) -> tab 1 starts at col 13, tab 2 at col 28
    super::input::handle_mouse_at(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 30,
            row: 1,
            modifiers: KeyModifiers::NONE,
        },
        (120, 32),
    );
    assert_eq!(app.selected, 1);
}

#[test]
fn an_expiring_identity_and_an_open_rotation_are_visible_in_the_detail_pane() {
    use ratatui::{backend::TestBackend, Terminal};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    // An hour of slack: at exactly 14 days, one second of clock movement
    // between building the response and drawing it truncates to "13d left".
    let expires = now + 14 * 86_400 + 3_600;
    let response = crate::uapi::parse_response(&format!(
        "vallum_interface=vallum0\n\
         vallum_suite=0x0003\n\
         vallum_listen=0.0.0.0:51820\n\
         errno=0\n\
         \n\
         public_key=aa\n\
         vallum_name=laptop\n\
         vallum_fingerprint=f1e20541fb69\n\
         vallum_valid_until={expires}\n\
         vallum_rotating=1\n\
         rx_bytes=10\n\
         tx_bytes=20\n\
         vallum_epoch=1\n\
         errno=0\n"
    ));

    let mut iface = super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/run/vallum/vallum0.sock"),
    );
    iface.set_device(DeviceView::from_response(&response));
    assert_eq!(
        iface.device.as_ref().unwrap().peers[0].valid_until,
        Some(expires)
    );
    assert!(iface.device.as_ref().unwrap().peers[0].rotating);
    let app = App::new(vec![iface]);

    let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("test terminal");
    terminal
        .draw(|frame| super::ui::draw(frame, &app))
        .expect("draw");
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("14d left"), "the window is not shown: {text}");
    // The pane wraps, so match the label and the start of the value.
    assert!(
        text.contains("rotation    open"),
        "an open rotation is not shown; buffer:\n{text}"
    );
}

#[test]
fn the_first_screen_asks_what_the_machine_is_and_shows_both_commands() {
    use ratatui::{backend::TestBackend, Terminal};

    let app = App::new(Vec::new());
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("test terminal");
    terminal
        .draw(|frame| super::ui::draw(frame, &app))
        .expect("draw empty state");
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();

    assert!(text.contains("What is this machine?"), "{text}");
    assert!(text.contains("The server"), "no server role");
    assert!(text.contains("The client"), "no client role");
    assert!(text.contains("vallum setup --server"), "no server command");
    assert!(
        text.contains("vallum join") && text.contains("--remote"),
        "no client command: {text}"
    );
}

#[test]
fn the_numbered_roles_open_the_setup_forms() {
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = App::new(Vec::new());
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE),
    );
    assert!(
        matches!(
            app.form.as_ref().map(|f| f.kind),
            Some(super::app::FormKind::SetupServer)
        ),
        "role 1 opens the server form"
    );

    let mut app = App::new(Vec::new());
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE),
    );
    assert!(
        matches!(
            app.form.as_ref().map(|f| f.kind),
            Some(super::app::FormKind::JoinNetwork)
        ),
        "role 2 opens the join form"
    );
}

#[test]
fn the_palette_offers_both_setup_roles() {
    let names: Vec<&str> = super::keymap::COMMANDS.iter().map(|c| c.name).collect();
    assert!(names.iter().any(|name| name.contains("server")));
    assert!(names.iter().any(|name| name.contains("join a network")));
    // Category badges must not collide with an existing one.
    let categories: Vec<&str> = super::keymap::COMMANDS.iter().map(|c| c.category).collect();
    assert!(categories.contains(&"SETUP"));
}

#[test]
fn invite_form_collects_name_ttl_and_optional_pin() {
    let form = Form::invite_peer();
    assert_eq!(form.fields.len(), 4);
    assert_eq!(form.field("name"), "");
    assert_eq!(form.field("TTL (minutes)"), "15");
    assert_eq!(form.field("pinned public line"), "");
    assert_eq!(form.field("remote SSH (optional)"), "");
    // The pinned field must not be masked — it is a public line, not a secret.
    assert!(!form.fields[2].masked);
}

#[test]
fn invite_qr_modal_says_one_time_and_no_private_key() {
    use ratatui::{backend::TestBackend, Terminal};

    let command = "sudo vallum join vallum1-join:203.0.113.10:51821/laptop/\
                   f19e9b24b97a687e4b3a7a1bdc16aaed/\
                   aaaa-bbbb-cccc-dddd-eeee-ffff-0000-1111/afa1f7be2ef6";
    let state =
        qr::encode_invite(command, "/run/vallum/enroll-laptop.json").expect("invite encodes");
    assert_eq!(state.kind, qr::QrKind::Invite);

    let mut app = App::new(Vec::new());
    app.qr = Some(state);
    let mut terminal = Terminal::new(TestBackend::new(160, 48)).expect("test terminal");
    terminal
        .draw(|frame| super::ui::draw(frame, &app))
        .expect("draw invite modal");
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("ONE-TIME ENROLMENT INVITE"));
    assert!(text.contains("ZERO PRIVATE KEYS"));
    assert!(!text.contains("SECRET MATERIAL"));
}

#[test]
fn v_opens_the_invite_form_and_k_opens_rotation() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = App::new(Vec::new());
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE),
    );
    assert!(matches!(
        app.form.as_ref().map(|f| f.kind),
        Some(super::app::FormKind::InvitePeer)
    ));
    app.form = None;

    // K needs a selected peer.
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('K'), KeyModifiers::NONE),
    );
    assert!(app.form.is_none());
    let device = DeviceView {
        interface: "vallum0".to_owned(),
        peers: vec![super::app::PeerView {
            name: "laptop".to_owned(),
            ..super::app::PeerView::default()
        }],
        ..DeviceView::default()
    };
    let mut app = App::new(Vec::new());
    app.interfaces.push(super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/run/vallum/vallum0.sock"),
    ));
    app.interfaces[0].device = Some(device);
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('K'), KeyModifiers::NONE),
    );
    assert!(matches!(
        app.form.as_ref().map(|f| f.kind),
        Some(super::app::FormKind::RotatePeer(0))
    ));
}

#[test]
fn f_only_confirms_finalize_when_a_rotation_is_open() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = App::new(Vec::new());
    app.interfaces.push(super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/run/vallum/vallum0.sock"),
    ));
    app.interfaces[0].device = Some(DeviceView {
        interface: "vallum0".to_owned(),
        peers: vec![super::app::PeerView {
            name: "laptop".to_owned(),
            rotating: false,
            ..super::app::PeerView::default()
        }],
        ..DeviceView::default()
    });
    // Not rotating: f must not open the destructive confirm.
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('f'), KeyModifiers::NONE),
    );
    assert!(app.confirm.is_none());

    app.interfaces[0].device.as_mut().expect("device").peers[0].rotating = true;
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('f'), KeyModifiers::NONE),
    );
    assert!(matches!(
        app.confirm.as_ref().map(|c| &c.action),
        Some(super::app::ConfirmAction::FinalizePeer { name }) if name == "laptop"
    ));
}

#[test]
fn device_view_parses_loop_stats_and_stays_honest_when_absent() {
    let with = Response {
        device: vec![
            ("vallum_interface".to_owned(), "vallum0".to_owned()),
            ("vallum_datagrams_sent".to_owned(), "42".to_owned()),
            ("vallum_datagrams_failed".to_owned(), "1".to_owned()),
            ("vallum_packets_delivered".to_owned(), "7".to_owned()),
            ("vallum_packets_failed".to_owned(), "0".to_owned()),
            ("vallum_handshakes_established".to_owned(), "3".to_owned()),
            ("vallum_handshakes_refused".to_owned(), "2".to_owned()),
            ("vallum_reassembled".to_owned(), "5".to_owned()),
            ("vallum_fragments_dropped".to_owned(), "4".to_owned()),
        ],
        peers: Vec::new(),
    };
    let device = DeviceView::from_response(&with);
    let stats = device.stats.expect("stats parsed");
    assert_eq!(stats.datagrams_sent, 42);
    assert_eq!(stats.refusals, 2);
    assert_eq!(stats.fragments_dropped, 4);

    // Partial telemetry is unknown, not a row of confident zeros.
    let partial = Response {
        device: vec![
            ("vallum_interface".to_owned(), "vallum0".to_owned()),
            ("vallum_datagrams_sent".to_owned(), "42".to_owned()),
        ],
        peers: Vec::new(),
    };
    assert!(DeviceView::from_response(&partial).stats.is_none());
}

/// Serialises tests that change the process environment.
static NO_COLOR_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Restores the environment when the guard drops.
struct NoColorEnv;

impl NoColorEnv {
    fn set() -> Self {
        std::env::set_var("NO_COLOR", "1");
        Self
    }
}

impl Drop for NoColorEnv {
    fn drop(&mut self) {
        std::env::remove_var("NO_COLOR");
    }
}

/// `NO_COLOR` must apply to the frame, not just to the tokens: one literal
/// `Color::` anywhere in the render path silently re-colours the screen for an
/// operator who asked for no colour. This asserts the whole buffer, so the next
/// hard-coded colour fails here instead of on someone's terminal.
#[test]
fn no_color_dashboard_renders_without_ansi_colour() {
    use ratatui::style::Color;
    use ratatui::{backend::TestBackend, Terminal};

    let _lock = NO_COLOR_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _env = NoColorEnv::set();

    let mut interface = super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/run/vallum/vallum0.sock"),
    );
    interface.set_device(DeviceView {
        interface: "vallum0".to_owned(),
        listen: "[::]:51820".to_owned(),
        suite: "0x0003".to_owned(),
        fingerprint: "0011223344556677".to_owned(),
        offload: true,
        peers: vec![super::app::PeerView {
            name: "build-runner".to_owned(),
            fingerprint: "8899aabbccddeeff".to_owned(),
            endpoint: "192.0.2.24:51820".to_owned(),
            allowed_ips: vec!["10.7.0.2/32".to_owned()],
            keepalive: Some(25),
            tx_bytes: 72_000,
            rx_bytes: 543_210,
            epoch: 2,
            preshared_key: true,
            ..super::app::PeerView::default()
        }],
        ..DeviceView::default()
    });
    interface.set_service_state(Some(super::app::ServiceState::Active));
    let dashboard = App::new(vec![interface]);
    let empty = App::new(Vec::new());

    let mut qr_app = App::new(Vec::new());
    qr_app.qr = Some(qr::QrState {
        frames: vec![
            "VALLUM1:1/1:afa1f7be:sudo vallum join vallum1-join:198.51.100.10:51821/n/charlie"
                .to_owned(),
        ],
        index: 0,
        last: std::time::Instant::now(),
        hash: "afa1f7be".to_owned(),
        path: "/run/vallum/enroll-vallum0-f19e9b24.json".to_owned(),
        kind: qr::QrKind::Invite,
    });

    for (name, app) in [("dashboard", dashboard), ("empty", empty), ("qr", qr_app)] {
        let mut terminal = Terminal::new(TestBackend::new(120, 36)).expect("test terminal");
        terminal
            .draw(|frame| super::ui::draw(frame, &app))
            .expect("draw view");
        let buffer = terminal.backend().buffer();
        for (index, cell) in buffer.content().iter().enumerate() {
            if cell.symbol().trim().is_empty() {
                continue;
            }
            assert_eq!(
                cell.fg,
                Color::Reset,
                "{name}: cell {index} sets a foreground colour under NO_COLOR"
            );
            assert_eq!(
                cell.bg,
                Color::Reset,
                "{name}: cell {index} sets a background colour under NO_COLOR"
            );
        }
    }
}

/// The render module takes every colour from `theme()`.
///
/// A literal in `ui.rs` is how the `NO_COLOR` guarantee dies: the buffer test
/// above only covers the views it draws, while a stray `Color::Red` on an
/// error path reaches a user who asked for no colour at all. The scan is
/// textual, and it skips comment-only lines, so documenting the rule is still
/// allowed — adding a new render module means adding it to this list.
#[test]
fn render_path_takes_every_colour_from_the_theme() {
    const UI: &str = include_str!("ui.rs");

    let literals: Vec<String> = UI
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
        .filter(|(_, line)| line.contains("Color::"))
        .map(|(index, line)| format!("ui.rs:{}: {}", index + 1, line.trim()))
        .collect();

    assert!(
        literals.is_empty(),
        "the TUI render path must take colours from theme(), not from literals:\n{}",
        literals.join("\n")
    );
}

#[test]
fn trial_plan_opens_the_trial_view_with_host_status() {
    use ratatui::{backend::TestBackend, Terminal};

    let mut app = App::new(Vec::new());
    super::actions::trial_plan(&mut app);
    assert_eq!(app.view, super::app::View::Trial);
    assert!(!app.trial_lines.is_empty());
    let joined = app.trial_lines.join("\n");
    assert!(joined.contains("FULL-TUNNEL TRIAL"));
    // With or without the dispatcher installed, the plan names the commands.
    assert!(joined.contains("vallum-ops"));

    let mut terminal = Terminal::new(TestBackend::new(120, 30)).expect("test terminal");
    terminal
        .draw(|frame| super::ui::draw(frame, &app))
        .expect("draw trial view");
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("FULL-TUNNEL TRIAL"));
}

#[test]
fn trial_commands_are_palette_only_with_no_global_keys() {
    let app = App::new(Vec::new());
    // A global key that reroutes all host traffic is the loaded-key class the
    // GUI removed; the TRIAL view's own `a`/`p` arm and panic once it is open.
    assert!(app
        .keymap
        .keys_for(super::keymap::Action::TrialPlan)
        .is_empty());
    assert!(app
        .keymap
        .keys_for(super::keymap::Action::TrialRevert)
        .is_empty());
    let names: Vec<&str> = super::keymap::matching_commands("trial")
        .iter()
        .map(|command| command.name)
        .collect();
    assert!(names.contains(&"preview full-tunnel trial…"));
    assert!(names.contains(&"revert full-tunnel trial (panic)"));
}

#[test]
fn trial_view_arms_and_panics_from_its_own_keys() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = App::new(Vec::new());
    super::actions::trial_plan(&mut app);
    // `a` arms: unprivileged hands `sudo vallum-ops full-tunnel` over, root
    // runs it and lands back on the verdict view either way.
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE),
    );
    assert!(
        app.toast
            .as_ref()
            .is_some_and(|toast| toast.message.contains("vallum-ops full-tunnel"))
            || app.view == super::app::View::Trial
    );
    // `p` panics back to split under the same privilege rule.
    super::actions::trial_plan(&mut app);
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE),
    );
    assert!(
        app.toast
            .as_ref()
            .is_some_and(|toast| toast.message.contains("vallum-ops revert"))
            || app.view == super::app::View::Trial
    );
    // Esc leaves the trial view.
    super::input::handle(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.view, super::app::View::Dashboard);
}

#[test]
fn health_verdict_matches_the_gui_sentence() {
    use super::health::{verdict, HealthFacts, Level};

    let mut facts = HealthFacts {
        interface: "vallum0".to_owned(),
        unit: "vallum@vallum0".to_owned(),
        route4: Some("wlp0s20f3".to_owned()),
        dns: vec!["127.0.0.53".to_owned()],
        guard_active: "inactive".to_owned(),
        quick_active: "inactive".to_owned(),
        unit_active: "inactive".to_owned(),
        interface_present: true,
        ..HealthFacts::default()
    };
    // Split by design reads SPLIT in amber, never red.
    let (label, _, level) = verdict(&facts);
    assert_eq!(label, "SPLIT");
    assert_eq!(level, Level::Warn);
    // The same host with a full-tunnel config and no tunnel reads as a fault.
    facts.expected_full = true;
    let (label, detail, level) = verdict(&facts);
    assert_eq!(label, "UNPROTECTED");
    assert!(detail.contains("vallum@vallum0 is inactive"));
    assert_eq!(level, Level::Fail);
    // Unit up but no route names the missing route instead.
    facts.unit_active = "active".to_owned();
    let (label, detail, level) = verdict(&facts);
    assert_eq!(label, "UNPROTECTED");
    assert!(detail.contains("no default route through vallum0"));
    assert_eq!(level, Level::Fail);
    // Route via the tunnel with a real DNS upstream is protected.
    facts.route4 = Some("vallum0".to_owned());
    facts.dns_upstream = vec!["10.7.0.1".to_owned()];
    let (label, _, level) = verdict(&facts);
    assert_eq!(label, "PROTECTED");
    assert_eq!(level, Level::Ok);
    // The same route with only the local stub leaks DNS.
    facts.dns_upstream.clear();
    facts.dns = vec!["127.0.0.53".to_owned()];
    let (label, detail, level) = verdict(&facts);
    assert_eq!(label, "DNS LEAK");
    assert!(detail.contains("127.0.0.53"));
    assert_eq!(level, Level::Fail);
    // Guard on but nothing tunnelled is unprotected, not split.
    facts.route4 = Some("wlp0s20f3".to_owned());
    facts.guard_active = "active".to_owned();
    facts.expected_full = false;
    let (label, _, level) = verdict(&facts);
    assert_eq!(label, "UNPROTECTED");
    assert_eq!(level, Level::Fail);
}

#[test]
fn health_check_opens_the_health_view_from_h_or_palette() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::{backend::TestBackend, Terminal};

    let interface = super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/run/vallum/vallum0.sock"),
    );
    let mut app = App::new(vec![interface]);
    // `H` opens the check from the dashboard.
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('H'), KeyModifiers::NONE),
    );
    assert_eq!(app.view, super::app::View::Health);
    // The measurement degrades to unknown rows where the tools are missing;
    // it never fails to render.
    assert!(!app.health_lines.is_empty());
    assert!(app.health_lines[0].contains(" — "));

    let mut terminal = Terminal::new(TestBackend::new(120, 30)).expect("test terminal");
    terminal
        .draw(|frame| super::ui::draw(frame, &app))
        .expect("draw health view");
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("EGRESS HEALTH"));

    // The palette reaches the same action by keyword.
    let names: Vec<&str> = super::keymap::matching_commands("health")
        .iter()
        .map(|command| command.name)
        .collect();
    assert!(names.contains(&"egress health check"));

    // `r` re-measures, Esc leaves.
    super::input::handle(
        &mut app,
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE),
    );
    assert_eq!(app.view, super::app::View::Health);
    super::input::handle(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.view, super::app::View::Dashboard);
}

#[test]
fn colliding_interface_names_carry_their_socket_origin() {
    use ratatui::{backend::TestBackend, Terminal};

    // An explicit --control plus the runtime dir's own socket for the same
    // interface: the poll renames both tabs to the daemon's name, so without
    // the origin suffix the header shows two identical tabs.
    let first = super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/tmp/a/vallum0.sock"),
    );
    let second = super::app::Interface::new(
        "vallum0".to_owned(),
        None,
        std::path::PathBuf::from("/tmp/b/vallum0.sock"),
    );
    let app = App::new(vec![first, second]);

    let mut terminal = Terminal::new(TestBackend::new(120, 30)).expect("test terminal");
    terminal
        .draw(|frame| super::ui::draw(frame, &app))
        .expect("draw dashboard");
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("[1/2] vallum0"));
    assert!(text.contains("[2/2] vallum0"));
    assert!(text.contains("· a "));
    assert!(text.contains("· b "));
}
