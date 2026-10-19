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
            ("vallum_epoch".to_owned(), "3".to_owned()),
        ]],
    };
    let device = DeviceView::from_response(&response);
    assert_eq!(device.interface, "vallum0");
    assert_eq!(device.suite_id, 3);
    assert!(device.batching);
    assert_eq!(device.peers[0].name, "laptop");
    assert_eq!(device.peers[0].allowed_ips, vec!["10.7.0.2/32"]);
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
    assert!(text.contains("No Vallum interface found"));
    assert!(text.contains("vallum-quick up"));
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
    assert!(text.contains("Vallum / TUNNEL CONTROL"));
    assert!(text.contains("offload on"));
    assert!(text.contains("UDP batching off"));
    assert!(text.contains("CONTROL LIVE"));
    assert!(text.contains("systemd active"));
    assert!(!text.contains("can_set"));
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
    assert!(text.contains("Peers (stale snapshot)"));
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
