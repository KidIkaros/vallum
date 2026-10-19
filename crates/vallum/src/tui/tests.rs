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
