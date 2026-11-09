//! `--serve`: the console over localhost HTTP.
//!
//! The Tauri window is one transport for this UI, not the product. On a machine
//! whose WebKitGTK cannot load pages, a browser tab against a local HTTP bridge
//! is the same console: same commands, same control socket, same payloads.
//! Hand-rolled on `std` deliberately — a localhost, loopback-only, alpha-grade
//! server does not need a framework, and the workspace stays dependency-light.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::{Console, InterfaceEntry, Payload};

const CONTENT_TYPES: &[(&str, &str)] = &[
    ("html", "text/html; charset=utf-8"),
    ("js", "text/javascript; charset=utf-8"),
    ("css", "text/css; charset=utf-8"),
    ("svg", "image/svg+xml"),
    ("png", "image/png"),
    ("json", "application/json"),
    ("ico", "image/x-icon"),
];

pub fn serve(port: u16, ui_dir: PathBuf, console: Arc<Console>) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|error| format!("cannot bind 127.0.0.1:{port}: {error}"))?;
    eprintln!(
        "vallum-gui: serving the console at http://127.0.0.1:{port} (ui from {})",
        ui_dir.display()
    );
    for stream in listener.incoming().flatten() {
        let console = Arc::clone(&console);
        let ui_dir = ui_dir.clone();
        std::thread::spawn(move || {
            let _ = handle(stream, &console, &ui_dir);
        });
    }
    Ok(())
}

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();

    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).ok()? == 0 {
            break;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).ok()?;
    }
    Some(Request { method, path, body })
}

fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}

fn json(stream: &mut TcpStream, status: &str, value: &serde_json::Value) {
    respond(stream, status, "application/json", value.to_string().as_bytes());
}

fn handle(mut stream: TcpStream, console: &Arc<Console>, ui_dir: &Path) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let Some(request) = read_request(&mut stream) else {
        return Ok(());
    };

    // SSE stream: one snapshot per second, straight from the control socket.
    if request.path == "/api/stream" {
        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                    Cache-Control: no-store\r\nConnection: keep-alive\r\n\r\n";
        stream.write_all(head.as_bytes())?;
        loop {
            let payload = match console.current_socket() {
                Some(path) => match crate::snapshot::fetch(&path) {
                    Ok(data) => Payload {
                        ok: true,
                        error: None,
                        data: Some(data),
                    },
                    Err(error) => Payload {
                        ok: false,
                        error: Some(error),
                        data: None,
                    },
                },
                None => Payload {
                    ok: false,
                    error: Some("no interface selected".to_owned()),
                    data: None,
                },
            };
            let frame = format!("data: {}\n\n", serde_json::to_string(&payload).unwrap_or_default());
            if stream.write_all(frame.as_bytes()).is_err() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    if request.path == "/api/interfaces" {
        let entries: Vec<InterfaceEntry> = crate::interfaces();
        json(
            &mut stream,
            "200 OK",
            &serde_json::to_value(entries).unwrap_or_default(),
        );
        return Ok(());
    }

    if request.path == "/api/select" {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
        if let Some(path) = body.get("path").and_then(|v| v.as_str()) {
            crate::select_path(console, path.to_owned());
            json(&mut stream, "200 OK", &serde_json::json!({ "ok": true }));
        } else {
            json(&mut stream, "400 Bad Request", &serde_json::json!({ "error": "path" }));
        }
        return Ok(());
    }

    if let Some(name) = request.path.strip_prefix("/api/cmd/") {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
        let outcome = crate::dispatch(console, name, body);
        match outcome {
            Ok(done) => json(&mut stream, "200 OK", &serde_json::to_value(done).unwrap_or_default()),
            Err(error) => json(&mut stream, "400 Bad Request", &serde_json::json!({ "error": error })),
        }
        return Ok(());
    }

    // Static files from the UI directory; `/` is index.html.
    let relative = request.path.split('?').next().unwrap_or("/");
    let relative = if relative == "/" { "/index.html" } else { relative };
    if relative.contains("..") {
        respond(&mut stream, "400 Bad Request", "text/plain", b"bad path");
        return Ok(());
    }
    let file = ui_dir.join(relative.trim_start_matches('/'));
    match std::fs::read(&file) {
        Ok(bytes) => {
            let extension = file
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or_default();
            let content_type = CONTENT_TYPES
                .iter()
                .find(|(ext, _)| *ext == extension)
                .map_or("application/octet-stream", |(_, ty)| *ty);
            respond(&mut stream, "200 OK", content_type, &bytes);
        }
        Err(_) => respond(&mut stream, "404 Not Found", "text/plain", b"not found"),
    }
    Ok(())
}
