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

/// The largest request body the console will read.
///
/// The console's own bodies are a few hundred bytes of JSON. The cap exists
/// so that a request's own Content-Length cannot order an allocation before
/// anything has been authenticated.
const MAX_BODY: usize = 64 * 1024;

/// The cookie the console's session is carried in.
const COOKIE: &str = "vallum-console";

/// A token for this console run.
///
/// The console is the only way an unprivileged user can read their own
/// protection state: the control socket is 0600 root and the config is
/// unreadable to them. That makes it the verdict surface - and a verdict
/// surface that any web page can drive is not a verdict surface, it is a
/// remote control.
///
/// So the console is authenticated: the operator's terminal prints a URL with
/// a token in it, the first request exchanges the token for a cookie, and
/// every later request must present the cookie. The token is in the URL
/// because the operator has to be able to click a link; it is exchanged for a
/// cookie immediately so it does not stay in the address bar, the history, or
/// a Referer header.
fn new_token() -> String {
    let bytes = vallum::entropy::seed();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Whether this request may touch the console.
///
/// Two independent checks, because they stop different attacks:
///
/// * the **Host** header must name the loopback. A page that rebinds a
///   hostname to 127.0.0.1 sends its own hostname, and this is what stops
///   it - without the check, a rebind makes the browser treat the console as
///   same-origin and read every answer.
/// * the **cookie** must carry this run's token. Without it, any page the
///   user opens can POST to the console: the kill switch, the apply, the
///   peer verbs.
fn authorized(request: &Request, port: u16, token: &str) -> bool {
    let host_ok = request.header("host").is_some_and(|host| {
        let host = host.split(',').next().unwrap_or(host).trim();
        host == "127.0.0.1" || host == "localhost" || host.ends_with(&format!(":{port}"))
    });
    if !host_ok {
        return false;
    }
    request.cookie(COOKIE) == Some(token)
}

/// The response that hands the browser its cookie and clears the token from
/// the address bar.
fn exchange(stream: &mut TcpStream, token: &str) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 302 Found\r\nLocation: /\r\nSet-Cookie: {COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes())
}

pub fn serve(port: u16, ui_dir: PathBuf, console: Arc<Console>) -> Result<(), String> {
    let token = new_token();
    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|error| format!("cannot bind 127.0.0.1:{port}: {error}"))?;
    eprintln!(
        "vallum-gui: serving the console at http://127.0.0.1:{port}/?token={token} (ui from {})",
        ui_dir.display()
    );
    for stream in listener.incoming().flatten() {
        let console = Arc::clone(&console);
        let ui_dir = ui_dir.clone();
        let token = token.clone();
        std::thread::spawn(move || {
            let _ = handle(stream, &console, &ui_dir, &token, port);
        });
    }
    Ok(())
}

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The value of a query parameter, if the path has one.
    fn query(&self, key: &str) -> Option<&str> {
        let (_, query) = self.path.split_once('?')?;
        query.split('&').find_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            (name == key).then_some(value)
        })
    }

    /// The value of a cookie, if the request has one.
    fn cookie(&self, name: &str) -> Option<&str> {
        self.header("cookie")?.split(';').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key.trim() == name).then_some(value.trim())
        })
    }
}

fn read_request<R: std::io::Read>(stream: &mut R) -> Option<Request> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();

    let mut content_length = 0usize;
    let mut headers = Vec::new();
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
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    // The cap comes BEFORE the allocation. The body used to be sized straight
    // from the request's own Content-Length, so one header pre-authenticating
    // nothing - the token exchange happens later - ordered a four-gigabyte
    // buffer. The console's bodies are a few hundred bytes of JSON; 64 KiB is
    // generous, and anything past it is dropped rather than read.
    if content_length > MAX_BODY {
        return None;
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).ok()?;
    }
    Some(Request {
        method,
        path,
        body,
        headers,
    })
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
    respond(
        stream,
        status,
        "application/json",
        value.to_string().as_bytes(),
    );
}

fn handle(
    mut stream: TcpStream,
    console: &Arc<Console>,
    ui_dir: &Path,
    token: &str,
    port: u16,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let Some(request) = read_request(&mut stream) else {
        return Ok(());
    };

    // The exchange: the request that carries the token gets the cookie, and
    // the token leaves the address bar.
    if request.query("token") == Some(token) {
        return exchange(&mut stream, token);
    }
    // Everything else needs the cookie and a loopback Host.
    if !authorized(&request, port, token) {
        respond(
            &mut stream,
            "403 Forbidden",
            "text/plain; charset=utf-8",
            b"this console needs the token from the terminal that started it",
        );
        return Ok(());
    }

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
            let frame = format!(
                "data: {}\n\n",
                serde_json::to_string(&payload).unwrap_or_default()
            );
            if stream.write_all(frame.as_bytes()).is_err() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    if request.path == "/api/panic" && request.method == "POST" {
        if let Some(socket) = console.known_socket() {
            if let Err(error) = crate::write_gate(&socket) {
                json(
                    &mut stream,
                    "403 Forbidden",
                    &serde_json::json!({ "error": error }),
                );
                return Ok(());
            }
        }
        match crate::panic() {
            Ok(done) => json(
                &mut stream,
                "200 OK",
                &serde_json::to_value(done).unwrap_or_default(),
            ),
            Err(error) => json(
                &mut stream,
                "500 Internal Server Error",
                &serde_json::json!({ "error": error }),
            ),
        }
        return Ok(());
    }

    if request.path == "/api/preflight" {
        json(&mut stream, "200 OK", &crate::hostfacts::preflight());
        return Ok(());
    }

    if request.path == "/api/ping" && request.method == "POST" {
        let Some(socket) = console.known_socket() else {
            json(
                &mut stream,
                "409 Conflict",
                &serde_json::json!({ "error": "no interface selected" }),
            );
            return Ok(());
        };
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
        let address = body
            .get("address")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if address.is_empty() {
            json(
                &mut stream,
                "400 Bad Request",
                &serde_json::json!({ "error": "missing `address`" }),
            );
            return Ok(());
        }
        json(
            &mut stream,
            "200 OK",
            &crate::hostfacts::ping(&socket, address, 3),
        );
        return Ok(());
    }

    if request.path == "/api/health" {
        let Some(socket) = console.known_socket() else {
            json(
                &mut stream,
                "409 Conflict",
                &serde_json::json!({ "error": "no interface selected" }),
            );
            return Ok(());
        };
        json(&mut stream, "200 OK", &crate::health(&socket));
        return Ok(());
    }

    if request.path == "/api/plan" {
        let Some(socket) = console.known_socket() else {
            json(
                &mut stream,
                "409 Conflict",
                &serde_json::json!({ "error": "no interface selected" }),
            );
            return Ok(());
        };
        json(&mut stream, "200 OK", &crate::plan(&socket));
        return Ok(());
    }

    if request.path == "/api/apply" && request.method == "POST" {
        let Some(socket) = console.known_socket() else {
            json(
                &mut stream,
                "409 Conflict",
                &serde_json::json!({ "error": "no interface selected" }),
            );
            return Ok(());
        };
        if let Err(error) = crate::write_gate(&socket) {
            json(
                &mut stream,
                "403 Forbidden",
                &serde_json::json!({ "error": error }),
            );
            return Ok(());
        }
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
        let confirm = body
            .get("confirm")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        // Long-running by design: the trial restarts the daemon, waits for the
        // handshake, arms the 90 s deadline and verifies. The request holds
        // until the verdict exists.
        match crate::apply(confirm) {
            Ok(output) => json(
                &mut stream,
                "200 OK",
                &serde_json::json!({ "ok": true, "output": output }),
            ),
            Err(error) => json(
                &mut stream,
                "400 Bad Request",
                &serde_json::json!({ "error": error }),
            ),
        }
        return Ok(());
    }

    if request.path == "/api/apply/cancel" && request.method == "POST" {
        let Some(socket) = console.known_socket() else {
            json(
                &mut stream,
                "409 Conflict",
                &serde_json::json!({ "error": "no interface selected" }),
            );
            return Ok(());
        };
        if let Err(error) = crate::write_gate(&socket) {
            json(
                &mut stream,
                "403 Forbidden",
                &serde_json::json!({ "error": error }),
            );
            return Ok(());
        }
        // The trial owns a revert timer, so killing the wait is not a
        // cancel. This runs the documented undo (panic, split config back,
        // unit left running) — the same end state a failed trial reaches.
        // Refused when no trial is armed: the undo restarts a working tunnel.
        match crate::apply_cancel(&socket) {
            Ok(output) => json(
                &mut stream,
                "200 OK",
                &serde_json::json!({ "ok": true, "output": output }),
            ),
            Err(error) => json(
                &mut stream,
                "400 Bad Request",
                &serde_json::json!({ "error": error }),
            ),
        }
        return Ok(());
    }

    if request.path == "/api/revert" && request.method == "POST" {
        let Some(socket) = console.known_socket() else {
            json(
                &mut stream,
                "409 Conflict",
                &serde_json::json!({ "error": "no interface selected" }),
            );
            return Ok(());
        };
        if let Err(error) = crate::write_gate(&socket) {
            json(
                &mut stream,
                "403 Forbidden",
                &serde_json::json!({ "error": error }),
            );
            return Ok(());
        }
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
        let confirm = body
            .get("confirm")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        // The deliberate undo of an applied full tunnel: same `vallum-ops
        // revert` the mid-trial cancel runs, gated here on the typed word
        // instead of an armed trial. Long-running like apply: it restarts
        // the unit, so the request holds until the verdict exists.
        match crate::revert(confirm) {
            Ok(output) => json(
                &mut stream,
                "200 OK",
                &serde_json::json!({ "ok": true, "output": output }),
            ),
            Err(error) => json(
                &mut stream,
                "400 Bad Request",
                &serde_json::json!({ "error": error }),
            ),
        }
        return Ok(());
    }

    if request.path == "/api/service" {
        let Some(socket) = console.known_socket() else {
            json(
                &mut stream,
                "409 Conflict",
                &serde_json::json!({ "error": "no interface selected" }),
            );
            return Ok(());
        };
        if request.method == "POST" {
            // The gate lives in `service_action` itself, shared with the
            // Tauri command — one gate for both transports.
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
            let action = body
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            match crate::service_action(&socket, action) {
                Ok(done) => json(
                    &mut stream,
                    "200 OK",
                    &serde_json::to_value(done).unwrap_or_default(),
                ),
                Err(error) => json(
                    &mut stream,
                    "400 Bad Request",
                    &serde_json::json!({ "error": error }),
                ),
            }
        } else {
            json(&mut stream, "200 OK", &crate::service_state(&socket));
        }
        return Ok(());
    }

    if request.path.starts_with("/api/logs") {
        let Some(socket) = console.known_socket() else {
            json(
                &mut stream,
                "409 Conflict",
                &serde_json::json!({ "error": "no interface selected" }),
            );
            return Ok(());
        };
        let lines = request
            .path
            .split_once("lines=")
            .and_then(|(_, value)| value.parse().ok())
            .unwrap_or(200u32);
        json(&mut stream, "200 OK", &crate::logs_tail(&socket, lines));
        return Ok(());
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
            json(
                &mut stream,
                "400 Bad Request",
                &serde_json::json!({ "error": "path" }),
            );
        }
        return Ok(());
    }

    if let Some(name) = request.path.strip_prefix("/api/cmd/") {
        // The gate lives in the shared write fns (`actions::*`, `*_at`),
        // shared with the Tauri commands — one gate for both transports.
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
        let outcome = crate::dispatch(console, name, body);
        match outcome {
            Ok(value) => json(&mut stream, "200 OK", &value),
            Err(error) => json(
                &mut stream,
                "400 Bad Request",
                &serde_json::json!({ "error": error }),
            ),
        }
        return Ok(());
    }

    // Static files from the UI directory; `/` is index.html.
    let relative = request.path.split('?').next().unwrap_or("/");
    let relative = if relative == "/" {
        "/index.html"
    } else {
        relative
    };
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A request body is capped before it is allocated: the cap used to come
    /// after, so a request's own Content-Length ordered the allocation.
    #[test]
    fn a_body_past_the_cap_is_not_read() {
        let stream = format!(
            "POST /api/ping HTTP/1.1\r\nHost: 127.0.0.1:7321\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        let mut stream = std::io::Cursor::new(stream);
        assert!(
            read_request(&mut stream).is_none(),
            "a body past the cap must not be allocated"
        );
    }

    #[test]
    fn a_normal_body_is_read() {
        let body = br#"[1,2,3]"#;
        let mut stream = format!(
            "POST /api/ping HTTP/1.1\r\nHost: 127.0.0.1:7321\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        stream.push_str(std::str::from_utf8(body).unwrap());
        let mut stream = std::io::Cursor::new(stream);
        let request = read_request(&mut stream).expect("a normal request parses");
        assert_eq!(request.body, body.to_vec());
        assert_eq!(request.path, "/api/ping");
    }
}
