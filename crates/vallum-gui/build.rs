// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

fn main() {
    // Allow a fresh `cargo build --workspace` to succeed even before `ui/dist`
    // has been compiled with Vite; `tauri_build` requires `frontendDist` to exist.
    let dist_dir = Path::new("ui/dist");
    let index = dist_dir.join("index.html");
    if !index.exists() {
        if let Err(err) = fs::create_dir_all(dist_dir) {
            panic!("failed to create placeholder ui/dist directory: {err}");
        }
        let stub = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Vallum</title></head><body><p>Run <code>npm run build</code> inside <code>crates/vallum-gui/ui</code> to populate the UI bundle.</p></body></html>\n";
        if let Err(err) = fs::write(&index, stub) {
            panic!("failed to write placeholder ui/dist/index.html: {err}");
        }
    }
    tauri_build::build();
}
