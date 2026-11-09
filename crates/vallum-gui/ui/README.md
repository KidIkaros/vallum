# The console's webview UI

React 19 + TypeScript on Vite, styled with Tailwind v4 and shadcn/ui
(new-york, neutral). `npm run build` emits `dist/`, which
`tauri.conf.json` names as `frontendDist`; `tauri dev` runs the Vite dev
server itself through `beforeDevCommand`.

## Contract

`src/types.ts` mirrors what the Rust side serialises — `Snapshot`, `Peer`,
`Counters` in `crates/vallum-gui/src/snapshot.rs`, and the `#[tauri::command]`
signatures in `src/main.rs`. `src/lib/bridge.ts` is the only code that touches
the bridge: everything the UI renders comes from one `snapshot` event and a
handful of invocations. A field added on the Rust side lands here first.

## Debug builds load the dev server, not `dist`

`tauri.conf.json` names a `devUrl` (`http://localhost:5173`) because `tauri dev`
needs it. A **debug** binary launched directly therefore loads that URL — with
no Vite server running, the window is blank, with no error anywhere. Either run
`npm run dev` beside a debug binary, or use the release build, which always
serves the embedded `dist`:

```
cargo build --release -p vallum-gui && ./target/release/vallum-gui
```

## Two transports

The console runs in two places with one frontend:

- **Inside Tauri** (the window): IPC via `window.__TAURI_INTERNALS__`.
- **`vallum-gui --serve [port] [--ui dir]`**: the same UI over localhost HTTP —
  `/api/interfaces`, `/api/select`, `/api/stream` (SSE, one snapshot per
  second) and `POST /api/cmd/<name>`, all backed by the same Rust functions the
  Tauri commands call. Use it where the webview cannot render (WebKitGTK on
  some GPU/driver combinations loads pages blank); open
  `http://127.0.0.1:7317` in any browser.

`src/lib/bridge.ts` picks the transport; nothing above it knows which one is
in use.

## Conventions

- No runtime dependency on any component library: shadcn components are
  vendored source in `src/components/ui`, owned here like the rest.
- The CSP in `tauri.conf.json` allows inline *style attributes* only
  (`style-src 'unsafe-inline'`), because Radix positions popovers and dialogs
  with them. Scripts stay locked to `'self'`; do not loosen that.
- Verification without a daemon: `npm run build` and open `dist/` (the empty state
  renders honestly when no control socket
  exists). With a daemon running (`vallum-quick up`), the live
  snapshot fills the same screen.
