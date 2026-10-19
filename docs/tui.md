# `vallum tui` — the operations console

`vallum tui` is a terminal dashboard for a running Vallum daemon. It talks to the
0600 control socket, so it needs the same user as the daemon; it does not need
root for status or peer changes.

```sh
vallum tui --config /etc/vallum/vallum0.toml
vallum tui --control /run/vallum/vallum0.sock
vallum tui --config-dir /etc/vallum
vallum tui --snapshot --width 120 --height 36   # headless, for CI/README
```

## Keys

| Key | Action |
|---|---|
| `Tab` / `Shift-Tab` | next/previous interface |
| `j` / `k`, arrows | select peer |
| `a` | add peer (name, public line, endpoint, allowed IPs, keepalive, PSK) |
| `e` | edit name, endpoint, allowed IPs, keepalive, PSK |
| `d` | remove peer (confirmation) |
| `g` | generate a key and prefill the add form |
| `q` | export the client bundle and show its animated QR |
| `c` | edit the runtime listen port and fwmark |
| `C` | edit listen/MTU/fwmark/addresses/DNS/table |
| `E` | edit the TOML in `$EDITOR`; review the two-column diff, Enter applies, Esc keeps the file |
| `s` | start/stop: systemd first, then `vallum-quick` |
| `l` | load journald logs |
| `f` | toggle log follow (in the Logs view) |
| `r` | refresh |
| `?` | help |
| `Q` / Ctrl-C | quit |

## What it does

- **Dashboard**: interface name, listen address, suite, fwmark, addresses,
  fingerprint, capabilities, offload/batching; per peer name, fingerprint,
  endpoint, allowed IPs, handshake age, rx/tx totals and rates, epoch, PSK
  presence. The table hides secondary columns on narrower terminals, and the
  dashboard switches to a stacked peer/detail layout below 100 columns.
- **Forms**: the focused field and insertion point are visible; arrows and
  Home/End move within text, Backspace/Delete edit in place, and Ctrl-U clears
  the current field. Secret fields use a fixed mask so their length is not
  displayed. Validation errors persist in the form, identify the invalid field
  when possible, and retain entered values until a corrected submission or
  cancellation.
- **Empty state**: when no interface is discoverable, the TUI shows direct
  commands and flags for connecting to or starting a tunnel instead of empty
  peers/details panes.
- **Peer CRUD** through the UAPI. The public line is decoded and checked against
  the device suite; endpoint hostnames are resolved; allowed IPs are validated.
- **Key generation** writes a 0600 key file and prefills the add form with the
  public line. If the config directory is not writable (for example
  `/etc/vallum` for a non-root operator), it falls back to
  `$XDG_CONFIG_HOME/vallum` or `~/.config/vallum`.
- **Bundle export** asks for the server endpoint (defaulting to the daemon's
  listen address; an unspecified `0.0.0.0`/`[::]` is rejected), writes a
  versioned JSON bundle (config + key file) as a `.vallum-bundle` file, and
  shows an animated multi-frame QR. The QR contains the private key; the modal
  says so and is cleared on close.
- **Bundle import** is `vallum import-bundle <file> --output-dir DIR`; it writes
  the config and a 0600 key, refusing to overwrite without `--force`.
- **Config edits** are backed up before `$EDITOR`; after editing, a two-column
  diff is shown. Enter restarts/applies, Esc keeps the file unapplied.
- **Service control**: `systemctl start/stop vallum@<stem>.service` when the
  unit exists; otherwise `vallum-quick up/down` if already root, or the exact
  `sudo` command when not. No sudo prompt is opened by the TUI.
- **Logs**: `journalctl -u vallum@<stem> -n 200 --no-pager -o cat`; `r`
  refreshes, `f` polls every second, and an empty/unavailable journal is shown
  as a message rather than a blank pane.

## Security

- Secrets are masked. The private key and PSK are never rendered; the QR is the
  only secret-bearing view and requires an explicit keypress.
- No shell: `systemctl`, `journalctl`, `vallum-quick`, and `$EDITOR` are spawned
  with argument arrays, never `sh -c`.
- The control socket is the same trust boundary as the private key (0600,
  same user). Each config must use a unique `control` path; relative paths are
  resolved against the config directory, so two configs with
  `control = "control.sock"` in one directory collide.
- Config edits through `$EDITOR` are not auto-applied; restart or `syncconf`
  after reviewing the diff.

## Limits

- Terminal-only; no GUI, camera QR scanning, or Windows named-pipe control.
- Interface/routes/DNS changes are raw TOML through `E`, not structured forms
  yet; peer and runtime-device changes are forms.
- The QR is an export format; import is from the `.vallum-bundle` file.
