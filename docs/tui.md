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
| `a` | add peer (public line, endpoint, allowed IPs, keepalive, PSK) |
| `e` | edit endpoint, allowed IPs, keepalive, PSK |
| `d` | remove peer (confirmation) |
| `g` | generate a key and prefill the add form |
| `q` | export the client bundle and show its animated QR |
| `c` | edit the runtime listen port and fwmark |
| `E` | edit the TOML in `$EDITOR` |
| `s` | start/stop: systemd first, then `vallum-quick` |
| `l` | load journald logs |
| `r` | refresh |
| `?` | help |
| `Q` / Ctrl-C | quit |

## What it does

- **Dashboard**: interface name, listen address, suite, fwmark, addresses,
  fingerprint, capabilities, offload/batching; per peer name, fingerprint,
  endpoint, allowed IPs, handshake age, rx/tx totals and rates, epoch, PSK
  presence.
- **Peer CRUD** through the UAPI. The public line is decoded and checked against
  the device suite; endpoint hostnames are resolved; allowed IPs are validated.
- **Key generation** writes a 0600 key file and prefills the add form with the
  public line.
- **Bundle export** writes a versioned JSON bundle (config + key file) as a
  `.vallum-bundle` file and an animated multi-frame QR. The QR contains the
  private key; the modal says so and is cleared on close.
- **Service control**: `systemctl start/stop vallum@<stem>.service` when the
  unit exists; otherwise `vallum-quick up/down` if already root, or the exact
  `sudo` command when not. No sudo prompt is opened by the TUI.
- **Logs**: `journalctl -u vallum@<stem> -n 200 --no-pager -o cat`.

## Security

- Secrets are masked. The private key and PSK are never rendered; the QR is the
  only secret-bearing view and requires an explicit keypress.
- No shell: `systemctl`, `journalctl`, `vallum-quick`, and `$EDITOR` are spawned
  with argument arrays, never `sh -c`.
- The control socket is the same trust boundary as the private key (0600,
  same user).
- Config edits through `$EDITOR` are not auto-applied; restart or `syncconf`
  after reviewing the diff.

## Limits

- Terminal-only; no GUI, camera QR scanning, or Windows named-pipe control.
- Interface/routes/DNS changes are raw TOML through `E`, not structured forms
  yet; peer and runtime-device changes are forms.
- The QR is an export format; import is from the `.vallum-bundle` file.
