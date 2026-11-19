# Vallum site

A static, build-free surface: two hand-written HTML pages and one stylesheet. No
bundler, no package manager, no generated output to keep in sync.

```
site/
  index.html        landing page: account-first journey, the handshake, the cockpit
  docs/index.html   documentation hub: every guide in the repo, grouped by job
  style.css         shared brandkit tokens and layout
```

## Preview

```sh
./scripts/stage-site.sh                       # pages + the image they use -> site/dist
python3 -m http.server -d site/dist 8000      # then open http://localhost:8000/
```

The pages reference `assets/vallum-cockpit.png` relative to their own root, but
the screenshot lives in the repository's `assets/` because the README and the
release media use it too. `scripts/stage-site.sh` copies it into the staged tree
and then checks every relative `href`/`src` resolves, so a mistyped path fails
here rather than as a broken image on the deployed page.

`site/dist/` is gitignored, and it is deliberately not `dist/`: `scripts/release.sh`
owns that path and deletes it wholesale.

Serve the pages over HTTP rather than `file://` so paths resolve the same way
they will when deployed.

## Where the content lives

The pages do not duplicate the documentation. Every entry in `docs/index.html`
links to its markdown file in the repository, which is the single source of
truth and renders on GitHub. The hub only adds grouping and a one-line purpose
per page; if a document is renamed, the link here changes with it.

Promoting this to a generated site (mdBook, Zola) is a separate decision: it
would let the markdown render on the site itself, at the cost of a build step
and a toolchain in CI. Nothing here depends on that happening.

## Design tokens

`style.css` carries the Vallum brandkit (`assets/vallum-brandkit.png`, rendered
by `scripts/generate_media.py` §05; the console's rendition lives in
`crates/vallum-gui/ui/src/index.css`). Dark surface only — the brandkit has no
light theme:

| token | role | value |
|---|---|---|
| `--bg` | obsidian canvas | `#0d1117` |
| `--panel` | raised surface | `#161b22` |
| `--panel-deep` | cockpit surface (brandkit §03) | `#090d12` |
| `--rule` / `--rule-soft` | hairlines | `#30363d` / `#21262d` |
| `--text` / `--subtext` / `--muted` | the three text roles | `#e6edf3` / `#8b949e` / `#7d8590` |
| `--signal` | signal cyan — the one accent | `#39c5cf` |
| `--live` / `--stale` / `--fault` / `--tx` | semantic telemetry only | `#3fb950` / `#d29922` / `#ff7b72` / `#bc8cff` |

One deliberate deviation: the brandkit's muted `#6e7681` fails AA at small
sizes on obsidian (4.12:1), so the muted role uses the console's `#7d8590`
(5.07:1 on canvas, 4.64:1 on panel). Every text/accent pair on the page was
computed, not asserted.

Type is the brandkit's JetBrains Mono (§06) first in the stack, with the
console's fallbacks and no webfont fetch; body prose is the system sans.
The signature detail is the ◆ set on a hairline that takes the slack — every
section rule is `◆ label ──────`, the TUI's section rule with the brand mark.
The hero seal is the brandkit's boundary geometry (§02) drawn as inline SVG:
initiator ──◆── responder, the rampart gate at the crossing.

Deliberately absent: hero photography, gradients, shadows, glows, stock
illustrations, and animations. The only raster image on the site is a real
frame rendered by `vallum tui --snapshot`.

## Landing page claims

The landing page is account-first: the primary CTA points at the hosted alpha
desk (`https://desk.wingman.gold`, invite-gated), and every claim maps to the
repository — `service/README.md` for the desk, the README and ADRs 0005, 0011,
0016, 0039, 0045, 0047 for the tunnel and its boundaries. One server per desk,
no fleet, no regions, no external audit: the page says so out loud.

## Deployment

Configured for a static host that runs one command and serves a directory. The
repository root holds `vercel.json`:

```json
{
  "buildCommand": "./scripts/stage-site.sh",
  "installCommand": "true",
  "outputDirectory": "site/dist"
}
```

There is no compiler in that pipeline — the build step is `cp`, the install step
is a no-op, and the output is the four files above. Any host that can run a shell
command and serve a directory needs the same three facts; only the file name
(`vercel.json`, `netlify.toml`, a workflow) changes.

**Nothing is deployed, and no domain is attached.** Two things have to happen
first, and both need the account owner:

1. Authorize the host's GitHub app for this private repository (or, for CLI
deploys, create an access token and use it — a token is a credential, so it is
not stored in the repository).
2. Pick the plan. The free tier of the host researched here is restricted to
non-commercial projects; Vallum ships as a commercial product, so a paid plan or
a different host is a licensing decision rather than a technical one. Ask before
paying for anything.
