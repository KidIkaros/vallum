# Vallum site

A static, build-free surface: two hand-written HTML pages and one stylesheet. No
bundler, no package manager, no generated output to keep in sync.

```
site/
  index.html        landing page: what the handshake does, install, the cockpit
  docs/index.html   documentation hub: every guide in the repo, grouped by job
  style.css         shared tokens and layout
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

`style.css` mirrors `crates/vallum/src/tui/theme.rs` so the site and the cockpit
read as one product:

| token | role | dark | light |
|---|---|---|---|
| `--accent` | signal, links, headings | `#22d3ee` | `#0e7490` |
| `--ok` | healthy / active | `#34d399` | `#047857` |
| `--warn` | aging / transitional | `#fbbf24` | `#9a6700` |
| `--danger` | failed / expired | `#f87171` | `#b91c1c` |
| `--selection` | selected row (`Rgb(24, 42, 58)` in the TUI) | `#182a3a` | `#e7f1f7` |

The TUI emits ANSI colours, so these hex values are the site's rendition of the
same roles, checked against both schemes. The `── label ──` rule under each
heading is the TUI's section rule, drawn as a hairline that takes the slack.

Deliberately absent: hero imagery, gradients, shadows, stock illustrations, and
animations. The only image on the site is a real frame rendered by
`vallum tui --snapshot`.

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
