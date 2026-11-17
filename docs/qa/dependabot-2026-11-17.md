# Two Dependabot alerts, and what they are (`2026-11-17`)

GitHub reported two open alerts on the default branch when `ad98a17` was
pushed. Neither is fixable today without an upstream release, and both are
recorded here with the check that settles each claim — so the next person who
sees the banner has the answer instead of a re-investigation.

Re-check either claim with:

```sh
gh api repos/KidIkaros/vallum/dependabot/alerts \
  --jq '.[] | select(.state=="open") | {number, severity: .security_advisory.severity, pkg: .dependency.package.name}'
cargo tree -e normal -i atty      # "nothing to print" == not shipped
cargo tree -e normal -i glib
```

## 1. `atty 0.2.14` — low, "potential unaligned read"

**Not in any shipped artifact.** `cargo tree -e normal -i atty` prints
*nothing to print*: the only path is a **dev-dependency** —

```
atty → clap v2.34.0 → dudect-bencher 0.7.0 (dev) → vallum-crypto-sdk
```

That is the constant-time benchmark harness, built only by `cargo bench` and
`cargo test` on a developer machine. Nothing that ships links it.

**Cannot be fixed by us today:** `dudect-bencher 0.7.0` is the latest release
and still uses `clap` v2, which pins `atty`. `atty` is unmaintained upstream.

**What would clear it:** a `dudect-bencher` release on `clap` v4 (which uses
`is-terminal`). Re-check with `cargo info dudect-bencher`.

## 2. `glib 0.18.5` — medium, "unsoundness in `Iterator`/`DoubleEndedIterator` impls for `glib::VariantStrIter`"

**In the shipped GUI, transitively.** The path is

```
glib → atk → gtk 0.18 → {muda, tao, tauri, tauri-runtime-wry} → vallum-gui
```

The advisory is a **soundness** bug: the iterator impls can hand out a
reference with a lifetime that outlives the variant. It is not memory
corruption reachable from the wire — Vallum's data plane is Rust with no GTK in
it, and the daemon does not link `glib` at all (only `vallum-gui` does).

**Our code never touches the API.** `grep -rn 'VariantStrIter\|Variant::'
crates/ --include=*.rs` is empty. Whether the GTK stack itself iterates a
`GVariant` string list internally is not something this repository can rule
out, which is why this is recorded as *not reachable from our code* rather than
*not reachable*.

**Cannot be fixed by us today:** the fix is `glib >= 0.20.0`, which requires
the `gtk-rs` 0.20 stack. `tauri 2.12.5` is the latest stable release and pins
`gtk` 0.18; only `tauri 3.0.0-alpha` has moved. Taking a Tauri alpha into the
desktop console of a security product to silence a soundness advisory in an
unused iterator is the wrong trade, and would put an unreleased UI framework on
the release path.

**What would clear it:** a stable Tauri release on `gtk-rs` 0.20. Re-check with
`cargo info tauri`.

## Why `cargo deny` is green

`cargo deny check` reports `advisories ok`, because these two are **GitHub
advisories (GHSA)** and are not in the RustSec database that `cargo-deny`
consults. That is a real gap in the gate, not a false negative to celebrate: a
green supply-chain check and an open Dependabot alert on the same commit is
exactly the "a green check is a claim about what it measures" pattern. It is
recorded here rather than papered over with an ignore, because an ignore for an
advisory the tool does not know about produces an unmatched-ignore warning and
teaches nothing.
