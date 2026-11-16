# Publication checklist

What has to be true before `KidIkaros/vallum` is made public, in dependency
order. Every item is checkable, and none of them is "it works on my machine":
the local gate passing (`scripts/verify.sh`) is already true and is not enough.

The point of publishing is stated in the [roadmap](roadmap.md): outside
deployments and review, the audit the PQ dependency is waiting on, and a second
maintainer. Those are **outputs** of publication, not inputs — no item below can
manufacture them, and none should pretend to.

Current state, for orientation: the repository is private, Apache-2.0, default
branch `main`, latest tag `v1.6.4` with signed tarballs, deb, rpm and an SBOM.
The tree-level work in §2 and §3 is **done** — it cost nothing to do while
private — and §1's runner rule is now configuration rather than a plan. What
cannot be proved from a private repository is the first hosted run (§1) and the
settings that only exist on a public repository (§5).

---

## 1. CI: no untrusted code on a persistent machine (configured)

**Done**: the runner is chosen by repository visibility, in all five jobs
(`ci.yml` ×3, `fuzz.yml`, `release.yml`):

```yaml
runs-on: ${{ github.event.repository.private && fromJSON('["self-hosted","linux","x64"]') || 'ubuntu-latest' }}
```

Private keeps the project's own machine (`wingman-vps`), which is where hosted
minutes are refused today. Public gets `ubuntu-latest` and nothing else — so a
stranger's `pull_request` can never execute on a persistent machine of yours.
That is the fork guard, and it is structural: there is no label to forget to
change on the day of the flip. `audit` additionally carries an explicit
`if:` refusing fork PRs, because it asks for `checks: write` and a fork PR's
token is read-only.

What a private repository cannot prove:

- [ ] After the flip, a **hosted run of `ci.yml` is green on `main`** — the
      roadmap's criterion, and the point where the runner wiring is actually
      exercised for the first time.
- [ ] `fuzz.yml`'s weekly schedule (`cron: '17 4 * * 0'`, 900 s per target) is
      green on the hosted runner, and the 60 s smoke on a PR.
- [ ] `release.yml`'s tag preflight is green on the hosted runner (a tag push is
      trusted input either way).

**Correction (2026-11-11): the wiring has been exercised.** The self-hosted
runner is live — `actions.runner.KidIkaros-vallum.wingman-vps.service` is active
on `wingman-vps` — and it ran two jobs to `Succeeded` on 2026-11-09:

    12:36:35Z Running job: test (1.95.0)
    12:42:35Z Job test (1.95.0) completed with result: Succeeded
    12:42:57Z Job advisories and supply chain completed with result: Succeeded

So "the runner wiring is actually exercised for the first time" is no longer what
the flip risks: the YAML *has* been parsed and run by a runner. The real gap is
narrower — **127 commits are ahead of `origin/main`**, so nothing since
2026-11-09 has been through one. Pushing `main` closes that today, on the
self-hosted runner, without waiting for the flip. The boxes below stay unticked
because each is specifically about the **hosted** runner after going public.

Re-check the guard, not the intent:

```sh
grep -n "runs-on" .github/workflows/*.yml          # all five: the expression, never a bare label
grep -rn "self-hosted" .github/workflows/*.yml      # only inside the expression and the comments
```

The ordering trap is real: proving hosted CI needs either paid minutes on a
private repository or free ones on a public one, which is why the tree had to be
clean (§2, §3) *before* the flip could be the test.

## 2. The tree carries nothing private (scrubbed)

**Done**: the two absolute paths found in the tree are gone — a proof artefact
now says "a throwaway directory created with `mktemp -d`" instead of naming a
home directory, and the UTCP manual links `vallum.utcp.json` relatively. Agent tooling state (`.agents/`, `.claude/`, `.freebuff/`,
`skills-lock.json`) is not tracked and is ignored by `.gitignore`.

Already true — run them as the regression test, not as a to-do:

- [x] `git grep -n "/home/" -- ':!docs/publication-checklist.md'` returns
      nothing. (This file has to quote the command, so it excludes itself.)
- [x] `git ls-files | grep -E "^\.(freebuff|agents|claude|codex)"` is empty.

Not settled by editing a file:

- [ ] **History scan**, not just the tip:
      `git log -p | grep -nE "(BEGIN [A-Z ]*PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{20,}|_secret *=|passphrase *=)"`.
      Anything hit is rotated **before** the flip; a rewritten history is a
      separate, later decision.
- [ ] The signing key used for releases is in no commit and no workflow — only
      its public half (`packaging/vallum-release.pub`, `allowed_signers`) is.
- [x] **The shipped binaries, not just the tree.** `v1.6.3` shipped the build
      machine's layout — 288 `/home/…` strings in `vallum`, 43 in `vallum-quick`
      — because `file!()` literals survive `strip = "symbols"`. `scripts/release.sh`
      remaps both roots now, and refuses to package a binary that still names
      `$HOME`. **Checked on the `v1.6.4` tarball: 0 and 0**, reading `/cargo/…`
      instead. Re-run per release:

      ```sh
      gh release download <tag> --repo KidIkaros/vallum --pattern '*x86_64-linux.tar.gz'
      tar xzf vallum-*.tar.gz && grep -aoF "/home/" vallum-*/vallum vallum-*/vallum-quick | wc -l   # expect 0
      ```

      The measurement itself: `docs/dogfood/2026-11-05-release-1.6.4.md` §2.
- [ ] Spot-check the proof and dogfood documents for hostnames or addresses that
      are not documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
      `203.0.113.0/24`): `git grep -nE "([0-9]{1,3}\.){3}[0-9]{1,3}" docs/proof docs/dogfood`.
- [ ] `contrib/telemetry/` posts to `http://127.0.0.1:8428` — local, nothing
      internal named. Leave as is; re-check if the default ever changes.

## 3. Text that assumes a private repository (scrubbed)

**Done**: the four places that told a reader to authenticate now say the assets
are public and name a private fork as the only case that wants a token —
`docs/deployment/server.md`, `docs/quickstart.md`, `docs/proof/quick.md`, and
`docs/releasing.md` (whose self-hosting paragraph now points at §1's runner
rule). `scripts/install.sh` keeps its `gh` fallback and no longer claims the
repository is private in the comments.

- [x] `grep -rn --exclude=publication-checklist.md "GH_TOKEN" docs README.md`
      returns only fork guidance ("a private fork"), never an instruction as if
      the main repository needed it.
- [ ] The install command in the README and quickstart works in a shell with no
      `GH_TOKEN` and no `gh` — testable only after the flip, since it is the
      anonymous download that changes.

## 4. What a stranger must be able to do

- [x] **Install without credentials** (verified anonymously 2026-11-16):
      the `latest` release endpoint resolves unauthenticated (v1.7.0),
      `SHA256SUMS.sig` verifies against `allowed_signers`, and the x86_64
      tarball's sha256 matches the signed sums. The `install.sh --from-release`
      mechanics are exactly this chain plus `sudo` for the file install.
- [x] **Build from a bare clone** (verified anonymously 2026-11-16):
      `git clone --depth 1 … && cargo build -p vallum -p vallum-quick` finishes
      clean with no credentials — `origin-crypto-sdk` resolves from the public
      repo pinned to tag `v0.7.4`. Do not unpublish the SDK without repinning
      to crates.io first.
- [x] **Follow one page** — [quickstart](quickstart.md) — from prerequisites to a
      verified tunnel, with the enrolment path chosen by what the client can
      reach. Every command in it was exercised by the 2026-11-16
      `verify-remote --clean-remote` run (all three transports); whether a
      stranger finds it *readable* is what "outside deployments" will tell us.
- [x] **Verify what they downloaded** (verified anonymously 2026-11-16): v1.7.0
      assets include `SHA256SUMS`, `SHA256SUMS.sig`, `allowed_signers` and the
      SBOM; the signature verifies and the x86_64 tarball's sum matches.
- [x] Community files exist and are current: `CONTRIBUTING.md`,
      `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `CODEOWNERS`,
      `.github/PULL_REQUEST_TEMPLATE.md`, `.github/ISSUE_TEMPLATE/`,
      `.github/dependabot.yml`. `CONTRIBUTING.md` now states the licence of
      contributions: inbound is Apache-2.0, no CLA, no copyright assignment.

## 5. Settings that only exist once the repository is public

Verified today: the protection API answers `403` with
*"Upgrade to GitHub Pro or make this repository public to enable this feature."*
So these are post-flip steps, and they need the flip to be safe already:

- [x] Branch protection on `main` (2026-11-16): require a pull request, require
      `test (stable)`, `test (1.95.0)`, `install`, `acceptance` (`audit` is not
      required — it refuses fork PRs by design), dismiss stale approvals,
      require `CODEOWNERS` review; no force pushes, no branch deletion.
- [x] **Private vulnerability reporting enabled** (2026-11-16, via
      `PUT /repos/KidIkaros/vallum/private-vulnerability-reporting`). The
      Security → Advisories → Report a vulnerability button now exists.
- [x] Secret scanning and push protection on (2026-11-16,
      `security_and_analysis`: both `enabled`).
- [x] Dependabot alerts on and security-update PRs enabled (2026-11-16); its
      first PRs were already running minutes after the flip — they are
      `pull_request` events and land on the hosted runner (§1 again).
- [ ] Decide whether outside contributors need a DCO/sign-off; if yes, add it to
      `CONTRIBUTING.md` **before** the first outside PR, not after.

## 6. The claim publication does not make

- [ ] The README's sentence about `origin-crypto-sdk` — `EXPERIMENTAL — NOT FOR
      PRODUCTION USE`, no external audit — stays exactly as it is. Publishing
      invites the review; it does not substitute for it.
- [ ] Numbers quoted anywhere are measured or marked unmeasured (`CONTEXT.md`'s
      rule). A public audience checks arithmetic.
- [ ] `docs/roadmap.md`'s "A public repository" row is updated to say it happened,
      with what is still owed: outside deployments, external review, an audit,
      a second maintainer.
- [ ] Nothing anywhere claims "production ready" in the abstract. The roadmap's
      seven conditions are the definition; the audit is the eighth thing a
      reviewer will ask about and it is not in the tree.

## 7. Order of operations

1. ~~Scrub §2 and §3~~ — done, while the repository was private, where a mistake
   cost nothing.
2. ~~§1: the runner rule~~ — done; the five `runs-on:` lines now choose hosted by
   visibility, and the workflow files parse (`python3 -c 'import yaml,sys; …'`
   standing in for `actionlint`, which is not installed here).
3. Flip visibility.
4. Watch the first hosted run on `main`; fix what only a hosted runner reveals.
5. §5: protection, private reporting, secret scanning, Dependabot.
6. Announce the install path; deploy the site as a separate decision (it is
   staged by `scripts/stage-site.sh` and blocked on host credentials, not on
   publication).
7. Record in `CHANGELOG.md` + roadmap that publication happened, and what remains.

## Re-checking this list

```sh
git grep -n "/home/" -- ':!docs/publication-checklist.md'   # §2
git ls-files | grep -E "^\.(freebuff|agents|claude)"    # §2
grep -rn --exclude=publication-checklist.md "repo is private\|repository is private" docs scripts README.md   # §3
grep -n "runs-on" .github/workflows/*.yml              # §1
gh api repos/KidIkaros/vallum --jq .visibility         # the flip itself
gh api repos/KidIkaros/OriginSDK --jq .visibility      # build dependency
```

The first three should print nothing before the flip; after it, they are the
regression test that the tree did not drift back into assuming privacy.
