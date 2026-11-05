# Publication checklist

What has to be true before `KidIkaros/vallum` is made public, in dependency
order. Every item is checkable, and none of them is "it works on my machine":
the local gate passing (`scripts/verify.sh`) is already true and is not enough.

The point of publishing is stated in the [roadmap](roadmap.md): outside
deployments and review, the audit the PQ dependency is waiting on, and a second
maintainer. Those are **outputs** of publication, not inputs — no item below can
manufacture them, and none should pretend to.

Current state, for orientation: the repository is private, Apache-2.0, default
branch `main`, latest tag `v1.6.3` with signed tarballs, deb, rpm and an SBOM.
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
now says "a throwaway directory created with `mktemp -d`" instead of
`/home/ikaaros/.hermes/…`, and the UTCP manual links `vallum.utcp.json`
relatively. Agent tooling state (`.agents/`, `.claude/`, `.freebuff/`,
`skills-lock.json`) is not tracked and is ignored by `.gitignore`.

Already true — run them as the regression test, not as a to-do:

- [x] `git grep -n "/home/"` returns nothing.
- [x] `git ls-files | grep -E "^\.(freebuff|agents|claude|codex)"` is empty.

Not settled by editing a file:

- [ ] **History scan**, not just the tip:
      `git log -p | grep -nE "(BEGIN [A-Z ]*PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{20,}|_secret *=|passphrase *=)"`.
      Anything hit is rotated **before** the flip; a rewritten history is a
      separate, later decision.
- [ ] The signing key used for releases is in no commit and no workflow — only
      its public half (`packaging/vallum-release.pub`, `allowed_signers`) is.
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

- [ ] **Install without credentials.** `curl -fsSL …/scripts/install.sh | sudo bash -s -- --from-release --install-only`
      resolves the release anonymously and verifies `SHA256SUMS.sig` against the
      key embedded in the script.
- [ ] **Build from a bare clone.** `git clone … && cargo build` works with no
      sibling checkout, because `origin-crypto-sdk` is a git dependency pinned to
      tag `v0.7.4` and **that repository is already public** (verified: it is).
      Do not unpublish the SDK without repinning to crates.io first.
- [ ] **Follow one page** — [quickstart](quickstart.md) — from prerequisites to a
      verified tunnel, with the enrolment path chosen by what the client can
      reach.
- [ ] **Verify what they downloaded**: release assets include `SHA256SUMS`,
      `SHA256SUMS.sig`, `allowed_signers` and the SBOM (`v1.6.3` has all four).
- [x] Community files exist and are current: `CONTRIBUTING.md`,
      `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `CODEOWNERS`,
      `.github/PULL_REQUEST_TEMPLATE.md`, `.github/ISSUE_TEMPLATE/`,
      `.github/dependabot.yml`. `CONTRIBUTING.md` now states the licence of
      contributions: inbound is Apache-2.0, no CLA, no copyright assignment.

## 5. Settings that only exist once the repository is public

Verified today: the protection API answers `403` with
*"Upgrade to GitHub Pro or make this repository public to enable this feature."*
So these are post-flip steps, and they need the flip to be safe already:

- [ ] Branch protection on `main`: require a pull request, require the `ci` job,
      dismiss stale approvals, require `CODEOWNERS` review.
- [ ] **Private vulnerability reporting enabled**, then open
      `SECURITY.md`'s own instruction and confirm the Security → Advisories →
      Report a vulnerability button appears. Without it the policy points at
      nothing.
- [ ] Secret scanning and push protection on (free on public repositories).
- [ ] Dependabot alerts on, and check that its PRs land on the hosted runner —
      they are `pull_request` events like any other (§1 again).
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
git grep -n "/home/"                                   # §2
git ls-files | grep -E "^\.(freebuff|agents|claude)"    # §2
grep -rn --exclude=publication-checklist.md "repo is private\|repository is private" docs scripts README.md   # §3
grep -n "runs-on" .github/workflows/*.yml              # §1
gh api repos/KidIkaros/vallum --jq .visibility         # the flip itself
gh api repos/KidIkaros/OriginSDK --jq .visibility      # build dependency
```

The first three should print nothing before the flip; after it, they are the
regression test that the tree did not drift back into assuming privacy.
