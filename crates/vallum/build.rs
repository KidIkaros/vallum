//! Stamp the build with its git hash: the fleet-parity check MOOR gets from
//! its descriptor build-ID gate, in the smallest form Vallum can use.
//!
//! The stamp must name the commit the binary was built from, so what it watches
//! is as important as what it reads. `.git/HEAD` is a *symref*: it holds
//! `ref: refs/heads/main` and keeps its mtime across commits, so watching it
//! alone froze the stamp at whatever was checked out when the build script last
//! ran — nine commits stale by 2026-11-11, asserting parity that did not exist.
//! A commit rewrites the ref file (or `packed-refs` when the branch is packed),
//! so those are watched too.

use std::path::Path;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // `--absolute-git-dir` so a worktree or a linked checkout is watched at the
    // right path instead of a hardcoded ../../.git.
    let git_dir =
        git(&["rev-parse", "--absolute-git-dir"]).unwrap_or_else(|| "../../.git".to_owned());

    let mut watched = vec![format!("{git_dir}/HEAD")];
    // The ref and packed-refs live in the COMMON dir. In a linked worktree
    // `--absolute-git-dir` points at `.git/worktrees/<name>`, which has neither,
    // so watching it there froze the stamp again — the exact failure this file
    // exists to fix. HEAD stays worktree-private; the ref does not.
    let common_dir = git(&["rev-parse", "--git-common-dir"])
        .map(|dir| {
            let path = Path::new(&dir);
            if path.is_absolute() {
                dir
            } else {
                format!("{git_dir}/{dir}")
            }
        })
        .unwrap_or_else(|| git_dir.clone());
    // On a branch the ref file is what a commit writes; a detached HEAD keeps
    // its hash in HEAD itself, which is already watched.
    if let Some(reference) = git(&["symbolic-ref", "-q", "HEAD"]) {
        watched.push(format!("{common_dir}/{reference}"));
    }
    watched.push(format!("{common_dir}/packed-refs"));

    // Only watch paths that exist: cargo treats a missing watched path as
    // always-changed, which would re-run this script on every build.
    for path in watched.iter().filter(|path| Path::new(path).exists()) {
        println!("cargo:rerun-if-changed={path}");
    }

    let hash = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=VALLUM_BUILD_ID={hash}");
}
