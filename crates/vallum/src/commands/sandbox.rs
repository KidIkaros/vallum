// SPDX-License-Identifier: Apache-2.0

//! `vallum sandbox`: the syscall allow-list the daemon installs (ADR-0028).
//!
//! The list is printed by the binary rather than copied into a script because
//! the CI guard diffs a live trace against it, and a guard with a second copy of
//! the list cannot fail when the two copies disagree. `--names` is the form that
//! diff wants; the default is for a person reading it.

use clap::Args;

use crate::{sandbox, say, Error};

#[derive(Debug, Args)]
pub struct SandboxArgs {
    /// Print only the syscall names, one per line.
    ///
    /// For the guard:
    ///
    /// ```text
    /// comm -23 <(traced | sort -u) <(vallum sandbox --names | sort)
    /// ```
    #[arg(long, conflicts_with = "json")]
    pub names: bool,

    /// Emit the allow-list as JSON.
    #[arg(long)]
    pub json: bool,
}

/// Print the allow-list.
///
/// # Errors
///
/// The sandbox command reads nothing and installs nothing, so it does not fail;
/// the signature matches every other command's.
pub fn list(args: &SandboxArgs) -> Result<(), Error> {
    let entries = sandbox::entries();
    if args.json {
        let items: Vec<serde_json::Value> = entries
            .iter()
            .map(|(name, number)| serde_json::json!({ "name": name, "number": number }))
            .collect();
        say!("{}", serde_json::json!({ "syscalls": items }));
        return Ok(());
    }
    if args.names {
        for (name, _) in &entries {
            say!("{name}");
        }
        return Ok(());
    }

    say!(
        "{} syscalls are allowed after the privilege drop (ADR-0028).",
        entries.len()
    );
    say!(
        "`interface.seccomp` selects `log` (the default) or `enforce`; the filter is \
         installed with the privilege drop, so it needs `interface.user` or `interface.group`."
    );
    say!("");
    let width = entries
        .iter()
        .map(|(name, _)| name.len())
        .max()
        .unwrap_or(0);
    for (name, number) in &entries {
        say!("{name:<width$}  {number}");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_names_form_is_one_name_per_line() {
        // The guard sorts and diffs this output, so a header or a number in it
        // would show up as an unknown syscall on every run.
        let args = SandboxArgs {
            names: true,
            json: false,
        };
        list(&args).expect("list");
        for (name, _) in sandbox::entries() {
            assert!(
                !name.contains(char::is_whitespace),
                "`{name}` would break a one-name-per-line reader"
            );
        }
    }
}
