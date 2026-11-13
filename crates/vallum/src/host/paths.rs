//! Where this host keeps Vallum's files. Every literal `/etc/vallum` and
//! `/run/vallum` a caller would otherwise spell itself is decided here once.

use std::path::{Path, PathBuf};

/// The machine's config directory. `/etc/vallum` on a Unix install — the same
/// root-gated directory `vallum-ops` and the units already agree on.
#[must_use]
pub fn config_dir() -> &'static Path {
    Path::new("/etc/vallum")
}

/// The conventional default config, for CLI definitions that need a literal —
/// clap's `default_value` cannot call [`config_dir`].
pub const DEFAULT_CONFIG: &str = "/etc/vallum/vallum0.toml";

/// The machine's runtime directory — sockets, invites, scrape files.
///
/// `VALLUM_RUN_DIR` and `VALLUM_RUNTIME_DIR` are the same directory under two
/// names: the console overrides the socket location with the second, so an
/// invite written by that console has to land where its daemon looks. One
/// override honoured by every caller is the only version that cannot disagree;
/// the compiled default lives in `vallum_config::RUNTIME_DIR`.
#[must_use]
pub fn runtime_dir() -> PathBuf {
    std::env::var("VALLUM_RUN_DIR")
        .or_else(|_| std::env::var("VALLUM_RUNTIME_DIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| vallum_config::runtime_dir().to_path_buf())
}

/// The config an interface stem names; without a stem, the config only when
/// the host has exactly one — several configs and no stem is ambiguous, and
/// the config dir is root-only on most installs anyway, so `None` is always
/// "cannot tell", never "no config".
#[must_use]
pub fn config_path(stem: Option<&str>) -> Option<PathBuf> {
    if let Some(stem) = stem {
        let exact = config_dir().join(format!("{stem}.toml"));
        if exact.is_file() {
            return Some(exact);
        }
    }
    let mut configs: Vec<PathBuf> = std::fs::read_dir(config_dir())
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("toml"))
        .collect();
    configs.sort();
    if configs.len() == 1 {
        configs.pop()
    } else {
        None
    }
}

/// The interface a config path names — `vallum0`, Vallum's conventional
/// default, when the filename isn't UTF-8 legible. Every caller used to
/// re-derive this fallback on its own.
#[must_use]
pub fn config_stem(path: &Path) -> &str {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vallum0")
}
