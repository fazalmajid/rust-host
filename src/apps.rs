//! Fixed allowlist of applications the `open` command may launch, and the
//! logic to resolve an allowlisted app id to a real executable on disk.
//!
//! This intentionally replaces the original host's `spawn`/`exec` commands,
//! which let any message pick an arbitrary executable path, argument list,
//! environment and `PATH` prefix. Here the message can only choose among a
//! fixed set of ids; the actual binary name(s) and the `PATH` used to find
//! them are not influenced by the message at all.

use std::env;
use std::path::{Path, PathBuf};

pub struct AppSpec {
    pub id: &'static str,
    /// Candidate executable basenames to look for, tried in order.
    candidates: &'static [&'static str],
}

pub const APPS: &[AppSpec] = &[
    AppSpec { id: "firefox", candidates: &["firefox"] },
    AppSpec {
        id: "chrome",
        candidates: &["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"],
    },
    AppSpec { id: "chromium", candidates: &["chromium", "chromium-browser"] },
    AppSpec { id: "vlc", candidates: &["vlc"] },
    AppSpec { id: "gimp", candidates: &["gimp"] },
];

fn is_executable_file(p: &Path) -> bool {
    let Ok(meta) = p.metadata() else { return false };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn search_path(candidates: &[&str]) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;

    for dir in env::split_paths(&path_var) {
        for candidate in candidates {
            let plain = dir.join(candidate);
            if is_executable_file(&plain) {
                return Some(plain);
            }
            #[cfg(windows)]
            {
                let with_exe = dir.join(format!("{candidate}.exe"));
                if is_executable_file(&with_exe) {
                    return Some(with_exe);
                }
            }
        }
    }
    None
}

/// Searches the process's own inherited `PATH` (never anything from the
/// incoming message) for the first candidate binary matching `app_id`.
pub fn resolve(app_id: &str) -> Option<PathBuf> {
    let spec = APPS.iter().find(|a| a.id == app_id)?;
    search_path(spec.candidates)
}

/// Resolves a raw command string, as sent by an extension's own `exec`
/// request (e.g. `"firefox"`, or a user-customized full path from an
/// extension's options page), to a real executable — but only if its
/// *basename* matches one of the allowlisted candidate names above.
///
/// Any directory component the message included is discarded rather than
/// trusted: a request for `/tmp/evil/firefox` or `../../bin/firefox`
/// resolves (or fails) exactly like a request for plain `firefox` would,
/// since only the basename is compared and the real binary is found via our
/// own `PATH` search, never the caller-supplied path.
pub fn resolve_command(command: &str) -> Option<PathBuf> {
    let basename = Path::new(command).file_name()?.to_str()?;
    APPS.iter()
        .find(|spec| spec.candidates.contains(&basename))
        .and_then(|spec| search_path(spec.candidates))
}

/// Rejects arguments that start with `-`, so a value can never be
/// misinterpreted as a flag by the launched application (argument
/// injection) regardless of what it actually contains.
pub fn validate_argument(arg: &str) -> Result<(), &'static str> {
    if arg.starts_with('-') {
        Err("argument must not start with '-'")
    } else {
        Ok(())
    }
}

/// Validates the single argument passed to the resolved app. Only an
/// absolute filesystem path or a URL with an allowed scheme is accepted;
/// anything starting with `-` is rejected so it can never be interpreted as
/// a flag by the launched application (argument injection).
pub fn validate_target(target: &str) -> Result<(), &'static str> {
    if target.is_empty() {
        return Err("target must not be empty");
    }
    if target.starts_with('-') {
        return Err("target must not start with '-'");
    }

    const ALLOWED_SCHEMES: &[&str] = &["http://", "https://", "ftp://", "file://"];
    if ALLOWED_SCHEMES.iter().any(|s| target.starts_with(s)) {
        return Ok(());
    }
    if Path::new(target).is_absolute() {
        return Ok(());
    }
    Err("target must be an http(s)/ftp/file URL or an absolute path")
}
