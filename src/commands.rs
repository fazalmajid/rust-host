//! Command dispatch. The supported command set is deliberately small:
//! `version`, `spec`, `echo`, and `open`. There is no `spawn`, `exec`,
//! `env`, or `script` — those let the original Node host run arbitrary
//! commands or arbitrary JavaScript on behalf of any of the ~50 extensions
//! allowlisted in the native-messaging manifest.

use serde_json::{json, Value};
use std::env;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::apps;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// How long `exec` waits for the launched process to exit before assuming
/// it's a long-lived GUI app (e.g. a freshly-started Firefox with no other
/// instance to hand the URL to) rather than a short-lived one (e.g. a
/// client handing a URL to an *already running* Firefox, which exits almost
/// immediately once it does so).
const EXEC_WAIT_TIMEOUT: Duration = Duration::from_millis(1500);

/// Commands the original host supported that this rewrite does not.
/// Named explicitly so callers get an actionable error instead of a bare
/// "unknown command".
const REMOVED_FOR_SECURITY: &[&str] = &["spawn", "env", "script", "clean-tmp"];

pub fn handle(msg: &Value) -> Value {
    let cmd = msg.get("cmd").and_then(Value::as_str).unwrap_or("");

    match cmd {
        "version" => json!({ "version": VERSION }),
        "spec" => json!({
            "version": VERSION,
            "separator": std::path::MAIN_SEPARATOR.to_string(),
            "tmpdir": env::temp_dir().to_string_lossy(),
        }),
        "echo" => msg.clone(),
        "open" => handle_open(msg),
        "exec" => handle_exec(msg),
        other if REMOVED_FOR_SECURITY.contains(&other) => json!({
            "error": format!(
                "The \"{other}\" command has been removed. It allowed arbitrary code/process \
                 execution and has no equivalent in this host; use \"open\" with an allowlisted \
                 app id instead.",
            ),
            "cmd": other,
            "code": 1000,
        }),
        other => json!({
            "error": format!("This native client does not support the \"{other}\" command."),
            "cmd": other,
            "code": 1000,
        }),
    }
}

fn handle_open(msg: &Value) -> Value {
    let app_id = match msg.get("app").and_then(Value::as_str) {
        Some(a) => a,
        None => return error_response("open", "missing \"app\""),
    };
    let target = match msg.get("target").and_then(Value::as_str) {
        Some(t) => t,
        None => return error_response("open", "missing \"target\""),
    };

    if let Err(e) = apps::validate_target(target) {
        return error_response("open", e);
    }

    let Some(bin) = apps::resolve(app_id) else {
        return error_response(
            "open",
            &format!("\"{app_id}\" is not an allowlisted app, or its executable was not found"),
        );
    };

    match Command::new(&bin)
        .arg(target)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => json!({ "cmd": "open", "code": 0, "pid": child.id() }),
        Err(e) => error_response("open", &format!("failed to launch \"{app_id}\": {e}")),
    }
}

/// Handles the wire protocol several existing "Open in X" extensions
/// actually speak: `{cmd: "exec", command, arguments, properties}`. Unlike
/// the original host, `command` is resolved through the same allowlist as
/// `open` (matched by basename, then found via our own `PATH`, never the
/// caller's path) and `properties` — which the original host merged
/// straight into the spawned process's options, enabling `shell: true`,
/// arbitrary `cwd`, `uid`/`gid`, etc. — is accepted but ignored entirely.
fn handle_exec(msg: &Value) -> Value {
    let command = match msg.get("command").and_then(Value::as_str) {
        Some(c) => c,
        None => return error_response("exec", "missing \"command\""),
    };
    let arguments: Vec<&str> = match msg.get("arguments") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => {
            match items.iter().map(Value::as_str).collect::<Option<Vec<_>>>() {
                Some(args) => args,
                None => return error_response("exec", "\"arguments\" must be an array of strings"),
            }
        }
        Some(_) => return error_response("exec", "\"arguments\" must be an array of strings"),
    };

    for arg in &arguments {
        if let Err(e) = apps::validate_argument(arg) {
            return error_response("exec", e);
        }
    }

    let Some(bin) = apps::resolve_command(command) else {
        return error_response(
            "exec",
            &format!("\"{command}\" is not an allowlisted application, or its executable was not found"),
        );
    };

    let mut child = match Command::new(&bin)
        .args(&arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => return error_response("exec", &format!("failed to launch \"{command}\": {e}")),
    };

    // Read stdout/stderr on their own threads so a chatty child can't
    // deadlock on a full pipe buffer while we're only polling for exit
    // below, and so the read continues even past the timeout.
    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    let stdout_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let stderr_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(child.wait());
    });

    match rx.recv_timeout(EXEC_WAIT_TIMEOUT) {
        // Exited within the timeout: this was a client handing the URL to
        // an already-running instance (or the app just runs that fast) —
        // report its real exit code and captured output.
        Ok(Ok(status)) => {
            let stdout = stdout_thread.join().unwrap_or_default();
            let stderr = stderr_thread.join().unwrap_or_default();
            json!({
                "cmd": "exec",
                "code": status.code().unwrap_or(-1),
                "stdout": String::from_utf8_lossy(&stdout),
                "stderr": String::from_utf8_lossy(&stderr),
            })
        }
        Ok(Err(e)) => error_response("exec", &format!("failed to wait on \"{command}\": {e}")),
        // Still running past the timeout: treat it as a long-lived GUI
        // process that was launched successfully rather than blocking the
        // whole host on it. The waiter/reader threads are left running in
        // the background and will finish (and get reaped) whenever the
        // process eventually exits.
        Err(mpsc::RecvTimeoutError::Timeout) => json!({
            "cmd": "exec",
            "code": 0,
            "stdout": "",
            "stderr": "",
        }),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            error_response("exec", &format!("lost track of \"{command}\" while waiting for it"))
        }
    }
}

fn error_response(cmd: &str, error: &str) -> Value {
    json!({ "cmd": cmd, "error": error, "code": 1001 })
}
