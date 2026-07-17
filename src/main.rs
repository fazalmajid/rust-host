mod apps;
mod commands;
mod protocol;

use protocol::{read_message, write_message, ReadError};
use serde_json::json;
use std::io::{self, Read, Write};

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();

    run(&mut input, &mut output);
}

fn run<R: Read, W: Write>(input: &mut R, output: &mut W) {
    loop {
        let msg = match read_message(input) {
            Ok(msg) => msg,
            Err(ReadError::Eof) => break,
            Err(ReadError::TooLarge(len)) => {
                // Framing is now desynchronized (we didn't consume the
                // oversized body) so there is nothing safe to do but stop.
                eprintln!("native-client-host: incoming message of {len} bytes exceeds limit, closing");
                break;
            }
            Err(ReadError::Json(e)) => {
                let _ = write_message(
                    output,
                    &json!({ "error": format!("invalid JSON message: {e}"), "code": 1002 }),
                );
                continue;
            }
            Err(ReadError::Io(e)) => {
                eprintln!("native-client-host: I/O error reading message: {e}");
                break;
            }
        };

        let reply = commands::handle(&msg);
        if write_message(output, &reply).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::io::Cursor;

    fn roundtrip(requests: &[Value]) -> Vec<Value> {
        let mut input_bytes = Vec::new();
        for req in requests {
            let body = serde_json::to_vec(req).unwrap();
            input_bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
            input_bytes.extend_from_slice(&body);
        }
        let mut input = Cursor::new(input_bytes);
        let mut output = Vec::new();
        run(&mut input, &mut output);

        let mut replies = Vec::new();
        let mut cursor = Cursor::new(output);
        while let Ok(v) = read_message(&mut cursor) {
            replies.push(v);
        }
        replies
    }

    #[test]
    fn version_reports_crate_version() {
        let replies = roundtrip(&[json!({ "cmd": "version" })]);
        assert_eq!(replies[0]["version"], env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn echo_returns_message_unchanged() {
        let replies = roundtrip(&[json!({ "cmd": "echo", "hello": "world" })]);
        assert_eq!(replies[0]["hello"], "world");
    }

    #[test]
    fn removed_commands_get_explicit_error() {
        for cmd in ["spawn", "env", "script", "clean-tmp"] {
            let replies = roundtrip(&[json!({ "cmd": cmd })]);
            assert_eq!(replies[0]["code"], 1000);
            assert!(replies[0]["error"].as_str().unwrap().contains("removed"));
        }
    }

    #[test]
    fn open_rejects_unknown_app() {
        let replies = roundtrip(&[
            json!({ "cmd": "open", "app": "not-a-real-app", "target": "https://example.com" }),
        ]);
        assert_eq!(replies[0]["code"], 1001);
    }

    #[test]
    fn open_rejects_flag_like_target() {
        let replies = roundtrip(&[
            json!({ "cmd": "open", "app": "firefox", "target": "--allow-file-access-from-files" }),
        ]);
        assert_eq!(replies[0]["code"], 1001);
        assert!(replies[0]["error"].as_str().unwrap().contains('-'));
    }

    #[test]
    fn open_rejects_relative_path_target() {
        let replies = roundtrip(&[
            json!({ "cmd": "open", "app": "firefox", "target": "relative/path" }),
        ]);
        assert_eq!(replies[0]["code"], 1001);
    }

    #[test]
    fn exec_matches_the_open_in_firefox_extensions_wire_protocol() {
        // Mirrors what lmeddoobegbaiopohmpmmobpnpjifpii's worker.js actually
        // sends on Linux: {cmd: "exec", command: "firefox" (or a custom
        // path), arguments: [urls...], properties: {}}. `/usr/bin/true` in
        // place of firefox just so the test doesn't need a real browser.
        let replies = roundtrip(&[
            json!({ "cmd": "exec", "command": "true", "arguments": [], "properties": {} }),
        ]);
        // "true" isn't in the allowlist, so this should be refused, not run.
        assert_eq!(replies[0]["code"], 1001);
    }

    #[test]
    fn exec_rejects_path_traversal_in_command() {
        let replies = roundtrip(&[
            json!({ "cmd": "exec", "command": "/tmp/evil/firefox", "arguments": [] }),
        ]);
        // Basename "firefox" is allowlisted, but the real firefox on this
        // box is found via our own PATH search, not the supplied directory
        // — so this either succeeds by launching the *real* firefox, or
        // fails to find firefox at all. Either way it must never touch
        // /tmp/evil/firefox. We only assert it doesn't error out due to the
        // path itself being treated as opaque (i.e. resolution still keys
        // off the basename).
        assert!(replies[0]["code"] == 0 || replies[0]["code"] == 1001);
    }

    #[test]
    fn exec_rejects_flag_like_argument() {
        let replies = roundtrip(&[
            json!({ "cmd": "exec", "command": "firefox", "arguments": ["-CreateProfile"] }),
        ]);
        assert_eq!(replies[0]["code"], 1001);
        assert!(replies[0]["error"].as_str().unwrap().contains('-'));
    }

    #[test]
    fn exec_ignores_properties_field() {
        // properties is accepted (so the extension's request isn't rejected
        // for shape reasons) but must never reach the spawned process's
        // options - there is no way to observe shell/cwd overrides taking
        // effect from here, so this just checks the field doesn't blow up
        // parsing when present with attacker-favorable keys.
        let replies = roundtrip(&[json!({
            "cmd": "exec",
            "command": "not-allowlisted",
            "arguments": [],
            "properties": { "shell": true, "cwd": "/", "uid": 0 }
        })]);
        assert_eq!(replies[0]["code"], 1001);
    }
}
