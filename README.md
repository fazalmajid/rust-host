# native-client-host (Rust)

A drop-in replacement for the Node.js native-messaging host in this
repository (`host.js` / `messaging.js`), written in Rust. It speaks the same
Chrome/Firefox native-messaging framing and installs under the same
`com.add0n.node` manifest name, but supports a deliberately small, allowlisted
command set instead of the original's general-purpose "run anything" API.

## Why replace it

The Node host is invoked, unauthenticated beyond the browser's own
`allowed_origins`/`allowed_extensions` manifest check, by any of the ~50
third-party extension IDs hardcoded in `config.js` — "Open in Firefox",
"Open in GIMP", "Media Converter", "Tor Control", and others from a range of
unrelated authors. A security review of `host.js` found that its command set
turns that trust relationship into a generic remote-code-execution bridge,
not a narrow "open this URL in that app" helper. Summary of findings, most
severe first:

### Critical

**1. The `script` command runs arbitrary JavaScript in a fake sandbox.**
```js
const vm = require('vm');
const sandbox = { ..., require: name => (msg.permissions||[]).indexOf(name)===-1 ? null : require(name) };
const script = new vm.Script(msg.script);
script.runInContext(vm.createContext(sandbox));
```
Node's `vm` module is explicitly documented as *not* a security boundary —
escaping it to reach the real `process` object (and from there
`require('child_process')`, bypassing the `permissions` allowlist entirely)
is a well-known one-liner. Any allowlisted extension could send
`{script: "..."}` and get full, unsandboxed code execution as the local
user. This is the single worst flaw and has no safe equivalent — the Rust
host does not implement it.

**2. `spawn`/`exec` are unrestricted process-execution primitives.**
```js
const p = Array.isArray(msg.command) ? path.join(...msg.command) : msg.command;
const sp = spawn(p, msg.arguments || [], Object.assign({env: process.env}, msg.properties));
```
The executable path, argument list, environment, working directory, and
stdin are all fully attacker/extension-controlled. `msg.properties` is
merged straight into Node's `child_process` options, so a caller can set
`shell: true` and reintroduce shell-metacharacter injection even though
arguments are passed as an array (the entire point of the array form).

**3. Attacker-controlled `PATH`.**
```js
if (msg.env) { msg.env.forEach(n => process.env.PATH += path.delimiter + n); }
```
Any message can prepend directories to `PATH` before a `spawn`/`exec` call.
Combined with a relative `command`, this enables PATH-hijacking — a
"trusted" binary name like `firefox` can be silently shadowed by an
attacker-supplied executable.

### High

**4. Trust is delegated to ~50 hardcoded third-party extension IDs.**
Because of (1)–(3), compromise of *any single* extension in that list
(store account takeover, malicious auto-update, supply-chain attack) yields
silent, no-interaction-required arbitrary code execution on every machine
that has it installed — regardless of what permissions that extension
declared in its own store listing. Installing a lightweight "open this file
in that app" extension carries a hidden blast radius of "full RCE" that
isn't visible in the extension's own permission prompt.

**5. No caller authentication inside the host itself.** `observe()`
executes every command from stdin unconditionally, trusting the browser's
manifest enforcement as the only checkpoint. Reasonable for native
messaging in general, but the surface being gated is (1)–(3), not a narrow
action.

### Medium / lower

**6. Swallowed `fs.unlink` errors mean temp-file cleanup silently never
runs.** `fs.unlink` is async and requires a callback in current Node;
calling it without one throws synchronously, and the surrounding
`try { } catch (e) {}` eats that throw. The "delete temp files on exit" and
`clean-tmp` logic never actually deletes anything.

**7. Unguarded `sp.stdout`/`sp.stderr` access in the `spawn` handler** can
crash the whole host process if `msg.properties.stdio` overrides stdio to
something without pipes (denial of service for the session).

**8. `spec`/`env` return the full `process.env` to any allowlisted
extension** — an unnecessary disclosure of potentially sensitive
environment variables to ~50 third-party codebases.

## Design of the replacement

`src/protocol.rs` implements the same 4-byte-length-prefixed JSON framing as
`messaging.js`, plus a 1 MiB cap on incoming message size (the original had
no such cap, so a hostile length prefix could force an unbounded
allocation).

`src/apps.rs` holds a fixed allowlist of application ids
(`firefox`, `chrome`, `chromium`, `vlc`, `gimp`, ...) mapped to candidate
executable basenames. Resolution always searches the host process's *own*
inherited `PATH` — a message can never supply a path, an argument list, an
environment override, or a `PATH` prefix, closing findings (2) and (3).

`src/commands.rs` dispatches only four commands:

| Command   | Purpose                                                            |
|-----------|---------------------------------------------------------------------|
| `version` | Report the host version.                                          |
| `spec`    | Report version, path separator, tmpdir. No `env` dump (finding 8). |
| `echo`    | Echo the message back, for connectivity checks.                   |
| `open`    | Launch an allowlisted app id with one URL/path argument.           |
| `exec`    | Compatibility shim for extensions that speak the original `{cmd: "exec", command, arguments, properties}` shape (see below). |

`spawn`, `env`, `script`, and `clean-tmp` are recognized just well enough to
return an explicit "removed for security, here's why" error instead of a
bare "unknown command" — so existing extensions that hit them fail loudly
and informatively rather than silently.

### The `exec` compatibility shim

In practice, several existing "Open in X" extensions (e.g. the "Open in
Firefox" extension this repo targets) don't send `open` — they send
`{cmd: "exec", command, arguments, properties}` directly, built by their own
internal command-line construction logic. `exec` implements that same wire
shape, but with the original's dangerous parts removed rather than passed
through:

- `command`'s **basename** must match an allowlisted binary; any directory
  component the message included is discarded, and the real executable is
  found via the host's own `PATH` search — never the caller-supplied path.
  A request for `/tmp/evil/firefox` resolves (or fails) exactly like a
  request for plain `firefox` would.
- Every argument is rejected if it starts with `-`, so a value can never be
  interpreted as a flag by the launched application (argument injection).
- `properties` — the field the original host merged straight into
  `child_process` options, enabling `shell: true`, arbitrary `cwd`,
  `uid`/`gid`, etc. — is accepted (so requests aren't rejected on shape)
  but never used.
- The child is spawned with piped stdout/stderr and given up to ~1.5s to
  exit. If it exits in time (e.g. handing a URL off to an already-running
  browser instance, which returns almost immediately), the real exit code
  and output are reported. If it's still running past the timeout (e.g. a
  freshly-started browser with no existing instance to hand off to, which
  keeps running until the user closes it), the host stops waiting and
  reports success immediately rather than blocking the entire message loop
  on a long-lived GUI process — a background thread reaps it whenever it
  eventually exits.

## Known tradeoffs

This is **not** a behavior-preserving port. Any extension relying on
`spawn`, `exec` with a non-allowlisted binary, `env`, or `script` will get an
explicit error instead of the original functionality — e.g. Media
Converter's ffmpeg invocation or GIMP's temp-file conversion flow won't work
until their specific needs are added to `apps.rs` deliberately, rather than
inherited automatically the way the original host's generic `spawn`/`exec`
allowed. Extending the allowlist for a specific, understood use case is a
small, contained change; restoring generic command execution is not the
goal of this rewrite.
