---
name: vpnconnect
description: "Operate the OpenFortiVpn Connect VPN (FortiGate SSL VPN on macOS) with the vpnconnect CLI: connect and disconnect a VPN, read the VPN status, follow the session live, manage Profiles (add, edit, remove, saved password, trusted certificates), change the app settings and check or install the Helper. Use when the user asks to connect or disconnect the VPN, whether the VPN is up, why the internal network, a cluster or an internal host is unreachable, or to create or change a VPN Profile."
---

# vpnconnect

`vpnconnect` is the command line of OpenFortiVpn Connect. It is the app's own executable, so the app window and the CLI are equal clients of the same VPN session, which lives in the Helper (a root daemon). A session started by one shows in the other, and it stays up after the command returns or the terminal closes.

This skill ships inside the binary. `vpnconnect skill install` installs or refreshes it for every agent on this Mac; run it again after the app updates.

## Learn the current CLI

The installed binary is the authority for syntax and flags. Read the help of the command you are about to run:

```bash
vpnconnect --help
vpnconnect connect --help
vpnconnect profile add --help
```

Help and version exit with 0. The long descriptions say how flags combine and what `--json` prints. This skill adds only what the help cannot say: who does what, the order, and the rules.

## Console user only

The Helper answers only root and the user logged in at the Mac's console. Over SSH, or from any other session, every command that talks to the Helper fails with `HELPER_UNAUTHORIZED` (exit 255). Report it and stop; retrying cannot help. Profile, settings and `skill` commands do not need the Helper.

## What is human

Ask the human, then wait. Never guess or work around these:

- SAML login: the human signs in on the gateway page in the browser.
- OTP: the human reads the code from their authenticator; codes are single-use and short-lived.
- FortiToken push: the human approves on the phone.
- Trusting a certificate (`profile trust`, `--auto-trust`): the human decides after checking the digest.
- The administrator password of the Helper install: typed by the human in the macOS dialog.
- The Profile's password: it comes from the human or from a secret store you are allowed to read.

## Connect

```bash
vpnconnect connect <profile> --json
vpnconnect connect <profile> --otp <code> --json
vpnconnect connect <profile> --no-browser --timeout 300
```

`<profile>` is an id or an exact name (see Profiles). `connect` blocks until the session is up (exit 0, prints the status) or has failed (exit 1 or 255 with an error code). The default `--timeout` is 120 s; at the limit it cancels the pending login and exits `TIMEOUT`.

1. Run `vpnconnect status --json` first. A session already active, whoever started it, is not yours to replace: `connect` refuses with `SESSION_ACTIVE`. If it is the Profile you need, use it; otherwise tell the human.
2. A password Profile needs `has_password: true` (`profile show`). The CLI reads the password from the Keychain without a prompt. Without it, `CREDENTIALS_MISSING`: ask the human for the password and save it (see Profiles).
3. An OTP Profile (`otp_required: true`) needs `--otp <code>`. Ask the human for a fresh code just before you run the command. Without it, `OTP_REQUIRED`.
4. A SAML Profile prints the login URL on stderr and opens the default browser. With `--no-browser` it only prints. A FortiToken push prints on stderr that it waits for the phone. Run `connect` in the background, read stderr, tell the human what to do (show the URL, ask for the approval) and wait for the exit.
5. On `CERT_UNTRUSTED` the error carries `cert_digest`. Show the human the digest and the command `vpnconnect profile trust <profile> <digest>`, then stop. The human verifies the certificate and runs it. Run it yourself only when the human, having seen this digest, tells you to.
6. `HELPER_NOT_INSTALLED` and `HELPER_OUTDATED` mean the Helper needs `vpnconnect helper install`; tell the human (see Helper).

Ctrl-C or SIGINT during `connect` cancels the pending login and exits 130. After a successful `connect` there is nothing to keep running.

## Status

```bash
vpnconnect status --json
```

Prints the Helper's state as-is plus `profile` (`{"id","name"}`, or `null` without a session; `name` is `null` if the Profile no longer exists here). `state` is `disconnected`, `connecting`, `waiting-saml` (with `url`), `waiting-push` or `connected`. A connected session has `ip`, `since`, `expires_at`, `dns_servers` and `dns_suffixes`. After a drop, `disconnected` carries `reason` and `cause` (`tunnel-dropped`, `expired`).

When an internal host is unreachable, read `status` before anything else:

- `connected`: the VPN is up; the problem is the host, the route or the DNS, so say so.
- `disconnected`: report `reason` and `cause`, then ask the human whether to connect.
- `waiting-saml` or `waiting-push`: a login is pending and needs the human.
- `HELPER_NOT_INSTALLED`, `HELPER_OUTDATED` or `HELPER_UNAVAILABLE`: run `vpnconnect helper status` (see Helper).

`vpnconnect disconnect` ends the session or cancels a pending login, whoever started it, and exits 0 when there is none. Run it only when the human asks you to disconnect, or to cancel a login your own `connect` started.

## Follow the session

```bash
vpnconnect watch
```

`watch` is always NDJSON on stdout, with or without `--json`: one object per line, each with an `event` field (`state`, `log`, `bandwidth`, `expiring`, `reconnecting`). The first line is the current state; nothing from the past is replayed. `--help` lists the events.

- `reconnecting` (with `in_ms`) is not an error: the Helper is unreachable, as in a restart, and `watch` retries by itself and streams again.
- It runs until stopped. Start it in the background and read its output; stop it with SIGINT (exit 130) or by killing the process. Stop it when you no longer need it.
- Only `HELPER_UNAUTHORIZED` (255) ends it by itself (see Console user only).

## Profiles

A Profile is a saved gateway: host, port, authentication (`password` or `saml`), username, realm, OTP flag, trusted certificates, split-DNS domains.

```bash
vpnconnect profile ls --json
vpnconnect profile show <profile> --json
vpnconnect profile add --name <name> --host <host> --auth password --username <user> --dns-domain corp.example.com
vpnconnect profile edit <profile> --port 443
vpnconnect profile rm <profile>
vpnconnect profile set-password <profile> --password-stdin
vpnconnect profile clear-password <profile>
vpnconnect profile trust <profile> <sha256>
vpnconnect profile untrust <profile> <sha256>
```

- Target a Profile by id or exact name. A partial or ambiguous name is refused (`PROFILE_NOT_FOUND`, `PROFILE_AMBIGUOUS`); take the id from `profile ls`.
- `profile add` and `profile edit` take the same flags, and `edit` changes only the flags passed. `--dns-domain` repeats and replaces the whole list; `--clear-dns-domains` empties it.
- The password goes in through stdin only, never as an argument: `printf '%s' "$PW" | vpnconnect profile set-password <profile> --password-stdin`. Read `$PW` from the human or a secret store into the pipe, not into a file. `profile show` reports `has_password`; no command prints the password.
- `profile rm` asks nothing and deletes the saved password too. Run it only when the human asks, naming the Profile.
- `--auto-trust` accepts whatever certificate the gateway presents. Set it only when the human asks for it for that Profile.

## Settings

```bash
vpnconnect settings show --json
vpnconnect settings set dns-fallback on
```

`dns-fallback` lets names the VPN DNS cannot resolve fall back to the system DNS. Change a setting only when the human asks.

## Helper

```bash
vpnconnect helper status --json
vpnconnect helper install
vpnconnect helper uninstall
```

`helper status` prints `installed`, `running`, `version` and `needs_update`, and exits 0 even when the Helper is down. `helper install` installs or updates it, `helper uninstall` removes it. Both open the macOS administrator dialog for the human to type the password, so run them only when the human asks and tell them the dialog is coming. `HELPER_INSTALL_CANCELLED` means the human declined: do not retry.

## Output and exit codes

Without `--json`, stdout is for people. With `--json`, stdout carries only JSON, on one line (`watch` is NDJSON either way). Progress, warnings and the SAML URL go to stderr. Errors go to stderr as `{"error":{"code","message"}}`, plus `cert_digest` for `CERT_UNTRUSTED`. The CLI never prompts, even with a terminal. Branch on `code`, not on the message.

| Exit | Meaning |
|---|---|
| 0 | success |
| 1 | refused by the Helper, the gateway or a pre-connect check; the Helper install was cancelled or failed |
| 255 | CLI failure: bad argument, Helper unavailable |
| 130 | interrupted (Ctrl-C) |

| Code | Exit | What it means and what to do |
|---|---|---|
| `HELPER_REFUSED` | 1 | The Helper refused the request; read the message and report it |
| `PROFILE_NOT_FOUND` | 1 | No Profile with that id or exact name; check `profile ls` |
| `PROFILE_AMBIGUOUS` | 1 | The name matches several Profiles; use the id |
| `PROFILE_NAME_TAKEN` | 1 | Profile names are unique; pick another |
| `INVALID_DNS_DOMAIN` | 1 | A `--dns-domain` the app would reject; fix the value |
| `INVALID_CERT_DIGEST` | 1 | Not a sha256 (64 hex characters); copy it again |
| `OTP_REQUIRED` | 1 | The Profile needs an OTP; ask the human for a code, pass `--otp` |
| `CREDENTIALS_MISSING` | 1 | No saved password; ask the human, then `profile set-password` |
| `SESSION_ACTIVE` | 1 | A session is already up; keep it (see Connect) |
| `CERT_UNTRUSTED` | 1 | The gateway certificate is unknown; show `cert_digest` to the human |
| `LOGIN_FAILED` | 1 | The gateway rejected the login (password, OTP); ask the human, do not loop |
| `CONNECT_FAILED` | 1 | The session failed after login; report the message |
| `CONNECT_CANCELLED` | 1 | The login ended before the session came up; ask whether to retry |
| `TIMEOUT` | 1 | No session within `--timeout`; the login was cancelled. Ask the human, retry once |
| `HELPER_INSTALL_CANCELLED` | 1 | The human closed the administrator dialog; do not retry |
| `HELPER_INSTALL_FAILED` | 1 | The install failed; report the message |
| `CLI_ERROR` | 255 | Usage or unexpected CLI failure; read `--help` of the command |
| `INVALID_ARGUMENT` | 255 | A bad value or flag combination; read `--help` of the command |
| `HELPER_UNAVAILABLE` | 255 | The Helper does not answer; `helper status`, then the human |
| `HELPER_UNAUTHORIZED` | 255 | Not the console user, as over SSH; report and stop |
| `HELPER_NOT_INSTALLED` | 255 | No Helper; the human runs `vpnconnect helper install` |
| `HELPER_OUTDATED` | 255 | The Helper is older than the app; the human runs `vpnconnect helper install` |

## Safety rules

- Leave the decision to trust a certificate to the human: show the digest, wait.
- Keep the password off command lines, `echo`, files and logs: stdin only.
- Leave a session the human opened as it is: no `disconnect`, no replacing it with `connect`, unless they ask.
- Treat `profile rm`, `helper uninstall`, `--auto-trust` and settings changes as the human's calls; run them on request.
- Ask the human for every OTP and every approval; never reuse an old code.
- Stop at `HELPER_UNAUTHORIZED`, `HELPER_INSTALL_CANCELLED` and `LOGIN_FAILED`; report instead of retrying.
