# Privileged Helper Daemon — Design Spec

## Problem

The app currently uses `osascript` with `with administrator privileges` for every privileged operation (spawn openfortivpn, setup DNS, kill + cleanup). Each call triggers a macOS password dialog, resulting in 3+ password prompts per connect/disconnect cycle. This is unacceptable UX now that the concept is validated.

## Solution

Install a LaunchDaemon helper that runs as root and executes all privileged operations on behalf of the main app. The user authenticates once (during helper installation), and never again for VPN operations.

---

## Architecture

```
+---------------------------+       Unix Socket        +----------------------------+
|  OpenFortiVPN Connect     | ---- JSON req/resp ----> |  openvpngui-helper         |
|  (Tauri App - user)       | <--- JSON req/resp ----  |  (LaunchDaemon - root)     |
+---------------------------+                           +------------+---------------+
                                                                     |
                                                        +------------v---------------+
                                                        | openfortivpn / scutil      |
                                                        | route / kill / pppd        |
                                                        +----------------------------+
```

**Two processes:**

1. **App principal** (runs as user) — UI, profiles, keychain. Sends commands to helper via Unix socket. No `osascript`, no password prompts.
2. **openvpngui-helper** (runs as root via LaunchDaemon) — Listens on `/var/run/openvpngui-helper.sock`. Executes privileged operations: spawn/kill openfortivpn, setup/teardown DNS, route restoration.

**Fallback:** If the helper is not installed, the app works with the current osascript flow. The helper is an opt-in improvement on first launch, transparent after installation.

---

## Protocol

JSON over Unix domain socket (`/var/run/openvpngui-helper.sock`). Each connection is a single request/response, then closes.

### Commands

```json
// Ping (health check + version)
-> {"cmd": "ping"}
<- {"ok": true, "version": "0.1.0"}

// Spawn VPN (args are raw, no shell quoting — helper uses Command::new().args() directly)
-> {"cmd": "spawn-vpn", "args": ["host:port", "-u", "user", "-p", "s3cret", ...], "log_path": "/tmp/openvpngui-xxx.log"}
<- {"ok": true, "pid": 12345}

// Kill VPN
-> {"cmd": "kill-vpn", "pid": 12345, "gateway": "192.168.1.1"}
<- {"ok": true}

// Setup DNS
-> {"cmd": "setup-dns", "servers": ["10.0.0.1", "10.0.0.2"], "suffix": "corp.example.com"}
<- {"ok": true}

// Teardown DNS
-> {"cmd": "teardown-dns"}
<- {"ok": true}

// Error (any command)
<- {"ok": false, "error": "descriptive message"}
```

### Validation (Whitelist)

| Command | Validation |
|---------|-----------|
| `spawn-vpn` | Only executes hardcoded binary path (`/opt/homebrew/bin/openfortivpn`). Validates args contain no dangerous shell metacharacters. |
| `kill-vpn` | Only kills PIDs that the helper itself spawned (tracked in memory). |
| `setup-dns` | Validates servers are valid IPv4 addresses, suffix is a valid hostname. |
| `teardown-dns` | No parameters — fixed scutil command. |

---

## Installation and Lifecycle

### Installed Files

| File | Path |
|------|------|
| Helper binary | `/Library/PrivilegedHelperTools/com.openvpngui.helper` |
| LaunchDaemon plist | `/Library/LaunchDaemons/com.openvpngui.helper.plist` |
| Helper log | `/var/log/openvpngui-helper.log` |
| Socket | `/var/run/openvpngui-helper.sock` |

### LaunchDaemon Plist

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.openvpngui.helper</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/PrivilegedHelperTools/com.openvpngui.helper</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/openvpngui-helper.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/openvpngui-helper.log</string>
</dict>
</plist>
```

`KeepAlive: true` ensures macOS restarts the helper if it crashes. `RunAtLoad: true` starts it automatically on boot.

### First-Time Installation Flow

1. App starts -> tries `ping` on socket
2. Fails -> shows dialog: "Para conectar sem pedir senha repetidamente, precisamos instalar um componente auxiliar. Isso requer sua senha de administrador uma unica vez."
3. User confirms -> app uses `osascript` ONE TIME to:
   - Copy helper binary from bundle to `/Library/PrivilegedHelperTools/`
   - Copy plist to `/Library/LaunchDaemons/`
   - `launchctl load -w /Library/LaunchDaemons/com.openvpngui.helper.plist`
4. Helper starts, creates socket, responds to `ping`
5. App proceeds normally without further password prompts

### Update Flow

1. App starts -> `ping` returns `version`
2. If helper version < bundled version -> shows: "Uma atualizacao do componente auxiliar esta disponivel."
3. Same installation flow (osascript once)
4. `launchctl unload` -> replace binary -> `launchctl load`

### Reinstall via Settings

- "Reinstalar Helper" button in Settings screen
- Same installation flow
- Useful if something broke or after manual update

### If User Declines

- App works normally with current osascript flow (3+ password prompts)
- On next launch, asks again (with "Nao perguntar mais" option saved to settings)

---

## File Structure

### New Files

```
src-tauri/
  Cargo.toml                    # Becomes workspace root
  helper/
    Cargo.toml                  # Deps: tokio, serde, serde_json, log, env_logger
    src/
      main.rs                   # Daemon entry point
      server.rs                 # Unix socket listener + dispatch
      handlers.rs               # Command implementations (spawn, kill, dns)
      validation.rs             # Input validation (IPs, hostnames, args)
  src/
    helper_client.rs            # NEW - Unix socket client
    helper_installer.rs         # NEW - Detect, install, update helper
```

### Modified Files

| File | Change |
|------|--------|
| `src-tauri/Cargo.toml` | Convert to workspace with members `["."]` and `["helper"]` |
| `src-tauri/src/process_manager.rs` | `spawn_vpn()` and `kill_vpn()` call `helper_client` instead of `osascript`. Fallback to osascript if helper unavailable. |
| `src-tauri/src/dns_manager.rs` | `setup_dns()` and `teardown_dns()` call `helper_client`. Fallback to osascript. |
| `src-tauri/src/lib.rs` | On `setup()`, check if helper is installed. If not, emit event for frontend to show dialog. |
| `src-tauri/src/commands.rs` | Add `check_helper_status` and `install_helper` Tauri commands. |
| `src-tauri/tauri.conf.json` | Add helper binary as resource in bundle. |
| Frontend (Settings) | "Reinstalar Helper" button + helper status indicator. |
| Frontend (App) | First-time helper installation dialog. |

### Helper Dependencies (minimal)

```toml
[dependencies]
tokio = { version = "1", features = ["net", "rt-multi-thread", "macros", "io-util", "process"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
log = "0.4"
env_logger = "0.11"
```

No Tauri, no UI, no keychain — minimal attack surface.

### What Does NOT Change

- **Keychain** — Stays in main app (runs as user, accesses user's keychain)
- **Log monitor** — Stays in main app (reads openfortivpn log file)
- **Frontend** — Same components, same hooks. Only adds install dialog and Settings button.
- **Profile store** — No change
- **Tray** — No change

---

## Revised Flows

### Connect (with helper)

```
1. User clicks "Connect"
2. App -> helper_client::spawn_vpn(args, log_path)
   -> Socket: {"cmd":"spawn-vpn", "args":[...], "log_path":"/tmp/openvpngui-xxx.log"}
   <- {"ok":true, "pid":12345}
3. App starts log monitor (same as today, no change)
4. Log detects "Tunnel is up" -> App -> helper_client::setup_dns(servers, suffix)
   -> Socket: {"cmd":"setup-dns", "servers":["10.0.0.1"], "suffix":"corp.example.com"}
   <- {"ok":true}
5. App emits "Connected" event to frontend

Zero password prompts.
```

### Disconnect (with helper)

```
1. User clicks "Disconnect"
2. App -> helper_client::kill_vpn(pid, gateway)
   -> Socket: {"cmd":"kill-vpn", "pid":12345, "gateway":"192.168.1.1"}
   <- {"ok":true}
   (Helper internally does: kill, cleanup pppd, ifconfig, route restore, scutil DNS, flush cache)
3. App cleans up state, emits "Disconnected"

Zero password prompts.
```

### Fallback (without helper)

Fallback is **per-operation**: each individual call to `helper_client` tries the socket first, then falls back to osascript. This means if the helper goes down mid-session, the next operation falls back transparently.

```text
1. helper_client tries to connect to socket -> fails
2. Falls back to current flow: osascript with administrator privileges
3. Works exactly like today (3+ password prompts)
```

### Error Handling

| Scenario | Behavior |
|----------|----------|
| Helper crashed | `KeepAlive: true` restarts automatically. If socket fails, fallback to osascript. |
| Socket timeout | 5 second timeout. If expired, fallback to osascript. |
| Helper returns error | App shows message to user (same as osascript error today). |
| Helper asked to kill unmanaged PID | Helper rejects: `{"ok":false, "error":"PID not managed by helper"}` |
