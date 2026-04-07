# OpenFortiVPN GUI - Design Specification

## Overview

A macOS menu bar (tray) application built with Tauri v2 + React that provides a graphical interface for `openfortivpn`. Supports multiple VPN profiles with both username/password and SAML authentication (via external browser).

## Decisions

| Decision | Choice |
|----------|--------|
| App format | Tray icon + small window |
| Credential storage | macOS Keychain |
| Sudo elevation | osascript native prompt |
| VPN backend | openfortivpn subprocess (direct) |
| SAML flow | openfortivpn `--saml-login` (built-in HTTP server) |
| Frontend | React + TypeScript |
| Styling | Tailwind CSS |
| Tauri version | v2 |

## Architecture

```
┌─────────────────────────────────────────────┐
│              Tauri App (macOS)               │
│                                             │
│  ┌─────────────┐     ┌───────────────────┐  │
│  │  React UI   │◄───►│  Tauri Commands   │  │
│  │  (Frontend)  │     │  (Rust Backend)   │  │
│  └─────────────┘     └───────┬───────────┘  │
│                              │              │
│                    ┌─────────▼──────────┐   │
│                    │  VPN Manager       │   │
│                    │  - ProfileStore    │   │
│                    │  - ProcessManager  │   │
│                    │  - KeychainAccess  │   │
│                    └─────────┬──────────┘   │
│                              │              │
└──────────────────────────────┼──────────────┘
                               │
              ┌────────────────▼────────────────┐
              │     openfortivpn (subprocess)    │
              └─────────────────────────────────┘
```

### Rust Backend Components

**VpnManager** (`vpn_manager.rs`): Central state machine. Holds current `ConnectionState`, active profile reference, and orchestrates connect/disconnect. Wrapped in `Arc<Mutex<>>` for thread-safe access from Tauri commands.

**ProcessManager** (`process_manager.rs`): Manages the openfortivpn subprocess lifecycle. Since `osascript` with `do shell script ... with administrator privileges` is synchronous (blocks until command exits), the process is spawned in background with output redirected to a temp log file:

- **Connect**: `osascript -e 'do shell script "openfortivpn [args] >> /tmp/openvpngui-{uuid}.log 2>&1 & echo $!" with administrator privileges'` — returns PID immediately
- **Monitor**: Tails the log file asynchronously from Rust, parsing lines for state changes
- **Disconnect**: `osascript -e 'do shell script "kill {pid}" with administrator privileges'`
- **Cleanup**: Removes temp log file after disconnect

Detects connection state from log output patterns:
- `"Tunnel is up"` → Connected
- `"Tunnel is down"` → Disconnected
- SAML URL pattern → WaitingSaml
- Error patterns → Error state

**ProfileStore** (`profile_store.rs`): CRUD operations for VPN profiles. Persists to `~/Library/Application Support/com.openvpngui.app/profiles.json`. Passwords are NOT stored here — only in Keychain.

**KeychainAccess** (`keychain.rs`): Wraps `security-framework` crate. Service name: `com.openvpngui.app`. Account format: `vpn-{profile_id}`. Operations: get_password, set_password, delete_password.

### Tauri Commands (Frontend → Backend)

| Command | Args | Returns |
|---------|------|---------|
| `get_profiles` | — | `Vec<VpnProfile>` |
| `save_profile` | `VpnProfile` + optional password | `Result<VpnProfile>` |
| `delete_profile` | `profile_id` | `Result<()>` |
| `connect` | `profile_id` | `Result<()>` |
| `disconnect` | — | `Result<()>` |
| `get_status` | — | `ConnectionState` |

### Tauri Events (Backend → Frontend)

| Event | Payload |
|-------|---------|
| `connection-status-changed` | `{ state, profile_id, ip?, duration? }` |
| `log-line` | `{ timestamp, level, message }` |
| `saml-url` | `{ url }` |

## Data Model

```rust
struct VpnProfile {
    id: String,                  // UUID v4
    name: String,                // Display name
    host: String,                // VPN gateway hostname
    port: u16,                   // Default: 8443
    auth_type: AuthType,         // Password | Saml
    username: Option<String>,    // For Password auth
    realm: Option<String>,       // Auth realm
    trusted_certs: Vec<String>,  // SHA256 digests
    extra_args: Vec<String>,     // Additional openfortivpn flags
}

enum AuthType {
    Password,
    Saml,
}

enum ConnectionState {
    Disconnected,
    Connecting { profile_id: String },
    WaitingSaml { profile_id: String, url: String },
    Connected { profile_id: String, ip: String, since: DateTime },
    Disconnecting,
    Error { message: String },
}
```

Profiles persisted at: `~/Library/Application Support/com.openvpngui.app/profiles.json`

## Connection Flows

### Username/Password

1. User selects profile, clicks "Connect"
2. Backend retrieves password from Keychain
3. Spawns via osascript (background + log file): `osascript -e 'do shell script "openfortivpn host:port -u user -p pass [--trusted-cert=xxx] [--realm=yyy] >> /tmp/openvpngui-{uuid}.log 2>&1 & echo $!" with administrator privileges'`
4. Captures PID from osascript output
5. Tails log file asynchronously → emits status events and log lines to frontend
6. Detects `"Tunnel is up"` in log → state = Connected
7. Disconnect: `osascript -e 'do shell script "kill {pid}" with administrator privileges'` + cleanup log file

### SAML

1. User selects SAML profile, clicks "Connect"
2. Spawns via osascript (background + log file): `osascript -e 'do shell script "openfortivpn host:port --saml-login [--trusted-cert=xxx] [--realm=yyy] >> /tmp/openvpngui-{uuid}.log 2>&1 & echo $!" with administrator privileges'`
3. Captures PID from osascript output
4. Tails log file → detects SAML URL (printed by openfortivpn when the local HTTP server starts)
5. Emits `saml-url` event to frontend
6. Frontend opens URL in system default browser via `tauri::shell::open`
7. User authenticates in browser
8. Browser redirects to `http://127.0.0.1:8020/?id=<session>` (captured by openfortivpn)
9. openfortivpn establishes tunnel → log shows `"Tunnel is up"`
10. State: Connecting → WaitingSaml → Connected

### Disconnect

1. User clicks "Disconnect" (or via tray menu)
2. Backend runs: `osascript -e 'do shell script "kill {pid}" with administrator privileges'`
3. Monitors log file for process exit / `"Tunnel is down"`
4. Cleans up temp log file
5. State: Connected → Disconnecting → Disconnected

## User Interface

### Tray Icon (Menu Bar)

- Status-indicating icon:
  - Disconnected: gray/outline shield icon
  - Connecting/WaitingSaml: yellow/animated icon
  - Connected: green/filled icon
- Left-click: toggles main window visibility
- Right-click context menu:
  - "Connect: {last_profile}" (quick connect)
  - "Disconnect" (when connected)
  - Separator
  - "Show Window"
  - "Quit"

### Main Window (~400x500px)

**Connection status area** (top):
- Current state with color indicator
- When connected: profile name, assigned IP, connection duration timer
- Connect/Disconnect button

**Profile list** (middle):
- List of saved profiles with name and auth type badge (SAML/Password)
- Active profile highlighted
- Gear icon per profile → opens editor
- "+ New Profile" button at bottom

**Footer**:
- Logs button → opens log viewer panel
- Settings button (future use)

### Profile Editor (replaces main content)

- Back button to return to profile list
- Fields: Name, Host, Port (default 8443), Auth type radio (SAML/Password)
- Conditional fields for Password auth: Username, Password
- Realm (optional)
- Trusted Certs list with add/remove
- Extra Args (optional, advanced)
- Save / Cancel buttons

### Log Viewer (slide-up panel or modal)

- Real-time display of openfortivpn stdout/stderr
- Auto-scroll with pause toggle
- Copy all logs button
- Clear logs button
- Monospace font, color-coded by level (info/warn/error)

## Trusted Certificate Management

When connecting to a new server, openfortivpn may report an untrusted certificate with its SHA256 digest. The app:
1. Detects the cert warning pattern in stdout
2. Shows a dialog: "Server presented an untrusted certificate: {digest}. Trust this certificate?"
3. If accepted: adds the digest to the profile's `trusted_certs` and reconnects with `--trusted-cert=<digest>`
4. If rejected: cancels connection

Users can also manually add/remove trusted certs in the profile editor.

## Project Structure

```
openvpngui/
├── src-tauri/
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   ├── capabilities/
│   ├── icons/
│   └── src/
│       ├── main.rs
│       ├── commands.rs
│       ├── vpn_manager.rs
│       ├── process_manager.rs
│       ├── profile_store.rs
│       ├── keychain.rs
│       └── models.rs
├── src/
│   ├── App.tsx
│   ├── main.tsx
│   ├── components/
│   │   ├── ConnectionStatus.tsx
│   │   ├── ProfileList.tsx
│   │   ├── ProfileEditor.tsx
│   │   ├── LogViewer.tsx
│   │   └── TrustedCertManager.tsx
│   ├── hooks/
│   │   ├── useVpnConnection.ts
│   │   └── useProfiles.ts
│   ├── types/
│   │   └── index.ts
│   └── styles/
├── package.json
├── tailwind.config.js
└── tsconfig.json
```

## Dependencies

### Rust (Cargo.toml)
- `tauri` 2.x
- `tauri-plugin-shell` — subprocess execution
- `security-framework` — macOS Keychain access
- `serde`, `serde_json` — serialization
- `uuid` — profile ID generation
- `tokio` — async runtime (bundled with Tauri)
- `chrono` — timestamps for logs and connection duration

### Frontend (package.json)
- `react` 18+, `react-dom`
- `@tauri-apps/api` — Tauri frontend bindings
- `@tauri-apps/plugin-shell` — open URLs in browser
- `tailwindcss`, `postcss`, `autoprefixer`
- `typescript`

## Verification Plan

1. **Build**: `cargo tauri dev` compiles and runs the app successfully
2. **Tray**: Icon appears in menu bar, changes color based on connection state
3. **Profiles CRUD**: Create, edit, delete profiles; verify JSON persistence survives app restart
4. **Keychain**: Save password for a profile → verify it appears in Keychain Access → retrieve it on next connect
5. **User/Pass Connection**: Connect to a FortiGate server with username/password, verify tunnel is up, verify disconnect works
6. **SAML Connection**: Connect with SAML profile, verify external browser opens with correct URL, complete SAML login, verify tunnel establishes
7. **Logs**: During connection, verify real-time log output appears in the log viewer
8. **Trusted Certs**: Connect to server with unknown cert, verify prompt appears, accept cert and verify reconnection succeeds
9. **Window behavior**: Tray click opens/closes window, window close hides to tray (doesn't quit app)
