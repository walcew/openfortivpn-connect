# OpenFortiVpn Connect

A lightweight, open-source macOS GUI client for [openfortivpn](https://github.com/adrienverge/openfortivpn).

![OpenFortiVpn Connect](docs/screenshots/openfortivpn-connect.png)

## Why?

If you've ever used the official FortiClient on macOS, you know the pain: bloated, buggy, and unreliable. Constant crashes, broken updates, and features you never asked for getting in the way of the one thing you need — a VPN connection.

I got tired of depending on it. So I built **OpenFortiVpn Connect** — a minimal, native macOS GUI that wraps the excellent [openfortivpn](https://github.com/adrienverge/openfortivpn) CLI tool. No telemetry, no bloat, no surprises. Just a clean interface to manage your VPN profiles and connect.

The UI is inspired by [OpenVPN Connect](https://openvpn.net/client/) — simple, focused, and easy to use. Built with native macOS vibrancy for a modern frosted glass look that blends with your desktop.

## Features

- **Multiple VPN profiles** — save and switch between different VPN connections
- **SAML authentication** — full support for SSO/SAML login flows
- **Password auth** — credentials stored securely in the macOS Keychain
- **Certificate trust management** — pin server certificates by SHA256 digest
- **Native macOS look** — vibrancy blur, overlay title bar, system tray integration
- **System tray** — connect/disconnect and switch profiles without opening the app
- **Real-time logs** — monitor connection logs with optional debug mode
- **Lightweight** — small binary, minimal resource usage

## Installation

### Homebrew (recommended)

```bash
brew tap walcew/tap
brew install --cask openfortivpn-connect
```

`openfortivpn` is bundled in the app (no separate CLI install).

### Manual

Download the `.dmg` for your architecture from [Releases](https://github.com/walcew/openfortivpn-connect/releases):

- **Apple Silicon (M1/M2/M3/M4):** `OpenFortiVpn.Connect_x.x.x_aarch64.dmg`
- **Intel:** `OpenFortiVpn.Connect_x.x.x_x64.dmg`

## Prerequisites

- macOS 12 (Monterey) or later

## Building from Source

### Requirements

- [Rust](https://rustup.rs/) (1.77.2+)
- [Node.js](https://nodejs.org/) (18+)
- [Tauri CLI](https://tauri.app/)
- A C toolchain to compile the bundled openfortivpn/OpenSSL: **Homebrew and/or Xcode Command Line Tools**

`scripts/build-openfortivpn.sh` picks what is available:

1. autoconf/automake already on `PATH`
2. else **Homebrew** (`brew install autoconf automake`)
3. else bootstrap autotools with **Xcode CLT** (`clang`/`make`/`perl`) - slower, first run only

Compiling from source always needs a compiler: there is no zero-toolchain path. Installing the DMG does not need Homebrew or Xcode CLT.

### Build

```bash
npm install
npm run build:openfortivpn
cargo tauri build
```

By default `npm run build:openfortivpn` fetches the latest [openfortivpn](https://github.com/adrienverge/openfortivpn) release (`OPENFORTIVPN_VERSION=latest`). Pin a tag for reproducible builds, e.g. `OPENFORTIVPN_VERSION=v1.24.1`.

### Development

```bash
cargo tauri dev
```

## Tech Stack

- **Backend:** [Tauri v2](https://tauri.app/) + Rust
- **Frontend:** React 19 + TypeScript + Tailwind CSS v4
- **VPN engine:** bundled [openfortivpn](https://github.com/adrienverge/openfortivpn) (statically linked OpenSSL)
- **Security:** macOS Keychain for credential storage
- **DNS:** Native macOS `scutil` integration

### Where to edit identity / shared values

| What | File |
|------|------|
| App + helper version | `src-tauri/Cargo.toml` → `[workspace.package].version` |
| Names, paths, repo, bundle ids, cask, … | `src-tauri/common/src/lib.rs` |

Derived files (frontend constants, `tauri.conf.json` fields, `package.json` name/version, `project.env`, …) are regenerated when you run `cargo tauri dev` or `cargo tauri build` (via `src-tauri/build.rs`). Do not edit those by hand.

## Credits

- [openfortivpn](https://github.com/adrienverge/openfortivpn) by Adrien Vergé — the open-source CLI tool that makes this project possible
- [OpenVPN Connect](https://openvpn.net/client/) — UI inspiration for the clean, profile-based interface
- [Tauri](https://tauri.app/) — the framework powering this native desktop app

## Disclaimer

This project is **not affiliated with, endorsed by, or associated with Fortinet, FortiClient, FortiGate, or FortiVPN** in any way. These are registered trademarks of Fortinet, Inc. This is an independent, open-source project that provides a graphical interface for the community-driven [openfortivpn](https://github.com/adrienverge/openfortivpn) tool.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

The bundled [openfortivpn](https://github.com/adrienverge/openfortivpn) binary is GPL-3.0; its source is available upstream. OpenSSL is linked statically into that binary.

## Author

**Wallacy Santos Ferreira** — [@walcew](https://github.com/walcew)
