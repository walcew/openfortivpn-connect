# Icon Customization — Design Specification

## Overview

Custom icon system for the OpenFortiVPN GUI app, replacing the default Tauri icons with a shield + padlock design. Includes a dock icon (full color) and two tray icon variants (connected/disconnected) following macOS template image conventions.

## Design Decisions

| Decision | Choice |
|----------|--------|
| Shield shape | Wide, flat-top, thick outline, pointed bottom |
| Dock icon | White shield on blue gradient background (#4A9EF5 → #2563EB) |
| Tray disconnected | Outline shield + open padlock (template image) |
| Tray connected | Filled shield + closed padlock (template image) |
| Tray format | macOS template images (single-color PNGs, system adapts to light/dark) |
| Source format | SVG masters → exported to PNG at required resolutions |
| Icon generation | Manual SVG + script to convert SVG → PNG via `rsvg-convert` or `sips` |

## Icon Assets

### 1. Dock Icon (App Icon)

**Visual:** White outline shield with closed padlock on a blue gradient background (#4A9EF5 → #2563EB). The gradient goes from top-left to bottom-right.

**SVG Definition:**
```svg
<svg viewBox="0 0 1024 1024" xmlns="http://www.w3.org/2000/svg">
  <!-- Blue gradient background (full canvas, macOS applies squircle mask) -->
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#4A9EF5"/>
      <stop offset="100%" stop-color="#2563EB"/>
    </linearGradient>
  </defs>
  <rect width="1024" height="1024" fill="url(#bg)"/>

  <!-- Shield (white outline, wide flat-top) -->
  <g transform="translate(512,480) scale(5.8)">
    <path d="M0 -72 L-65 -50 L-65 -2 C-65 28 -35 58 0 72 C35 58 65 28 65 -2 L65 -50 Z"
          fill="none" stroke="white" stroke-width="10" stroke-linejoin="round"/>
    <!-- Padlock body -->
    <rect x="-20" y="6" width="40" height="30" rx="5" fill="white"/>
    <!-- Padlock shackle (closed) -->
    <path d="M-13 6 V-8 C-13 -22 13 -22 13 -8 V6"
          fill="none" stroke="white" stroke-width="6" stroke-linecap="round"/>
    <!-- Keyhole -->
    <circle cx="0" cy="17" r="5" fill="#3B82F6"/>
    <rect x="-2" y="17" width="4" height="9" rx="1" fill="#3B82F6"/>
  </g>
</svg>
```

**Required output files (in `src-tauri/icons/`):**
- `icon.png` — 1024×1024 (master)
- `icon.icns` — macOS app icon bundle (16, 32, 64, 128, 256, 512, 1024)
- `icon.ico` — Windows icon (16, 32, 48, 256)
- `32x32.png` — 32×32
- `128x128.png` — 128×128
- `128x128@2x.png` — 256×256
- `Square*Logo.png` — Windows Store variants (existing sizes maintained)

### 2. Tray Icon — Disconnected

**Visual:** Outline shield (not filled) with open padlock (shackle raised on right side). Single color — black pixels on transparent background. macOS renders as template image, adapting to menu bar appearance.

**Template image note:** macOS template images use the alpha channel only. Black pixels (any color, actually) with alpha=1 are tinted to match the menu bar. Transparent pixels (alpha=0) show through. The SVGs below use `fill="white"` to represent cutouts for visual clarity, but the final PNGs must use **transparent pixels** (alpha=0) instead of white for all cutout areas (keyholes, padlock body in connected state). The `generate-icons.sh` script handles this conversion.

**SVG Definition:**
```svg
<svg viewBox="0 0 22 24" xmlns="http://www.w3.org/2000/svg">
  <g transform="translate(11,11.5) scale(0.135)">
    <!-- Shield outline only -->
    <path d="M0 -72 L-65 -50 L-65 -2 C-65 28 -35 58 0 72 C35 58 65 28 65 -2 L65 -50 Z"
          fill="none" stroke="black" stroke-width="10" stroke-linejoin="round"/>
    <!-- Padlock body -->
    <rect x="-20" y="6" width="40" height="30" rx="5" fill="black"/>
    <!-- Padlock shackle (OPEN - right side raised) -->
    <path d="M-13 6 V-8 C-13 -22 13 -22 13 -14"
          fill="none" stroke="black" stroke-width="6" stroke-linecap="round"/>
    <!-- Keyhole (transparent) -->
    <circle cx="0" cy="17" r="5" fill="white"/>
    <rect x="-2" y="17" width="4" height="9" rx="1" fill="white"/>
  </g>
</svg>
```

**Required output files (in `src-tauri/icons/`):**
- `tray-disconnected.png` — 22×24 (@1x)
- `tray-disconnected@2x.png` — 44×48 (@2x, Retina)

### 3. Tray Icon — Connected

**Visual:** Filled shield with closed padlock (inverted colors — padlock cutout from filled shield). Single color — black pixels on transparent background.

**SVG Definition:**
```svg
<svg viewBox="0 0 22 24" xmlns="http://www.w3.org/2000/svg">
  <g transform="translate(11,11.5) scale(0.135)">
    <!-- Shield FILLED -->
    <path d="M0 -72 L-65 -50 L-65 -2 C-65 28 -35 58 0 72 C35 58 65 28 65 -2 L65 -50 Z"
          fill="black" stroke="black" stroke-width="10" stroke-linejoin="round"/>
    <!-- Padlock body (cutout/white) -->
    <rect x="-20" y="6" width="40" height="30" rx="5" fill="white"/>
    <!-- Padlock shackle (CLOSED, cutout/white) -->
    <path d="M-13 6 V-8 C-13 -22 13 -22 13 -8 V6"
          fill="none" stroke="white" stroke-width="6" stroke-linecap="round"/>
    <!-- Keyhole (black, matches fill) -->
    <circle cx="0" cy="17" r="5" fill="black"/>
    <rect x="-2" y="17" width="4" height="9" rx="1" fill="black"/>
  </g>
</svg>
```

**Required output files (in `src-tauri/icons/`):**
- `tray-connected.png` — 22×24 (@1x)
- `tray-connected@2x.png` — 44×48 (@2x, Retina)

## Implementation

### Icon Files

1. Create SVG source files in `src-tauri/icons/svg/`:
   - `dock-icon.svg` — dock/app icon
   - `tray-disconnected.svg` — tray disconnected state
   - `tray-connected.svg` — tray connected state

2. Convert SVGs to PNGs using a script (`src-tauri/icons/generate-icons.sh`):
   - Uses `rsvg-convert` (from `librsvg`, install via `brew install librsvg`)
   - Generates all required PNG sizes from SVG sources
   - Generates `.icns` via `iconutil` (macOS built-in)
   - Generates `.ico` via `png2ico` or ImageMagick

### Tray Icon Switching (Rust)

Modify `src-tauri/src/tray.rs` to:

1. Load both tray icon PNGs at startup using `tauri::image::Image::from_bytes()` with the `include_bytes!` macro
2. Add a `pub fn update_tray_icon(app: &AppHandle, state: &ConnectionState)` function that:
   - Matches on `ConnectionState`
   - `Disconnected | Error { .. }` → set disconnected icon
   - `Connected { .. }` → set connected icon
   - `Connecting { .. } | WaitingSaml { .. } | Disconnecting` → set disconnected icon (transitional states use disconnected appearance)
3. Call `tray.set_icon()` with the appropriate icon
4. Keep `icon_as_template(true)` so macOS adapts colors

Call `update_tray_icon` from `VpnManager::set_state()` whenever state changes, alongside the existing `refresh_tray_menu` call.

### Files to Modify

| File | Change |
|------|--------|
| `src-tauri/icons/svg/dock-icon.svg` | New — SVG source for dock icon |
| `src-tauri/icons/svg/tray-disconnected.svg` | New — SVG source for tray (disconnected) |
| `src-tauri/icons/svg/tray-connected.svg` | New — SVG source for tray (connected) |
| `src-tauri/icons/generate-icons.sh` | New — conversion script |
| `src-tauri/icons/*.png` | Regenerated from new SVGs |
| `src-tauri/icons/icon.icns` | Regenerated |
| `src-tauri/icons/icon.ico` | Regenerated |
| `src-tauri/src/tray.rs` | Add icon loading + `update_tray_icon()` function |
| `src-tauri/src/vpn_manager.rs` | Call `update_tray_icon` on state changes |

## Verification

1. **Build**: `cargo tauri dev` — app compiles and launches
2. **Dock icon**: Blue gradient shield visible in macOS dock
3. **Tray disconnected**: Outline shield with open padlock in menu bar, adapts to light/dark mode
4. **Tray connected**: Filled shield with closed padlock after VPN connects
5. **State transitions**: Icon changes correctly through Disconnected → Connecting → Connected → Disconnecting → Disconnected
6. **Retina**: Icons render crisp on Retina displays (check @2x variants)
7. **Light/dark mode**: Toggle macOS appearance, verify tray icon adapts automatically
