# Install guide — kvendra-cli v0.1.0

Detailed install instructions for each platform. For a quick install,
see the [README install section](../README.md#install).

## macOS (Intel + Apple Silicon)

### Option 1: cargo install (recommended)

```bash
cargo install --git https://github.com/KvendraAI/kvendra-cli kvendra
```

Requires Rust 1.75+. The build downloads ~50 dependencies and takes
~3-5 minutes on a modern machine.

### Option 2: pre-built binary

```bash
curl -L https://github.com/KvendraAI/kvendra-cli/releases/latest/download/kvendra-aarch64-apple-darwin -o kvendra
chmod +x kvendra
xattr -d com.apple.quarantine kvendra   # bypass Gatekeeper for unsigned binary
sudo mv kvendra /usr/local/bin/
kvendra --version
```

### Gatekeeper "unidentified developer" warning

Because v0.1.0 binaries are unsigned, macOS Gatekeeper warns the first
time you run them. Options:

1. **Recommended**: `xattr -d com.apple.quarantine kvendra` (one-time per binary).
2. **Alternative**: System Settings → Privacy & Security → scroll to
   "kvendra was blocked from use because it is not from an identified developer"
   → click "Open Anyway".

Touch ID-protected MCP password storage is **not available** in v0.1.0
and is planned for v0.2.0 (`ROAD-KVD-CLI-002`, requires Apple Developer ID).

## Linux (Debian / Ubuntu / Arch / Fedora)

### Option 1: cargo install (recommended)

```bash
cargo install --git https://github.com/KvendraAI/kvendra-cli kvendra
```

### Option 2: pre-built binary

```bash
curl -L https://github.com/KvendraAI/kvendra-cli/releases/latest/download/kvendra-x86_64-unknown-linux-gnu -o kvendra
chmod +x kvendra
sudo mv kvendra /usr/local/bin/
kvendra --version
```

### Distribution-specific notes

- **Debian/Ubuntu**: `sudo apt install build-essential pkg-config libssl-dev` before `cargo install`.
- **Arch**: `sudo pacman -S base-devel openssl` before `cargo install`.
- **Fedora**: `sudo dnf install gcc openssl-devel pkgconfig` before `cargo install`.

## Windows (msvc)

### Option 1: cargo install (recommended)

Install Rust via [rustup](https://rustup.rs/) with the `msvc` toolchain
(default on Windows). Then:

```powershell
cargo install --git https://github.com/KvendraAI/kvendra-cli kvendra
```

### Option 2: pre-built binary

Download `kvendra-x86_64-pc-windows-msvc.exe` from the latest release.

```powershell
Move-Item .\kvendra-x86_64-pc-windows-msvc.exe C:\Program Files\kvendra\kvendra.exe
$env:Path += ";C:\Program Files\kvendra"
kvendra --version
```

### SmartScreen "Unknown publisher" warning

Because v0.1.0 binaries are unsigned, Windows SmartScreen warns the
first time you run them. Click "More info" → "Run anyway".

Authenticode signing is planned for `ROAD-KVD-CLI-003` (post v0.2.0).

## Building from source (contributors)

```bash
git clone https://github.com/KvendraAI/kvendra-cli
cd kvendra-cli
cargo build --release
./target/release/kvendra --version
cargo test --release
```

## Verification

After install, run the bootstrap flow to verify a working install:

```bash
kvendra init
# follow prompts: master password, confirm code 0
kvendra --version
kvendra audit --json | head -5
```

Expected: `audit.db` row `vault_created` present, files in `~/.kvendra/`
with permissions `0600` (sentinel.blob, recovery_codes.json, config.toml)
and `0700` (the dir itself).

## What's next

- **Configure your first profile**: see the README quickstart section.
- **Run the smoke harness** (development): `bash scripts/e2e-smoke.sh`.
- **Read the security model**: see [`docs/security.md`](security.md).
