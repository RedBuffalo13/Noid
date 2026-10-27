# Noid Messenger — Installation & Setup Manual

## Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Windows 10+, Linux (glibc 2.31+), Android 10+ | Windows 11, Debian 12/Ubuntu 24.04, Android 12+ |
| RAM | 1 GB | 2 GB |
| Disk | 200 MB | 500 MB |
| Build tools | Rust stable, Node 20+, Tauri CLI | latest stable toolchain |

## Desktop — from source

```bash
git clone <repo> && cd noid
npm install
npm run tauri dev          # development
npm run tauri build        # release bundle
cargo build --release --bin noid  # binary only → target/release/noid[.exe]
```

## VPS / headless Linux node

```bash
git clone <repo> /opt/noid && cd /opt/noid
npm install
cd src-tauri && cargo build --release --bin noid
# run (GUI session :10 or a virtual display):
DISPLAY=:10 XAUTHORITY=/root/.Xauthority NOID_LOG=debug \
  nohup ./target/release/noid > /root/noid-app.log 2>&1 &
# open firewall
ufw allow 4020/tcp && ufw allow 4021/tcp && ufw allow 4020/udp
```

A public node needs port **4020/tcp+udp** (QUIC/TCP) and **4021/tcp**
(WebSocket). One process serves the relay, mailbox and DHT — do **not**
run any separate relay daemon.

## Android

```bash
npm run tauri android init              # once — generates gen/android scaffold
npm run tauri android build -- --apk    # APK in gen/android/app/build/outputs/apk/
adb install -r <apk-path>
```

**Windows workaround (symlink error).** `tauri android build` fails on Windows
without Developer Mode at the `.so` symlink step. The documented workaround:

```bash
# Rust lib is already compiled by the previous step — copy it manually:
cp src-tauri/target/aarch64-linux-android/release/libnoid_lib.so    src-tauri/gen/android/app/src/main/jniLibs/arm64-v8a/
# then package the APK directly via gradle (skipping the rustBuild task):
cd src-tauri/gen/android
ANDROID_HOME="$LOCALAPPDATA/Android/Sdk" JAVA_HOME="C:/Program Files/Android/Android Studio/jbr" ./gradlew.bat assembleArm64Release -x rustBuildArm64Release
# -> app/build/outputs/apk/arm64/release/app-arm64-release-unsigned.apk
```

Full details: `docs/ANDROID_BUILD.md` (SDK/NDK versions, FGS notes).

## First run

1. Launch → set **TruePIN** (8–64 chars). Optionally set a **KillPIN** —
  entering it instead of the PIN wipes all local data.
2. The node starts after unlock: listeners + bootstrap seeds dial
  automatically. Add peers via invite (`noid:<peerId>@<addr>`) or
  username search.
3. Send a message: on first contact the app fetches the peer's signed
  prekey bundle (direct request, DHT fallback), performs X3DH and
  encrypts via Double Ratchet. If the peer is offline, the envelope is
  parked on their mailbox node.

## Configuration

| File | Location | Purpose |
|------|----------|---------|
| `relay_config.json` | app data dir | role (auto/relay/client), privacy mode, ports |
| `bootstrap_nodes.json` | app data dir | extra seed nodes (bundled seeds are compiled in) |
| `noid.db` | app data dir | encrypted local storage |
| `noid.log` | app log dir | UTC-redacted logs (`NOID_LOG=debug` for diagnostics) |

Relay roles: `auto` (relays only when publicly reachable),
`relay` (forced public node), `client` (never relays).
Privacy: `direct` (default) or `relayed_only` (hides your IP from
peers — relays still see it).

## Updating an existing node

Replace the binary and restart the app. Database, keys, contacts and
ratchet states are preserved. Never run two instances on the same data
directory (single-instance lock will refuse the second one anyway).
