# Noid Messenger — Presentation Text (for visual generation)

> Slide-by-slide text for a presentation / video / landing page.
> Every slide has a headline, body text and a visual cue.

## Slide 1 — Title
**Noid Messenger**
Your messages exist only on your devices.
Visual: dark hero, two devices exchanging a glowing encrypted stream; no
server icon anywhere.

## Slide 2 — The problem
Messengers today are post offices that read your letters.
Central servers store plaintext, metadata, contacts — forever.
Visual: a city of filing cabinets labelled "server" vs. a dark shield.

## Slide 3 — The idea
No server. No relay service. One binary does everything:
chat client + DHT node + relay + offline mailbox.
Visual: one icon split into four labelled roles.

## Slide 4 — Security in depth
PIN (Argon2id) → master key → AES-256-GCM storage.
X3DH handshake → Double Ratchet per contact.
Noise transport on QUIC/TCP/WebSocket.
KillPin erases everything instantly.
Visual: concentric shields around a device.

## Slide 5 — How peers find each other
Kademlia DHT: usernames, signed prekey bundles, mailbox pointers.
Invite codes carry addresses directly — invite → connect → talk.
Visual: a distributed mesh of nodes, some highlighted as relays.

## Slide 6 — Offline? No problem.
Encrypted envelopes wait in a mailbox node — another Noid client,
not a central server. Messages survive NAT, reboots, offline days.
Visual: sealed envelope resting on a friendly peer's node.

## Slide 7 — Same code, every platform
Windows · Linux/VPS · Android — one Rust core, one crypto stack,
one file format. Headless nodes run on any VPS.
Visual: three devices, one shared core glowing underneath.

## Slide 8 — Status: interim stable (Oct 2026)
Windows ↔ VPS live delivery verified: sessions, encryption, persistence,
outbox draining. 328 tests green. Android matrix is next.
Visual: a checklist with checked items and a forward arrow.

## Slide 9 — Open & auditable
Rust + Svelte + Tauri. Reproducible builds, testable crypto,
documented threat model — read the code, verify yourself.
Visual: terminal window showing the test suite passing.

## Slide 10 — The bottom line
Noid: messaging that belongs to you.
Visual: the banner — violet-to-green gradient circle, ECG-style pulse.

---
*Palette: #0a0a0b background, #121214 surfaces, #8b5cf6 violet accent,
#10b981 green accent, dark-first UI. Tone: confident, technical,
no marketing fluff.*
