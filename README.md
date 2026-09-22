# union-core

Minecraft-independent federation protocol and tournament state machine.

- PeerId identities, QUIC / TCP Noise, bounded framing, explicit service directories, scoped grants and optional Circuit Relay v2.
- League roster consent, configurable cross-school participation and seats, seeded random selection, adaptive reconnect grace and substitutes, seat epochs, two scoreboards.
- Signed optimistic commands and durable single-writer journal (protocol `/jlucraft/union/governance/2`, signature domain `jlucraft/governance/1`).
- Delegated school identity credentials with local trust roots, expiry/revocation and device/profile binding. Email affiliation and current enrollment are separate checks.
- `client` is shared by JNI and Tauri; `tools/unionctl` supports governance, grants and student delegation tools.

```sh
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
```

This is not Byzantine consensus. One league currently represents one match. A snapshot must fit a 64 KiB protocol frame; oversized state mutations are rejected. League enrollment still requires administrator enrollment. StudentPresentation supports authenticated stream admission under an explicitly configured Students policy; the application receives verified claims and must still bind them to actual game login. Minecraft authentication and backend switching belong to a protocol proxy adapter; opaque service streams alone cannot perform a live switch.
