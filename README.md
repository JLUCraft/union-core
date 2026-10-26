# Shared federation libraries

A library-only Cargo workspace for JLUCraft identity, protocol, governance, networking, organization workflows, activity points, AI requests, and terminal runtime.

## Setup and structure

The protocol schema is defined in `crates/protocol/src/lib.rs`. Libraries live in `crates/`; cross-library acceptance inputs live in `tests/`. Keep this checkout adjacent to its consumers: `federated-server`, `union-manager`, and `FollyLauncher`.

## Validation

Select one validation channel for a batch and reuse successful results for unchanged inputs. Standard commands:

```sh
python3 scripts/check-layers.py
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Read [AGENTS.md](AGENTS.md) before making changes.
