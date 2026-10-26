# AGENTS.md — union-core

Follow the workspace rules in `../AGENTS.md`. Read [README.md](README.md) for project scope, setup, and standard validation commands.

## Documentation ownership

Keep project documentation in the root `AGENTS.md` and `README.md` only. Product content and required license files retain their existing locations. Workspace progress and evidence belong in `../TODO.md`; unresolved issues belong in `../PROBLEMS.md`. These workspace records are machine-local and are not published.

## Development boundaries

The protocol schema is defined in `crates/protocol/src/lib.rs`. Libraries live in `crates/`; cross-library acceptance inputs live in `tests/`. Keep this checkout adjacent to its consumers: `federated-server`, `union-manager`, and `FollyLauncher`.

Change only the affected subsystem. Use existing dependencies and build directories. Finish each batch before validation; select one validation channel and reuse successful evidence for unchanged inputs. Report skipped checks and device execution limits explicitly.
