#!/usr/bin/env python3
"""Reject platform dependency cycles and transport imports in pure lower layers."""
from pathlib import Path
import tomllib
import json
import subprocess

root = Path(__file__).resolve().parents[1]
allowed = {
    "protocol": set(),
    "terminal-runtime": {"state", "node", "authority"},
    "identity": {"protocol"},
    "state": {"protocol", "identity"},
    "league": {"protocol", "identity", "state"},
    "journal": {"protocol", "identity", "state"},
    # Durable revocation views intentionally come from journal, not a caller-created watch.
    "node": {"protocol", "identity", "journal"},
    "authority": {"protocol", "identity", "state", "journal", "node"},
    "events": {"state", "protocol", "node", "league"},
    "flows": {"state", "protocol"},
    "llm-gateway": {"protocol"},
    "client": {"league", "events", "flows", "protocol", "identity", "state", "authority", "node"},
}
for name, permitted in allowed.items():
    manifest = tomllib.loads((root / "crates" / name / "Cargo.toml").read_text())
    dependencies = manifest["dependencies"]
    local = {key for key, value in dependencies.items() if isinstance(value, dict) and "path" in value}
    assert local <= permitted, (name, "forbidden dependency", local - permitted)
    if name == "events":
        assert dependencies["node"].get("optional") is True, "document transport must stay optional"
    if name in {"protocol", "identity", "state", "league"}:
        forbidden = {"tokio", "libp2p", "libp2p-stream", "reqwest", "openraft"}
        assert not forbidden.intersection(dependencies), (name, "transport in pure layer")
print("platform dependency layers verified")

metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"], cwd=root))
for package in metadata["packages"]:
    assert all("bin" not in target["kind"] for target in package["targets"]), (package["name"], "executable in library workspace")
print("library workspace has no executable targets")
