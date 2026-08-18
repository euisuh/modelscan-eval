#!/usr/bin/env python3
"""Build deterministic M1 pickle fixtures."""

from __future__ import annotations

import pickle
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from corpus._marker import drop_canary  # noqa: E402


class CanaryPayload:
    """Technique: __reduce__; benign marker: drop_canary('.') only."""

    def __reduce__(self):
        return drop_canary, (".",)


def main() -> None:
    manifest = yaml.safe_load((ROOT / "corpus/manifest.yaml").read_text(encoding="utf-8"))
    output = {
        "malicious_reduce": pickle.dumps(CanaryPayload(), protocol=4),
        "clean": pickle.dumps({"format": "state_dict", "weights": [1.0, 2.0]}, protocol=4),
    }
    paths = {item["id"]: ROOT / item["path"] for item in manifest["items"]}
    if paths.keys() != output.keys():
        raise ValueError("manifest items must match generated fixtures")

    fixture_dir = ROOT / "corpus/fixtures"
    fixture_dir.mkdir(parents=True, exist_ok=True)
    for stale in fixture_dir.iterdir():
        if stale.is_file() and stale not in paths.values():
            stale.unlink()
    for item_id, data in output.items():
        paths[item_id].write_bytes(data)


if __name__ == "__main__":
    main()
