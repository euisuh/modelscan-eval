from __future__ import annotations

import argparse
import json
from dataclasses import asdict, replace
from pathlib import Path

import yaml

from scanners.opcode_baseline import OpcodeBaseline


ROOT = Path(__file__).resolve().parents[1]
SCANNERS = {OpcodeBaseline.name: OpcodeBaseline}


def run(scanner_name: str):
    adapter = SCANNERS[scanner_name]()
    manifest = yaml.safe_load((ROOT / "corpus/manifest.yaml").read_text(encoding="utf-8"))
    return [replace(adapter.scan(ROOT / item["path"]), item_id=item["id"]) for item in manifest["items"]]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scanner", choices=SCANNERS, default=OpcodeBaseline.name)
    args = parser.parse_args()
    for verdict in run(args.scanner):
        print(json.dumps(asdict(verdict), sort_keys=True))


if __name__ == "__main__":
    main()
