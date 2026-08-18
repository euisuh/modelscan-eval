from __future__ import annotations

import argparse
import json
from dataclasses import asdict, replace
from pathlib import Path

import yaml

from scanners.opcode_baseline import OpcodeBaseline
from scanners.modelscan_adapter import ModelScanAdapter
from scanners.picklescan_adapter import PickleScanAdapter


ROOT = Path(__file__).resolve().parents[1]
SCANNERS = {
    PickleScanAdapter.name: PickleScanAdapter,
    ModelScanAdapter.name: ModelScanAdapter,
    OpcodeBaseline.name: OpcodeBaseline,
}


def run(scanner_name: str):
    adapter = SCANNERS[scanner_name]()
    if not adapter.available():
        return None
    manifest = yaml.safe_load((ROOT / "corpus/manifest.yaml").read_text(encoding="utf-8"))
    return [replace(adapter.scan(ROOT / item["path"]), item_id=item["id"]) for item in manifest["items"]]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scanner", action="append", choices=SCANNERS)
    args = parser.parse_args()
    for scanner_name in args.scanner or [OpcodeBaseline.name]:
        verdicts = run(scanner_name)
        if verdicts is None:
            print(json.dumps({"scanner": scanner_name, "status": "skipped"}, sort_keys=True))
            continue
        for verdict in verdicts:
            print(json.dumps(asdict(verdict), sort_keys=True))


if __name__ == "__main__":
    main()
