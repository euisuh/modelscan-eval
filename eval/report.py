from __future__ import annotations

import hashlib
import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import yaml

from eval.metrics import compute_metrics

ROOT = Path(__file__).resolve().parents[1]
RAW_PATH = ROOT / "results/verdicts.jsonl"
RESULTS_PATH = ROOT / "results/results.json"
REPORT_PATH = ROOT / "results/REPORT.md"
MANIFEST_PATH = ROOT / "corpus/manifest.yaml"


def format_rate(value: float | None, counts: list[int] | None = None) -> str:
    if value is None:
        return "no data"
    return f"{value:.1%} ({counts[0]}/{counts[1]})" if counts else f"{value:.1%}"


def scanner_version(scanner: str) -> str:
    try:
        return version(scanner)
    except PackageNotFoundError:
        return "n/a"


def main() -> None:
    verdicts = [json.loads(line) for line in RAW_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    manifest_bytes = MANIFEST_PATH.read_bytes()
    items = yaml.safe_load(manifest_bytes)["items"]
    metrics = compute_metrics(verdicts, items)
    scanners = list(metrics["per_scanner"])
    available = [scanner for scanner in scanners if any(v["scanner"] == scanner and v.get("status") != "skipped" for v in verdicts)]
    unavailable = [scanner for scanner in scanners if scanner not in available]
    corpus_hash = hashlib.sha256(manifest_bytes).hexdigest()
    result = {
        "run_meta": {
            "corpus_version": f"sha256:{corpus_hash}",
            "corpus_item_count": len(items),
            "available_scanners": available,
            "unavailable_scanners": unavailable,
            # read from the environment running the report; run `make eval report` in one env
            "scanner_versions": {scanner: scanner_version(scanner) for scanner in available if scanner != "opcode_baseline"},
        },
        "verdicts": verdicts,
        "metrics": metrics,
    }

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    techniques = sorted({item["evasion"] for item in items if item.get("evasion")})
    lines = [
        "# modelscan-eval report",
        "",
        f"- Corpus: `sha256:{corpus_hash}` ({len(items)} items)",
        f"- Available scanners: {', '.join(f'`{scanner}`' for scanner in available) or 'none'}",
        f"- Unavailable scanners: {', '.join(f'`{scanner}`' for scanner in unavailable) or 'none'}",
        *[f"- `{scanner}` version: {ver}" for scanner, ver in result["run_meta"]["scanner_versions"].items()],
        "",
        "## Leaderboard",
        "",
        "| Scanner | Detection rate | False-positive rate | Scan errors |",
        "|---|---:|---:|---:|",
        *[
            f"| {scanner} | {format_rate(m['detection_rate'], m['counts']['detection'])} "
            f"| {format_rate(m['fpr'], m['counts']['fpr'])} | {m['errors']} |"
            for scanner, m in metrics["per_scanner"].items()
        ],
        "",
        "## Evasion robustness",
        "",
        f"| Scanner | {' | '.join(techniques)} |",
        f"|---|{'|'.join(['---:'] * len(techniques))}|",
        *[
            f"| {scanner} | "
            + " | ".join(
                format_rate(
                    metrics["per_scanner"][scanner]["evasion_robustness_by_technique"][technique],
                    metrics["per_scanner"][scanner]["counts"]["evasion"][technique],
                )
                for technique in techniques
            )
            + " |"
            for scanner in scanners
        ],
        "",
    ]
    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
