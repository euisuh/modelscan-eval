from pathlib import Path

import yaml

from corpus.generate import outputs

ROOT = Path(__file__).resolve().parents[1]
ITEMS = yaml.safe_load((ROOT / "corpus/manifest.yaml").read_text(encoding="utf-8"))["items"]


def test_manifest_matches_generator_and_committed_fixtures():
    generated = outputs()
    assert {i["id"] for i in ITEMS} == generated.keys()
    for item in ITEMS:
        assert (ROOT / item["path"]).read_bytes() == generated[item["id"]], item["id"]


def test_manifest_labels_are_consistent():
    for item in ITEMS:
        assert item["label"] in {"malicious", "clean"}
        if item["label"] == "clean":
            assert item.get("technique") is None and item.get("evasion") is None
