import pickle
import zipfile
from pathlib import Path

import pytest
import yaml

from corpus._marker import CANARY_CONTENT, CANARY_NAME


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = yaml.safe_load((ROOT / "corpus/manifest.yaml").read_text(encoding="utf-8"))
MARKER_PICKLES = [
    item for item in MANIFEST["items"]
    if item["id"] == "malicious_reduce" or item.get("derived_from") == "malicious_reduce"
]


@pytest.mark.parametrize("item", MARKER_PICKLES, ids=lambda item: item["id"])
def test_malicious_pickle_drops_only_canary(item, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fixture = ROOT / item["path"]
    if item["kind"] == "torch_bin":
        with zipfile.ZipFile(fixture) as archive:
            result = pickle.loads(archive.read("archive/data.pkl"))
    else:
        result = pickle.loads(fixture.read_bytes())

    marker = tmp_path / CANARY_NAME
    assert result == marker
    assert marker.read_text(encoding="utf-8") == CANARY_CONTENT
    assert list(tmp_path.iterdir()) == [marker]
