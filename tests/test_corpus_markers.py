import pickle
import subprocess
import sys
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


CONTROLS = [item for item in MANIFEST["items"] if item.get("payload") == "control"]


@pytest.mark.skipif(sys.platform == "win32", reason="control payload needs a POSIX shell")
@pytest.mark.parametrize("item", CONTROLS, ids=lambda item: item["id"])
def test_control_pickle_only_echoes(item, tmp_path):
    fixture = ROOT / item["path"]
    data = zipfile.ZipFile(fixture).read("archive/data.pkl") if item["kind"] == "torch_bin" else fixture.read_bytes()
    code = "import pickle, sys; pickle.loads(sys.stdin.buffer.read())"
    # unpickle in a child process: the payload writes to the child's stdout via the shell
    run = subprocess.run([sys.executable, "-c", code], input=data, capture_output=True, cwd=tmp_path, check=True)
    assert run.stdout.decode().strip() == item["expected_stdout"]
    assert list(tmp_path.iterdir()) == []
