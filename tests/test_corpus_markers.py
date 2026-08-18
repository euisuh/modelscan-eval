import pickle
from pathlib import Path

from corpus._marker import CANARY_CONTENT, CANARY_NAME


ROOT = Path(__file__).resolve().parents[1]


def test_malicious_pickle_drops_only_canary(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with (ROOT / "corpus/fixtures/malicious_reduce.pkl").open("rb") as fixture:
        result = pickle.load(fixture)

    marker = tmp_path / CANARY_NAME
    assert result == marker
    assert marker.read_text(encoding="utf-8") == CANARY_CONTENT
    assert list(tmp_path.iterdir()) == [marker]
