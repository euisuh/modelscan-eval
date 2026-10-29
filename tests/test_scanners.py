import pickle
import zipfile
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from scanners.modelscan_adapter import ModelScanAdapter
from scanners.opcode_baseline import OpcodeBaseline


class Evil:
    def __reduce__(self):
        return print, ("x",)


def test_baseline_flags_plain_pickle(tmp_path):
    f = tmp_path / "a.pkl"
    f.write_bytes(pickle.dumps(Evil()))
    v = OpcodeBaseline().scan(f)
    assert v.flagged and v.error is None


def test_baseline_unwraps_torch_zip(tmp_path):
    f = tmp_path / "a.bin"
    with zipfile.ZipFile(f, "w") as z:
        z.writestr("archive/data.pkl", pickle.dumps(Evil()))
    v = OpcodeBaseline().scan(f)
    assert v.flagged and v.error is None


def test_baseline_clean_pickle_not_flagged(tmp_path):
    f = tmp_path / "a.pkl"
    f.write_bytes(pickle.dumps({"w": [1.0]}))
    assert not OpcodeBaseline().scan(f).flagged


@pytest.mark.parametrize("name", ["config.json", "modeling.py"])
def test_baseline_non_pickle_is_not_an_error(tmp_path, name):
    f = tmp_path / name
    f.write_text("{}")
    v = OpcodeBaseline().scan(f)
    assert not v.flagged and v.error is None


def test_baseline_corrupt_pickle_reports_error(tmp_path):
    f = tmp_path / "a.pkl"
    f.write_bytes(b"\xff\xfe not a pickle")
    v = OpcodeBaseline().scan(f)
    assert not v.flagged and v.error


@pytest.mark.parametrize(("rc", "flagged", "has_error"), [(0, False, False), (1, True, False), (3, False, False), (2, False, True)])
def test_modelscan_exit_codes(monkeypatch, rc, flagged, has_error):
    monkeypatch.setattr("subprocess.run", lambda *a, **k: CompletedProcess(a[0], rc, "out", ""))
    v = ModelScanAdapter().scan(Path("x.json"))
    assert v.flagged is flagged and bool(v.error) is has_error


def test_runner_strips_absolute_paths():
    from eval.runner import ROOT, run

    verdicts = run("opcode_baseline")
    assert verdicts and not any(str(ROOT) in v.detail for v in verdicts)
