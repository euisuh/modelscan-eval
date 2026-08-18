from pathlib import Path
from subprocess import CompletedProcess

import pytest

from scanners.base import Verdict
from scanners.modelscan_adapter import ModelScanAdapter
from scanners.picklescan_adapter import PickleScanAdapter


@pytest.mark.parametrize("adapter", [PickleScanAdapter(), ModelScanAdapter()])
def test_unavailable_without_tool(monkeypatch, adapter):
    monkeypatch.setattr("shutil.which", lambda _: None)
    assert adapter.available() is False


@pytest.mark.parametrize(
    ("adapter", "output"),
    [
        (PickleScanAdapter(), "Infected files: 1"),
        (ModelScanAdapter(), '{"summary": {"total_issues": 1}}'),
    ],
)
def test_mocked_flagged_verdict_has_schema_types(monkeypatch, adapter, output):
    monkeypatch.setattr(
        "subprocess.run",
        lambda *args, **kwargs: CompletedProcess(args[0], 1, output, ""),
    )

    verdict = adapter.scan(Path("fixture.pkl"))

    assert isinstance(verdict, Verdict)
    assert isinstance(verdict.scanner, str)
    assert isinstance(verdict.item_id, str)
    assert isinstance(verdict.flagged, bool)
    assert verdict.severity is None or isinstance(verdict.severity, str)
    assert isinstance(verdict.detail, str)
    assert verdict.error is None or isinstance(verdict.error, str)
    assert isinstance(verdict.duration_ms, float)
