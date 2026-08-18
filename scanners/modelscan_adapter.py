from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from scanners.base import ScannerAdapter, Verdict


class ModelScanAdapter(ScannerAdapter):
    name = "modelscan"

    def available(self) -> bool:
        return shutil.which("modelscan") is not None

    def scan(self, path: Path) -> Verdict:
        started = time.perf_counter()
        try:
            result = subprocess.run(
                ["modelscan", "--path", str(path), "--reporting-format", "json"],
                capture_output=True,
                text=True,
                check=False,
            )
            detail = result.stdout.strip() or result.stderr.strip()
            error = None if result.returncode in (0, 1) else detail or f"exit code {result.returncode}"
            return Verdict(
                self.name,
                path.stem,
                result.returncode == 1,
                "high" if result.returncode == 1 else None,
                detail,
                error,
                (time.perf_counter() - started) * 1000,
            )
        except OSError as exc:
            return Verdict(self.name, path.stem, False, None, "scan failed", str(exc), (time.perf_counter() - started) * 1000)
