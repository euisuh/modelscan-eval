from __future__ import annotations

import pickletools
import time
from pathlib import Path

from scanners.base import ScannerAdapter, Verdict


class OpcodeBaseline(ScannerAdapter):
    name = "opcode_baseline"

    def available(self) -> bool:
        return True

    def scan(self, path: Path) -> Verdict:
        started = time.perf_counter()
        try:
            dangerous = [op.name for op, _, _ in pickletools.genops(path.read_bytes()) if op.name in {"REDUCE", "GLOBAL", "STACK_GLOBAL"}]
            return Verdict(
                scanner=self.name,
                item_id=path.stem,
                flagged=bool(dangerous),
                severity="high" if dangerous else None,
                detail=f"dangerous opcodes: {', '.join(dangerous)}" if dangerous else "no dangerous opcodes",
                error=None,
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception as exc:
            return Verdict(self.name, path.stem, False, None, "scan failed", str(exc), (time.perf_counter() - started) * 1000)
