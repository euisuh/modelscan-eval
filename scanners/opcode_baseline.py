from __future__ import annotations

import pickletools
import time
import zipfile
from pathlib import Path

from scanners.base import ScannerAdapter, Verdict

DANGEROUS = {"REDUCE", "GLOBAL", "STACK_GLOBAL"}
PICKLE_SUFFIXES = {".pkl", ".pickle", ".bin", ".pt", ".pth"}


def pickle_payloads(path: Path) -> list[bytes]:
    """Return the pickle streams in a file: the file itself, or the data.pkl members of a torch zip."""
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            return [archive.read(n) for n in archive.namelist() if n.endswith(".pkl")]
    return [path.read_bytes()]


class OpcodeBaseline(ScannerAdapter):
    name = "opcode_baseline"

    def available(self) -> bool:
        return True

    def scan(self, path: Path) -> Verdict:
        started = time.perf_counter()

        def verdict(flagged: bool, detail: str, error: str | None = None) -> Verdict:
            return Verdict(self.name, path.stem, flagged, "high" if flagged else None, detail, error,
                           (time.perf_counter() - started) * 1000)

        if path.suffix not in PICKLE_SUFFIXES:
            # Not a pickle container: nothing for an opcode scanner to inspect (not an error).
            return verdict(False, "unsupported format: not a pickle file")
        try:
            dangerous = [
                op.name
                for data in pickle_payloads(path)
                for op, _, _ in pickletools.genops(data)
                if op.name in DANGEROUS
            ]
        except Exception as exc:
            return verdict(False, "scan failed", str(exc))
        return verdict(bool(dangerous), f"dangerous opcodes: {', '.join(dangerous)}" if dangerous else "no dangerous opcodes")
