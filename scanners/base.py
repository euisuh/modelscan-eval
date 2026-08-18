from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Verdict:
    scanner: str
    item_id: str
    flagged: bool
    severity: str | None
    detail: str
    error: str | None
    duration_ms: float


class ScannerAdapter(ABC):
    name: str

    @abstractmethod
    def available(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def scan(self, path: Path) -> Verdict:
        raise NotImplementedError
