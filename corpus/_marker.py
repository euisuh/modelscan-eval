from pathlib import Path


CANARY_NAME = "modelscan-eval.canary"
CANARY_CONTENT = "MODELscan-eval benign canary\n"


def drop_canary(path: str | Path) -> Path:
    marker = Path(path).resolve() / CANARY_NAME
    marker.write_text(CANARY_CONTENT, encoding="utf-8")
    return marker
