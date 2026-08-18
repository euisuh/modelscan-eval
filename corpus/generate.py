#!/usr/bin/env python3
"""Build deterministic, safe-by-construction corpus fixtures."""

from __future__ import annotations

import io
import json
import operator
import pickle
import sys
import zipfile
from functools import partial
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from corpus._marker import drop_canary  # noqa: E402


class CanaryPayload:
    """Technique: pickle_reduce_direct; benign marker: drop_canary('.') only."""

    def __reduce__(self):
        return drop_canary, (".",)


class PartialCanaryPayload:
    """Technique: pickle_reduce_partial; benign marker: drop_canary('.') only."""

    def __reduce__(self):
        return partial(drop_canary, "."), ()


class BuiltinCallCanaryPayload:
    """Technique: pickle_reduce_builtin_call; benign marker: drop_canary('.') only."""

    def __reduce__(self):
        return operator.methodcaller("__call__", "."), (drop_canary,)


def pickle_bytes(value: object, protocol: int = 4) -> bytes:
    return pickle.dumps(value, protocol=protocol)


def torch_zip(data: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, content in (
            ("archive/data.pkl", data),
            ("archive/byteorder", b"little"),
            ("archive/version", b"3\n"),
        ):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            archive.writestr(info, content)
    return output.getvalue()


def python_source(name: str, malicious: bool) -> bytes:
    marker = (
        "# Technique: custom_code_import; benign marker: drop_canary('.') only.\n"
        "from corpus._marker import drop_canary\n\n"
        "drop_canary('.')\n\n"
        if malicious
        else ""
    )
    return (
        f'"""Synthetic {name} fixture."""\n\n'
        f"{marker}"
        f"class {name}:\n"
        "    model_type = \"synthetic-transformer\"\n\n"
        "    def __init__(self, hidden_size=16):\n"
        "        self.hidden_size = hidden_size\n"
    ).encode()


def metadata(name: str, author: str, architecture: str) -> bytes:
    return (json.dumps({
        "_name_or_path": name,
        "architectures": [architecture],
        "author": author,
        "hidden_size": 16,
        "model_type": "synthetic-transformer",
    }, indent=2, sort_keys=True) + "\n").encode()


def outputs() -> dict[str, bytes]:
    clean_pickles = {
        "clean_state_dict": {"format": "state_dict", "weights": [1.0, 2.0]},
        "clean_optimizer": {"state": {}, "param_groups": [{"lr": 0.001}]},
        "clean_tokenizer": {"vocab": {"[PAD]": 0, "[UNK]": 1}, "lowercase": True},
        "clean_training_args": {"epochs": 3, "seed": 42, "batch_size": 8},
        "clean_tensor_shell": {"shape": [2, 2], "dtype": "float32", "data": [0.0] * 4},
        "clean_checkpoint": {"step": 1200, "metrics": {"loss": 0.125}},
        "clean_scheduler": {"last_epoch": 4, "base_lrs": [0.001]},
    }
    result = {
        "malicious_reduce": pickle_bytes(CanaryPayload()),
        "malicious_reduce_optimizer": pickle_bytes({"state": CanaryPayload(), "param_groups": []}),
        "malicious_reduce_tokenizer": pickle_bytes({"vocab": {"[PAD]": 0}, "post_init": CanaryPayload()}),
        "malicious_reduce_tuple": pickle_bytes(("checkpoint", CanaryPayload())),
        "malicious_reduce_partial": pickle_bytes(PartialCanaryPayload()),
        "malicious_reduce_builtin_call": pickle_bytes(BuiltinCallCanaryPayload()),
        "malicious_reduce_state_dict": pickle_bytes({"state_dict": CanaryPayload()}),
        "malicious_reduce_torch_zip": torch_zip(pickle_bytes(CanaryPayload())),
        **{item_id: pickle_bytes(value) for item_id, value in clean_pickles.items()},
        "clean_torch_zip": torch_zip(pickle_bytes({"state_dict": {"layer.weight": [0.1, 0.2]}})),
    }
    for item_id, class_name in (
        ("malicious_modeling_alpha", "AlphaModel"),
        ("malicious_modeling_beta", "BetaModel"),
        ("malicious_modeling_vision", "VisionModel"),
        ("malicious_tokenizer_code", "SyntheticTokenizer"),
        ("malicious_processing", "SyntheticProcessor"),
        ("clean_modeling_alpha", "AlphaModel"),
        ("clean_modeling_beta", "BetaModel"),
        ("clean_modeling_vision", "VisionModel"),
        ("clean_tokenizer_code", "SyntheticTokenizer"),
        ("clean_processing", "SyntheticProcessor"),
    ):
        result[item_id] = python_source(class_name, item_id.startswith("malicious_"))
    spoofed = (
        ("metadata_typosquat", "acne/bert-base", "Acme AI"),
        ("metadata_lineage_spoof", "trusted-org/secure-model", "Unknown Publisher"),
        ("metadata_author_spoof", "synthetic/research-model", "Trusted Research Lab"),
        ("metadata_namespace_spoof", "official/models-v2", "Official Models"),
        ("metadata_checkpoint_spoof", "major-lab/foundation-large", "major-lab"),
    )
    legit = (
        ("clean_metadata_alpha", "modelscan-eval/alpha", "modelscan-eval"),
        ("clean_metadata_beta", "modelscan-eval/beta", "modelscan-eval"),
        ("clean_metadata_vision", "modelscan-eval/vision", "modelscan-eval"),
        ("clean_metadata_tokenizer", "modelscan-eval/tokenizer", "modelscan-eval"),
        ("clean_metadata_processor", "modelscan-eval/processor", "modelscan-eval"),
    )
    for item_id, name, author in (*spoofed, *legit):
        result[item_id] = metadata(name, author, "SyntheticModel")
    return result


def main() -> None:
    manifest = yaml.safe_load((ROOT / "corpus/manifest.yaml").read_text(encoding="utf-8"))
    output = outputs()
    paths = {item["id"]: ROOT / item["path"] for item in manifest["items"]}
    if paths.keys() != output.keys():
        raise ValueError("manifest items must match generated fixtures")

    fixture_dir = ROOT / "corpus/fixtures"
    fixture_dir.mkdir(parents=True, exist_ok=True)
    for item_id, data in output.items():
        paths[item_id].write_bytes(data)


if __name__ == "__main__":
    main()
