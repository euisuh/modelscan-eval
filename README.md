# modelscan-eval

`modelscan-eval` is a reproducible meta-benchmark for static ML supply-chain
scanners. It runs multiple scanners over the same 41-item labeled synthetic
corpus and reports detection rate, false-positive rate, and robustness to five
pickle-evasion techniques.

The corpus covers pickle and torch-style artifacts, custom Hugging Face code,
and spoofed metadata. No real model weights or downloads are required.

## Run

Python 3.10 or newer is required. From a fresh clone:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[scanners]'
make check
make eval
make report
```

`make check` runs the safety lint before the tests. `make eval` writes raw
verdicts to `results/verdicts.jsonl`; `make report` produces
`results/results.json` and the shippable [report](results/REPORT.md).

The optional `[scanners]` extra installs `picklescan` and `modelscan`. Those
extras are not installed in the environment used for the committed report, so
only `opcode_baseline` has measurements there. The harness degrades gracefully:
an absent adapter returns `available() == False`, is recorded as `skipped`, and
is excluded from metric denominators rather than counted as a miss.

## Safety model

Every corpus fixture and generator source is safety-lint-enforced. The only
permitted behavior of a malicious fixture is one benign marker-file write under
a caller-provided temporary directory, through the audited
`corpus._marker.drop_canary` helper. Fixtures do not access the network, spawn
shells against targets, read or exfiltrate user data, or modify files outside
that temporary directory. The evaluation harness performs static scans and
never unpickles or imports malicious fixtures.

[`tools/safety_lint.py`](tools/safety_lint.py) is the mechanical enforcement
gate readers can inspect and run themselves:

```sh
python3 tools/safety_lint.py corpus/
```

It checks committed/generated artifacts and generator sources for forbidden
network, shell, dynamic-execution, and related tokens. `make check` always runs
this gate before pytest. Separate sandboxed tests verify each payload produces
only its expected canary.

## Prior art and differentiation

- **InjecAgent-style corpora:** this project reuses the benchmark pattern of a
  labeled synthetic adversarial corpus with matched clean controls and explicit
  attack categories. It does not reuse prompt-injection samples or evaluate
  agents; its artifacts and threat model are ML model-supply-chain specific.
- **`picklescan` and `modelscan`:** these existing scanners are reused
  unmodified as subjects under test, behind thin adapters. The in-repo
  `pickletools.genops` opcode scanner is a deliberately naive denylist baseline
  reflecting the technique described in community and Trail of Bits writeups.
- **Novel contribution:** one shared labeled corpus, one uniform pickle-evasion
  taxonomy, and an apples-to-apples cross-tool report measuring both ordinary
  detection and evasion robustness. This project evaluates scanners; it does
  not propose another scanner.

## Limitations

- Synthetic, intentionally small corpus (41 items); results do not estimate
  prevalence or performance on all real-world model repositories.
- Static analysis only. No behavioral detonation and no claim about runtime
  containment.
- Pickle-focused. The corpus covers pickle, torch-style pickle containers,
  custom Hugging Face code, and metadata; safetensors, GGUF, ONNX, Keras H5,
  and TensorFlow SavedModel exploit formats are out of scope for v1.
- No live/networked payloads, real model downloads, or multi-gigabyte weights;
  size- and ecosystem-specific scanner behavior may differ in production.
- Metadata spoof and custom-code cases are synthetic, so conclusions depend on
  the v1 labels and attack taxonomy.
- Scanner results depend on installed versions. The committed report records
  unavailable optional scanners explicitly and should be regenerated with
  `.[scanners]` installed for a full comparison.

See [PLAN.md](PLAN.md) for the complete threat model, corpus composition, and
metric definitions.
