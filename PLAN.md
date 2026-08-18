# modelscan-eval — Implementation Plan (v1)

## 1. Problem statement & novel angle

ML supply-chain scanners (Protect AI `modelscan`, `picklescan`, Hugging Face
Hub's pickle import scan) each claim to catch malicious model artifacts —
unsafe pickle/`torch.load` payloads, malicious custom code, spoofed metadata.
But their detection quality is asserted per-tool, on each project's own terms.
There is no shared, labeled, adversarial corpus that measures **how these tools
compare against each other on the same inputs, and specifically how they hold up
against deliberate evasion**. `modelscan-eval` builds a small, rigorous
meta-benchmark: a labeled synthetic corpus (clean + malicious + obfuscated
variants), a harness that runs real scanners over it, and a report of detection
rate / false-positive rate / evasion robustness per scanner.

**Novel angle:** an apples-to-apples, evasion-robustness leaderboard across
multiple scanners on one shared labeled corpus. Assume the individual tool repos
do not publish this cross-tool evasion comparison themselves.

**Reused vs. novel:**
- *Reused (as subjects under test):* `picklescan`, `modelscan` — run unmodified,
  treated as black boxes behind adapters.
- *Reused (as a comparison baseline):* a hand-rolled pickle-opcode scanner
  (`pickletools.genops`-based) representing the "naive dangerous-opcode list"
  technique described in Trail of Bits / community writeups.
- *Novel:* the shared labeled corpus, the evasion taxonomy applied uniformly to
  every scanner, and the cross-tool robustness report.

## 2. Threat model / scope

**In scope for v1 (artifact types):**
- Pickle-based artifacts: `.pkl`, `pytorch_model.bin`-shaped files (a pickle
  stream, or a tiny zip-of-pickle mimicking `torch.save`'s newer format).
- Repo metadata / code files: `config.json`, custom `modeling_*.py`,
  tokenizer files (`tokenizer_config.json`).

**In scope (attack techniques):**
- Malicious `__reduce__` in a pickle that triggers code execution on unpickle.
- Malicious code embedded in a custom `modeling_*.py` (auto-loaded via HF
  `trust_remote_code`).
- Typosquatted / lineage-spoofed metadata (e.g. `config.json` claiming a
  well-known base model / author it isn't).

**Explicitly out of scope for v1:**
- Real (multi-GB) model weights or real Hugging Face downloads.
- Non-pickle deep-learning formats beyond a minimal safetensors clean sample
  (no GGUF, ONNX, Keras H5, TF SavedModel exploits).
- Live/networked payloads of any kind.
- Runtime/behavioral detonation-based detection (v1 is static-scanner eval only;
  the harness never *executes* a malicious payload — see §3).
- Building a new/better scanner (this evaluates, it does not defend).
- Prompt-injection material (covered by the sibling `agent-injection-bench`).

## 3. Safety constraints & mechanical enforcement

**Principle:** every malicious sample is a *safe-by-construction proof of
concept*. A payload may only demonstrate that code *would* run by producing a
benign, local, observable marker — writing a canary file to a caller-provided
temp path, or printing a fixed marker string. Payloads MUST NOT: touch the
network, spawn shells against real targets, read/exfiltrate real user data,
delete/modify files outside a provided temp dir, or fetch/execute remote code.

**The harness never unpickles or imports a malicious sample.** Scanners are
*static* analyzers; the harness feeds them file paths only. Payload *behavior*
is verified separately in an isolated, sandboxed self-test that runs each
payload's marker action against a `tmp_path` and asserts only the canary
appeared (§ milestone M1/corpus generator self-test).

**Mechanical enforcement (must exist as runnable checks):**
- `tools/safety_lint.py`: greps every generated/committed payload artifact and
  every corpus generator source for a denylist of disallowed tokens
  (`socket`, `urllib`, `requests`, `http`, `curl`, `wget`, `subprocess` with a
  non-marker command, `os.system` with a non-marker command, IP-literal
  regexes, `eval(`/`exec(` on non-literal input, base64-then-exec chains that
  aren't the declared evasion fixtures). Exits non-zero on any hit outside an
  explicit allowlist of declared-evasion fixtures.
- Canary actions are constrained to an allowlisted helper
  (`corpus/_marker.py: drop_canary(path)`) so payloads reference one audited
  sink, not arbitrary code.
- CI (single `make check` target, also a GitHub Actions workflow later) runs:
  `safety_lint` → corpus self-test (payload markers fire only in sandbox) →
  scanner eval. `safety_lint` must be the first gate and must pass before any
  eval runs.
- `README`/`PLAN` state the constraint prominently; each malicious fixture
  carries a header comment naming its technique and its benign marker.

## 4. Architecture

**Repo layout:**
```
modelscan-eval/
  README.md
  PLAN.md
  pyproject.toml            # deps: pytest; scanners as optional extras
  Makefile                  # make check / make eval / make report
  corpus/
    _marker.py              # allowlisted benign canary sink
    generate.py             # builds all fixtures from code (deterministic)
    manifest.yaml           # labeled index: id -> {kind,label,technique,evasion}
    fixtures/               # generated artifacts (gitignored or committed tiny)
  scanners/
    base.py                 # ScannerAdapter ABC + Verdict dataclass
    picklescan_adapter.py
    modelscan_adapter.py
    opcode_baseline.py      # hand-rolled pickletools baseline
  eval/
    runner.py               # runs adapters x corpus -> raw results
    metrics.py              # detection rate, FPR, evasion robustness
    report.py               # writes results/REPORT.md + results.json
  tools/
    safety_lint.py
  tests/
    test_corpus_markers.py  # sandboxed payload-behavior self-test
    test_adapters.py        # verdict schema conformance (mocked)
  results/                  # gitignored; REPORT.md is the shippable artifact
```

**Core abstractions:**
- `CorpusItem` (from `manifest.yaml`): `id`, `path`, `kind`
  (`pickle|torch_bin|py_code|metadata`), `label` (`clean|malicious`),
  `technique` (nullable), `evasion` (nullable), `expected_marker` (nullable).
- `Verdict` dataclass: `scanner`, `item_id`, `flagged: bool`, `severity: str|None`,
  `detail: str`, `error: str|None`, `duration_ms`.
- `ScannerAdapter` (ABC): `name`, `available() -> bool`, `scan(path) -> Verdict`.
  Adapters shell out to / import the real tool and normalize output into
  `Verdict`. Unavailable scanner (not installed) => skipped, recorded as such,
  not counted as a miss.
- Evasion technique = a pure function `apply(payload_bytes|src) -> bytes|src`
  used by `corpus/generate.py` to derive an obfuscated variant from a base
  malicious sample; each is registered by name so the manifest can label it.
- `Evaluator` = `eval/runner.py` (cartesian product adapters×items) +
  `metrics.py` (aggregates) + `report.py` (renders).
- **Result schema (`results.json`):** `{run_meta, verdicts: [Verdict...],
  metrics: {per_scanner: {detection_rate, fpr, evasion_robustness_by_technique}}}`.

## 5. Milestones (ordered, codex-executable, self-contained)

Each task assumes no memory of this conversation. Repo is at
`github.com/euisuh/modelscan-eval`, Python project, deps via `pyproject.toml`.

### M0 — Project skeleton & safety gate (S)
- **Goal:** runnable `pyproject.toml`, `Makefile`, empty package dirs, and the
  safety lint that guards everything.
- **Files:** `pyproject.toml`, `Makefile`, `tools/safety_lint.py`,
  `corpus/_marker.py`, `scanners/base.py` (with `Verdict` + `ScannerAdapter`
  ABC), `tests/` package init.
- **Acceptance:**
  - `pip install -e .` succeeds (deps: `pytest`, `pyyaml`; `picklescan` and
    `modelscan` as optional extras `[scanners]`).
  - `python tools/safety_lint.py corpus/` exits 0 on empty corpus and exits 1
    when pointed at a file containing `import socket`.
  - `corpus/_marker.py: drop_canary(path)` writes a fixed marker file under
    `path` and returns its path; `python -c "import corpus._marker"` works.
  - `make check` target exists and runs safety_lint then pytest.

### M1 — Thin vertical slice: 1 malicious sample, 1 scanner, 1 verdict (M)
- **Goal:** prove the whole pipe end to end with the smallest possible corpus.
- **Files:** `corpus/generate.py` (one fixture: a `.pkl` whose `__reduce__`
  calls `corpus._marker.drop_canary`), `corpus/manifest.yaml` (that one item +
  one clean `.pkl`), `scanners/opcode_baseline.py`, `eval/runner.py`,
  `tests/test_corpus_markers.py`.
- **Acceptance:**
  - `python corpus/generate.py` writes exactly the fixtures named in
    `manifest.yaml`; rerun is deterministic (identical bytes).
  - `python tools/safety_lint.py corpus/` passes (the `__reduce__` payload uses
    only the allowlisted `drop_canary` sink).
  - `tests/test_corpus_markers.py` unpickles the malicious sample **inside a
    `tmp_path` sandbox** and asserts the canary file appears and nothing else;
    passes under `pytest`.
  - `python -m eval.runner --scanner opcode_baseline` prints/records a `Verdict`
    per corpus item: malicious `.pkl` => `flagged=True`, clean `.pkl` =>
    `flagged=False`.

### M2 — Real scanner adapters (picklescan + modelscan) (M)
- **Goal:** integrate the two real subjects-under-test behind adapters.
- **Files:** `scanners/picklescan_adapter.py`, `scanners/modelscan_adapter.py`,
  `tests/test_adapters.py`.
- **Acceptance:**
  - Each adapter implements `available()`/`scan()` and returns a schema-valid
    `Verdict`; `available()` returns `False` cleanly when the tool isn't
    installed (no crash).
  - `python -m eval.runner --scanner picklescan --scanner modelscan --scanner
    opcode_baseline` runs over the M1 corpus and records verdicts for every
    installed scanner; skipped scanners are marked `skipped`, not `miss`.
  - `tests/test_adapters.py` validates `Verdict` field types via mocked tool
    output (no real tool required in CI).

### M3 — Corpus breadth: technique categories (M)
- **Goal:** grow to a few dozen labeled items across the three attack techniques
  plus matched clean controls.
- **Files:** `corpus/generate.py` (extended), `corpus/manifest.yaml`.
- **Acceptance:**
  - Corpus contains the composition in §6 (counts must match manifest).
  - Every artifact < 64 KB; total `corpus/fixtures/` < 5 MB.
  - `python tools/safety_lint.py corpus/` passes on the full set.
  - Every malicious item has a `technique`; every clean item has `technique:
    null`; `python -m eval.runner` produces verdicts for all items.

### M4 — Evasion variants (L)
- **Goal:** derive obfuscated variants of the pickle payloads per §8 taxonomy.
- **Files:** `corpus/generate.py` (evasion functions + registry),
  `corpus/manifest.yaml` (variants labeled with `evasion`),
  `tests/test_corpus_markers.py` (extended to cover variants).
- **Acceptance:**
  - Each evasion technique in §8 produces at least one variant of an existing
    base malicious pickle, labeled with its `evasion` name.
  - Variants preserve payload behavior: the marker self-test fires for each
    variant in `tmp_path` and only the canary appears.
  - `safety_lint` passes; evasion fixtures that legitimately use
    base64/opcode tricks are covered by the explicit declared-evasion allowlist,
    not a blanket exception.

### M5 — Metrics & report (M)
- **Goal:** turn raw verdicts into the leaderboard artifact.
- **Files:** `eval/metrics.py`, `eval/report.py`, `Makefile` (`make report`).
- **Acceptance:**
  - `make eval` (runner over full corpus) then `make report` writes
    `results/results.json` and `results/REPORT.md`.
  - `REPORT.md` contains, per scanner: detection rate on malicious (non-evasion)
    items, FPR on clean items, and evasion-robustness table (detection rate per
    evasion technique). Numbers are computed, not placeholders.
  - Metrics correctly exclude `skipped` verdicts from denominators.
  - A small `tests/test_metrics.py` asserts detection/FPR math on a hand-built
    verdict list.

### M6 — Docs & finish (S)
- **Goal:** make it reproducible and reviewer-legible.
- **Files:** `README.md` (run instructions, safety statement, prior-art/differ-
  entiation, limitations), commit the generated `results/REPORT.md` as the
  shippable result (override gitignore for that one file).
- **Acceptance:**
  - Fresh clone: `pip install -e .[scanners] && make check && make eval && make
    report` reproduces `REPORT.md` end to end.
  - README states the safety model and points to `safety_lint` as enforcement.
  - `make check` (safety_lint + tests) is green.

## 6. Synthetic corpus composition (v1)

Target ~35–45 items total (dozens, not hundreds). Every malicious item has a
matched clean control of the same `kind`.

- **Pickle `__reduce__` payloads (kind=pickle/torch_bin):** ~6 malicious base
  samples (e.g. marker via `os` builtin, via `__builtin__`, one wrapped in a
  torch-style zip). ~6 clean pickles (real-looking serialized dicts/state-dict
  shells).
- **Malicious custom code (kind=py_code):** ~4 malicious `modeling_*.py` /
  tokenizer files with a benign marker at import time; ~4 clean equivalents.
- **Spoofed metadata (kind=metadata):** ~4 typosquat/lineage-spoof
  `config.json` (fake `_name_or_path`, impersonated author); ~4 legit configs.
- **Evasion variants (from M4):** ~10–14 derived from the pickle bases, one per
  base per applicable technique (§8).

Counts are the manifest's source of truth; keep each artifact KB-scale.

## 7. Scanners under test (v1)

- **`picklescan`** (pip) — pickle opcode/import denylist scanner. Adapter.
- **`modelscan`** (Protect AI, pip) — broader model-file scanner. Adapter.
- **`opcode_baseline`** (in-repo) — hand-rolled `pickletools.genops` walker that
  flags known-dangerous opcodes/globals (`REDUCE`, `GLOBAL`/`STACK_GLOBAL` to
  `os`,`posix`,`subprocess`,`builtins.eval/exec`). Represents the "naive
  denylist" comparison baseline.

**Extensibility:** all three sit behind the `ScannerAdapter` ABC (§4). Adding a
scanner later = one new file implementing `available()`/`scan()` + registering
in the adapter registry; no runner/metrics/report changes. `available()` lets
the harness degrade gracefully when a tool isn't installed.

## 8. Evasion taxonomy (v1)

Each is a deterministic transform of a base malicious pickle that preserves the
marker behavior while trying to slip past denylist/opcode scanners. Implement in
`corpus/generate.py`; all remain safe-by-construction (marker sink only).

1. **Opcode-level obfuscation:** hand-emit equivalent pickle opcodes / reorder
   so the `GLOBAL` import isn't in the literal form a scanner's string match
   expects (e.g. build via `pickletools`-level assembly rather than the default
   `pickle` protocol output).
2. **Indirect/aliased global import:** reach the same callable through a
   less-obvious module path (e.g. `posix.system` vs `os.system`, or via
   `importlib`/`__builtin__` alias) to dodge exact-name denylists.
3. **Nested / second-stage payload:** the outer pickle's `__reduce__` yields a
   bytes blob that is itself a pickle (or base64 of one); the dangerous opcodes
   live one layer down where a single-pass scanner may not recurse. (Declared
   evasion fixture — allowlisted for safety_lint.)
4. **Non-standard reducer:** use `__reduce_ex__` / `__setstate__` /
   `copyreg`-style custom reducer instead of plain `__reduce__`, so scanners
   keyed on the common pattern miss it.
5. **Protocol / framing variance:** emit at an uncommon pickle protocol and/or
   inside the torch-style zip container, testing whether the scanner unwraps the
   container before scanning.

## 9. Evaluation methodology

- **Detection rate** (per scanner): fraction of *malicious, non-evasion* items
  flagged. Denominator excludes `skipped`.
- **False-positive rate** (per scanner): fraction of *clean* items flagged.
- **Evasion robustness** (per scanner, per technique): detection rate computed
  over only the variants carrying that `evasion` label — directly comparable to
  the base detection rate to show degradation.
- **Reporting:** `results/REPORT.md` — one leaderboard table (scanner × {det.
  rate, FPR}) plus an evasion table (scanner × technique). Raw per-verdict data
  in `results/results.json` for reproducibility. Report the corpus version/hash
  and which scanners were available for the run.

## 10. "Done for v1"

A fresh clone runs `pip install -e .[scanners] && make check && make eval &&
make report` and produces `results/REPORT.md` containing a populated cross-tool
leaderboard (detection rate, FPR, per-technique evasion robustness) over a
~35–45-item labeled corpus spanning three attack techniques and five evasion
techniques, with `picklescan`, `modelscan`, and the opcode baseline as subjects.
`safety_lint` and all tests are green, and no committed payload does anything
beyond dropping a local canary. The result is a self-contained artifact
structured to grow into a workshop-paper writeup.

## 11. Non-goals for v1

- No new/better scanner or defense.
- No real model downloads, real weights, or network access anywhere.
- No behavioral/dynamic detonation-based detection.
- No non-pickle exploit formats (GGUF/ONNX/H5/SavedSavedModel) beyond one clean
  safetensors control.
- No web UI, dashboard, or hosted leaderboard — Markdown + JSON only.
- No hundreds-of-samples corpus; breadth is deliberately dozens.
- No prompt-injection content (sibling project owns that).
