from __future__ import annotations


def compute_metrics(verdicts: list[dict], items: list[dict]) -> dict:
    """Per-scanner rates plus raw counts.

    Skipped verdicts are excluded from denominators. Scan errors count as unflagged
    (fail-open, as a user would experience them) and are tallied in `errors`.
    Items with `payload: control` (known-dangerous global, harmless argument) are
    tallied separately from the canary group. `counts` holds [flagged, total] for each rate so tiny denominators stay visible.
    """
    item_by_id = {item["id"]: item for item in items}
    techniques = sorted({item["evasion"] for item in items if item.get("evasion")})
    scanners = dict.fromkeys(verdict["scanner"] for verdict in verdicts)
    metrics = {}

    def tally(selected: list[dict]) -> list[int]:
        return [sum(bool(v["flagged"]) for v in selected), len(selected)]

    def rate(counts: list[int]) -> float | None:
        return counts[0] / counts[1] if counts[1] else None

    for scanner in scanners:
        usable = [
            v for v in verdicts
            if v["scanner"] == scanner and v.get("status") != "skipped" and v.get("item_id") in item_by_id
        ]
        def label(v: dict) -> dict:
            return item_by_id[v["item_id"]]

        def group(payload: str | None) -> list[dict]:
            # items without a `payload` key are the canary group
            return [v for v in usable if label(v).get("payload") == payload]

        canary, control = group(None), group("control")
        base = tally([v for v in canary if label(v)["label"] == "malicious" and label(v).get("evasion") is None])
        clean = tally([v for v in usable if label(v)["label"] == "clean"])
        evasion = {t: tally([v for v in canary if label(v).get("evasion") == t]) for t in techniques}
        control_base = tally([v for v in control if label(v).get("evasion") is None])
        control_evasion = {t: tally([v for v in control if label(v).get("evasion") == t]) for t in techniques}
        metrics[scanner] = {
            "detection_rate": rate(base),
            "fpr": rate(clean),
            "evasion_robustness_by_technique": {t: rate(c) for t, c in evasion.items()},
            "control_detection_rate": rate(control_base),
            "control_evasion_robustness_by_technique": {t: rate(c) for t, c in control_evasion.items()},
            "counts": {
                "detection": base, "fpr": clean, "evasion": evasion,
                "control_detection": control_base, "control_evasion": control_evasion,
            },
            "errors": sum(bool(v.get("error")) for v in usable),
        }

    return {"per_scanner": metrics}
