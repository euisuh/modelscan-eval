from __future__ import annotations


def compute_metrics(verdicts: list[dict], items: list[dict]) -> dict:
    item_by_id = {item["id"]: item for item in items}
    techniques = sorted({item["evasion"] for item in items if item.get("evasion")})
    scanners = dict.fromkeys(verdict["scanner"] for verdict in verdicts)
    metrics = {}

    for scanner in scanners:
        usable = [
            verdict
            for verdict in verdicts
            if verdict["scanner"] == scanner
            and verdict.get("status") != "skipped"
            and verdict.get("item_id") in item_by_id
        ]

        def rate(selected: list[dict]) -> float | None:
            return sum(bool(verdict["flagged"]) for verdict in selected) / len(selected) if selected else None

        base = [
            verdict
            for verdict in usable
            if item_by_id[verdict["item_id"]]["label"] == "malicious"
            and item_by_id[verdict["item_id"]].get("evasion") is None
        ]
        clean = [
            verdict
            for verdict in usable
            if item_by_id[verdict["item_id"]]["label"] == "clean"
        ]
        metrics[scanner] = {
            "detection_rate": rate(base),
            "fpr": rate(clean),
            "evasion_robustness_by_technique": {
                technique: rate(
                    [
                        verdict
                        for verdict in usable
                        if item_by_id[verdict["item_id"]].get("evasion") == technique
                    ]
                )
                for technique in techniques
            },
        }

    return {"per_scanner": metrics}
