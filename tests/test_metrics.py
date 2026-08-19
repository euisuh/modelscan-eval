from eval.metrics import compute_metrics


def test_rates_exclude_skipped_verdicts() -> None:
    items = [
        {"id": "malicious_hit", "label": "malicious", "evasion": None},
        {"id": "malicious_error", "label": "malicious", "evasion": None},
        {"id": "malicious_skipped", "label": "malicious", "evasion": None},
        {"id": "clean_fp", "label": "clean", "evasion": None},
        {"id": "clean_ok", "label": "clean", "evasion": None},
        {"id": "evasion_hit", "label": "malicious", "evasion": "alias"},
        {"id": "evasion_skipped", "label": "malicious", "evasion": "alias"},
    ]
    verdicts = [
        {"scanner": "fake", "item_id": "malicious_hit", "flagged": True, "error": None},
        {"scanner": "fake", "item_id": "malicious_error", "flagged": False, "error": "scan error"},
        {"scanner": "fake", "item_id": "malicious_skipped", "flagged": False, "error": None, "status": "skipped"},
        {"scanner": "fake", "item_id": "clean_fp", "flagged": True, "error": None},
        {"scanner": "fake", "item_id": "clean_ok", "flagged": False, "error": None},
        {"scanner": "fake", "item_id": "evasion_hit", "flagged": True, "error": None},
        {"scanner": "fake", "item_id": "evasion_skipped", "flagged": False, "error": None, "status": "skipped"},
    ]

    metrics = compute_metrics(verdicts, items)["per_scanner"]["fake"]

    assert metrics["detection_rate"] == 1 / 2
    assert metrics["fpr"] == 1 / 2
    assert metrics["evasion_robustness_by_technique"] == {"alias": 1.0}
