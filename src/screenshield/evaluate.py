from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .demo import generate_demo
from .pipeline import sanitize, scan_image

SYNTHETIC_RAW_VALUES = [
    "alex.morgan@example.com",
    "+7 (999) 123-45-67",
    "4111 1111 1111 1111",
    "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
    "sk-demoKey_abcdefghijklmnopqrstuvwxyz",
    "postgres://admin:secret@localhost:5432/app",
]


def evaluate_demo() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="screenshield-eval-") as temp:
        folder = Path(temp)
        source = generate_demo(folder)
        truth = json.loads((folder / "ground-truth.json").read_text(encoding="utf-8"))
        detections, _ = scan_image(source)
        categories = {item.category for item in detections}
        required = set(truth["required_categories"])
        review = set(truth["review_categories"])
        report, _ = sanitize(source, folder / "safe.png")
        serialized = report.model_dump_json()
        expected = required | review
        return {
            "fixture": "synthetic-en-ru-v1",
            "required_categories": len(required),
            "detected_required_categories": len(required & categories),
            "deterministic_category_recall": round(len(required & categories) / len(required), 4),
            "unexpected_categories": sorted(categories - expected),
            "raw_values_in_report": [value for value in SYNTHETIC_RAW_VALUES if value in serialized],
            "output_differs_from_input": report.input_sha256 != report.output_sha256,
            "network_required": False,
        }
