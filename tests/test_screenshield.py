from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw

from screenshield.demo import generate_demo
from screenshield.evaluate import evaluate_demo
from screenshield.models import BoundingBox, Detection, Redaction, RedactionMode
from screenshield.pipeline import sanitize, scan_image, validate_image
from screenshield.recognizers import _valid_luhn
from screenshield.redact import sanitize_image, sha256_file


class ScreenShieldTests(unittest.TestCase):
    def test_demo_recall_and_privacy_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            source = generate_demo(folder)
            truth = json.loads((folder / "ground-truth.json").read_text())
            detections, _ = scan_image(source)
            categories = {item.category for item in detections}
            required = set(truth["required_categories"])
            self.assertGreaterEqual(len(categories & required) / len(required), 0.95)
            original_hash = sha256_file(source)
            destination = folder / "safe.png"
            report, _ = sanitize(source, destination)
            self.assertEqual(sha256_file(source), original_hash)
            serialized = report.model_dump_json()
            for raw_secret in (
                "alex.morgan@example.com",
                "4111 1111 1111 1111",
                "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
                "postgres://admin:secret",
            ):
                self.assertNotIn(raw_secret, serialized)
            self.assertNotEqual(report.input_sha256, report.output_sha256)

    def test_luhn_rejects_false_positives(self) -> None:
        self.assertTrue(_valid_luhn("4111 1111 1111 1111"))
        self.assertFalse(_valid_luhn("1111 1111 1111 1111"))
        self.assertFalse(_valid_luhn("1234 5678 9012 3456"))

    def test_all_redaction_modes_cover_region_and_strip_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.jpg"
            image = Image.new("RGB", (160, 120), "white")
            draw = ImageDraw.Draw(image)
            draw.rectangle((40, 30, 120, 80), fill="#d1242f")
            draw.line((40, 30, 120, 80), fill="black", width=4)
            exif = Image.Exif()
            exif[0x010E] = "private description"
            image.save(source, exif=exif)
            detection = Detection(
                id="d1",
                category="EMAIL",
                bounding_box=BoundingBox(x1=40, y1=30, x2=120, y2=80),
                confidence=1.0,
                detector="test",
                masked_preview="ab••cd",
                value_sha256=hashlib.sha256(b"secret").hexdigest(),
                default_selected=True,
            )
            for mode in RedactionMode:
                output = root / f"{mode.value}.png"
                sanitize_image(
                    source, output, [detection], [Redaction(detection_id="d1", mode=mode, padding=2)]
                )
                with Image.open(output) as result:
                    self.assertFalse(result.getexif())
                    crop = np.asarray(result.convert("RGB"))[28:82, 38:122]
                    self.assertFalse(np.all(crop == 255), mode)

    def test_original_cannot_be_overwritten_and_bad_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.png"
            Image.new("RGB", (20, 20), "white").save(source)
            with self.assertRaises(ValueError):
                sanitize_image(source, source, [], [])
            corrupt = root / "corrupt.png"
            corrupt.write_bytes(b"not an image")
            with self.assertRaises(ValueError):
                validate_image(corrupt)

    def test_evaluation_thresholds_and_false_positive_fixture(self) -> None:
        result = evaluate_demo()
        self.assertGreaterEqual(result["deterministic_category_recall"], 0.95)
        self.assertEqual(result["unexpected_categories"], [])
        self.assertEqual(result["raw_values_in_report"], [])


if __name__ == "__main__":
    unittest.main()
