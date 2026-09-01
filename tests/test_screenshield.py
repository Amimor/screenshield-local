from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
from PIL import Image, ImageChops, ImageDraw

from screenshield.cli import _safe_output_name
from screenshield.demo import generate_demo
from screenshield.evaluate import evaluate_demo
from screenshield.model_store import install_yunet, installed_yunet_path
from screenshield.models import BoundingBox, Detection, OCRToken, Redaction, RedactionMode
from screenshield.pipeline import _deduplicate, sanitize, scan_image, validate_image
from screenshield.recognizers import _valid_ip, _valid_luhn, detect_patterns
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

    def test_ipv4_and_ipv6_validation_and_detection(self) -> None:
        self.assertTrue(_valid_ip("192.168.10.25"))
        self.assertTrue(_valid_ip("2001:db8::8a2e:370:7334"))
        self.assertFalse(_valid_ip("999.999.999.999"))
        tokens = [
            OCRToken(
                text="Hosts: 192.168.10.25 and 2001:db8::8a2e:370:7334",
                bounding_box=BoundingBox(x1=10, y1=10, x2=500, y2=40),
                confidence=1.0,
            )
        ]
        values = [item for item in detect_patterns(tokens) if item.category == "IP_ADDRESS"]
        self.assertEqual(len(values), 2)

    def test_overlapping_detections_keep_high_risk_priority(self) -> None:
        shared = BoundingBox(x1=10, y1=10, x2=110, y2=40)

        def detection(category: str, selected: bool, confidence: float) -> Detection:
            return Detection(
                id=category,
                category=category,
                bounding_box=shared,
                confidence=confidence,
                detector="test",
                masked_preview="••••",
                value_sha256=hashlib.sha256(category.encode()).hexdigest(),
                default_selected=selected,
            )

        merged = _deduplicate(
            [detection("PERSON", False, 0.99), detection("EMAIL", True, 0.9)]
        )
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].category, "EMAIL")
        self.assertTrue(merged[0].default_selected)

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
                    with Image.open(
                        Path(__file__).parent / "snapshots" / f"redaction-{mode.value}.png"
                    ) as expected:
                        difference = ImageChops.difference(result.convert("RGB"), expected.convert("RGB"))
                        self.assertIsNone(difference.getbbox(), mode)

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

    def test_generated_filename_does_not_copy_input_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "alex.morgan@example.com-ghp_fake_secret.png"
            Image.new("RGB", (20, 20), "white").save(source)
            output_name = _safe_output_name(source)
            self.assertRegex(output_name, r"^sanitized-[0-9a-f]{12}\.png$")
            self.assertNotIn("alex", output_name)
            self.assertNotIn("ghp", output_name)

    def test_model_download_is_hash_verified_and_idempotent(self) -> None:
        payload = b"verified model fixture"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            with (
                patch("screenshield.model_store.YUNET_SHA256", digest),
                patch(
                    "screenshield.model_store.urllib.request.urlopen",
                    return_value=tempfile.SpooledTemporaryFile(),
                ) as mocked,
            ):
                response = mocked.return_value
                response.write(payload)
                response.seek(0)
                installed = install_yunet(directory)
                self.assertEqual(installed.read_bytes(), payload)
                self.assertEqual(installed_yunet_path(directory), installed)
                self.assertEqual(install_yunet(directory), installed)
                self.assertEqual(mocked.call_count, 1)

    def test_evaluation_thresholds_and_false_positive_fixture(self) -> None:
        result = evaluate_demo()
        self.assertGreaterEqual(result["deterministic_category_recall"], 0.95)
        self.assertEqual(result["unexpected_categories"], [])
        self.assertEqual(result["raw_values_in_report"], [])


if __name__ == "__main__":
    unittest.main()
