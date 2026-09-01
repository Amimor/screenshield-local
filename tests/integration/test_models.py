from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from screenshield.demo import generate_demo
from screenshield.model_store import install_yunet

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("RUN_MODEL_INTEGRATION") != "1",
        reason="Set RUN_MODEL_INTEGRATION=1 to run downloaded local models.",
    ),
]


def test_real_ocr_presidio_qr_and_face_pipeline() -> None:
    from screenshield.pipeline import scan_image
    from screenshield.recognizers import PresidioRecognizer

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        source = generate_demo(root)
        source.with_suffix(source.suffix + ".ocr.json").unlink()
        source.with_suffix(source.suffix + ".visual.json").unlink()
        detections, tokens = scan_image(
            source,
            "en",
            include_presidio=True,
            presidio=PresidioRecognizer(),
            face_model=install_yunet(),
        )
        categories = {item.category for item in detections}
        assert tokens
        assert {"EMAIL", "PHONE", "PAYMENT_CARD", "GITHUB_TOKEN", "QR_CODE"} <= categories

    fixture = os.environ.get("SCREENSHIELD_FACE_FIXTURE")
    if fixture:
        from screenshield.visual import OpenCVVisualDetector

        detections = OpenCVVisualDetector(install_yunet()).detect(Path(fixture))
        assert any(item.category == "FACE" for item in detections)
