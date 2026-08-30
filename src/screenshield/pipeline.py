from __future__ import annotations

from pathlib import Path

from PIL import Image, UnidentifiedImageError

from .models import Detection, OCRToken, Redaction, RedactionMode, SanitizationReport
from .ocr import AutoOCRBackend, OCRBackend
from .recognizers import PresidioRecognizer, detect_patterns
from .redact import sanitize_image
from .visual import AutoVisualDetector

SUPPORTED_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp"}


def validate_image(path: Path) -> tuple[int, int]:
    if path.suffix.lower() not in SUPPORTED_SUFFIXES:
        raise ValueError(f"Unsupported image type: {path.suffix}")
    try:
        with Image.open(path) as image:
            image.verify()
        with Image.open(path) as image:
            return image.size
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError(f"Unreadable image: {path}") from exc


def _deduplicate(detections: list[Detection]) -> list[Detection]:
    ordered = sorted(detections, key=lambda item: (-item.confidence, item.category))
    result: list[Detection] = []
    for detection in ordered:
        duplicate = next(
            (
                existing
                for existing in result
                if existing.category == detection.category
                and existing.bounding_box.intersects(detection.bounding_box)
            ),
            None,
        )
        if duplicate is None:
            result.append(detection)
    return sorted(result, key=lambda item: (item.bounding_box.y1, item.bounding_box.x1, item.category))


def scan_image(
    path: Path,
    language: str = "en",
    ocr: OCRBackend | None = None,
    include_presidio: bool = False,
    face_model: Path | None = None,
) -> tuple[list[Detection], list[OCRToken]]:
    validate_image(path)
    tokens = (ocr or AutoOCRBackend()).read(path, language)
    detections = detect_patterns(tokens)
    if include_presidio:
        detections.extend(PresidioRecognizer().detect(tokens, language))
    try:
        detections.extend(AutoVisualDetector(face_model).detect(path))
    except RuntimeError:
        # OCR-only operation remains useful when OpenCV is not installed.
        pass
    return _deduplicate(detections), tokens


def strict_redactions(
    detections: list[Detection], mode: RedactionMode = RedactionMode.SOLID
) -> list[Redaction]:
    return [
        Redaction(detection_id=item.id, mode=mode, padding=6) for item in detections if item.default_selected
    ]


def sanitize(
    source: Path,
    destination: Path,
    language: str = "en",
    mode: RedactionMode = RedactionMode.SOLID,
    ocr: OCRBackend | None = None,
) -> tuple[SanitizationReport, list[Detection]]:
    detections, _ = scan_image(source, language, ocr)
    report = sanitize_image(source, destination, detections, strict_redactions(detections, mode))
    return report, detections
