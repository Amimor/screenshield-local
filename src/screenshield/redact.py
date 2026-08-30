from __future__ import annotations

import hashlib
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

from .models import Detection, Redaction, RedactionMode, SanitizationReport


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _public_detection(detection: Detection) -> dict[str, str | float | list[int]]:
    return {
        "category": detection.category,
        "confidence": detection.confidence,
        "bounding_box": list(detection.bounding_box.as_tuple()),
        "masked_preview": detection.masked_preview,
        "value_sha256": detection.value_sha256,
        "detector": detection.detector,
    }


def sanitize_image(
    source: Path,
    destination: Path,
    detections: list[Detection],
    redactions: list[Redaction],
) -> SanitizationReport:
    if source.resolve() == destination.resolve():
        raise ValueError("Destination must differ from source; originals are never overwritten")
    selected = {redaction.detection_id: redaction for redaction in redactions}
    with Image.open(source) as opened:
        image = opened.convert("RGB")
    for detection in detections:
        redaction = selected.get(detection.id)
        if redaction is None:
            continue
        box = detection.bounding_box.padded(redaction.padding, image.size)
        coordinates = box.as_tuple()
        if redaction.mode == RedactionMode.SOLID:
            ImageDraw.Draw(image).rectangle(coordinates, fill="black")
        else:
            crop = image.crop(coordinates)
            if redaction.mode == RedactionMode.BLUR:
                crop = crop.filter(ImageFilter.GaussianBlur(radius=max(8, min(box.width, box.height) // 8)))
            else:
                tiny = crop.resize((max(1, box.width // 16), max(1, box.height // 16)))
                crop = tiny.resize((box.width, box.height), Image.Resampling.NEAREST)
            image.paste(crop, coordinates)
    destination.parent.mkdir(parents=True, exist_ok=True)
    image.save(destination, format=destination.suffix.lstrip(".").upper().replace("JPG", "JPEG"), exif=b"")
    selected_public = [_public_detection(item) for item in detections if item.id in selected]
    skipped_public = [_public_detection(item) for item in detections if item.id not in selected]
    return SanitizationReport(
        input_sha256=sha256_file(source),
        output_sha256=sha256_file(destination),
        selected_detections=selected_public,
        skipped_detections=skipped_public,
    )
