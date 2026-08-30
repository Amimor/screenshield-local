from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import uuid4

from .models import BoundingBox, Detection


def _visual_detection(category: str, box: BoundingBox, detector: str, confidence: float) -> Detection:
    digest = hashlib.sha256(f"{category}:{box.model_dump_json()}".encode()).hexdigest()
    return Detection(
        id=str(uuid4()),
        category=category,
        bounding_box=box,
        confidence=confidence,
        detector=detector,
        masked_preview=f"<{category.lower()}>",
        value_sha256=digest,
        default_selected=category == "QR_CODE",
    )


class SidecarVisualDetector:
    def detect(self, path: Path) -> list[Detection]:
        sidecar = path.with_suffix(path.suffix + ".visual.json")
        if not sidecar.exists():
            return []
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
        return [
            _visual_detection(
                item["category"],
                BoundingBox.model_validate(item["bounding_box"]),
                "visual-sidecar",
                float(item.get("confidence", 1.0)),
            )
            for item in payload
        ]


class OpenCVVisualDetector:
    """QR and face detector. YuNet is used when an ONNX model path is supplied."""

    def __init__(self, face_model: Path | None = None) -> None:
        try:
            import cv2
        except ImportError as exc:  # pragma: no cover - optional integration
            raise RuntimeError("Install screenshield-local[vision] to enable QR/face detection") from exc
        self.cv2 = cv2
        self.face_model = face_model

    def detect(self, path: Path) -> list[Detection]:
        cv2 = self.cv2
        image = cv2.imread(str(path))
        if image is None:
            return []
        detections: list[Detection] = []
        qr = cv2.QRCodeDetector()
        try:
            ok, _, points, _ = qr.detectAndDecodeMulti(image)
        except ValueError:  # OpenCV builds differ in return arity
            ok, points = False, None
        if ok and points is not None:
            for polygon in points:
                xs, ys = polygon[:, 0], polygon[:, 1]
                box = BoundingBox(x1=int(xs.min()), y1=int(ys.min()), x2=int(xs.max()), y2=int(ys.max()))
                detections.append(_visual_detection("QR_CODE", box, "opencv-qr", 0.98))
        if self.face_model and self.face_model.exists():
            height, width = image.shape[:2]
            detector = cv2.FaceDetectorYN.create(str(self.face_model), "", (width, height))
            detector.setInputSize((width, height))
            _, faces = detector.detect(image)
            if faces is not None:
                for face in faces:
                    x, y, w, h = face[:4]
                    box = BoundingBox(x1=int(x), y1=int(y), x2=int(x + w), y2=int(y + h))
                    detections.append(_visual_detection("FACE", box, "opencv-yunet", float(face[-1])))
        return detections


class AutoVisualDetector:
    def __init__(self, face_model: Path | None = None) -> None:
        self.face_model = face_model

    def detect(self, path: Path) -> list[Detection]:
        sidecar = SidecarVisualDetector().detect(path)
        if sidecar:
            return sidecar
        return OpenCVVisualDetector(self.face_model).detect(path)
