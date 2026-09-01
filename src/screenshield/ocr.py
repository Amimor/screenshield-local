from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from .models import BoundingBox, OCRToken


class OCRBackend(Protocol):
    def read(self, path: Path, language: str = "en") -> list[OCRToken]: ...


class SidecarOCRBackend:
    """Read explicit OCR fixtures; never infer text from a filename."""

    def read(self, path: Path, language: str = "en") -> list[OCRToken]:
        sidecar = path.with_suffix(path.suffix + ".ocr.json")
        if not sidecar.exists():
            return []
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
        return [OCRToken.model_validate(item) for item in payload]


class PaddleOCRBackend:
    def __init__(self, language: str = "en") -> None:
        try:
            from paddleocr import PaddleOCR
        except ImportError as exc:  # pragma: no cover - optional integration
            raise RuntimeError("Install screenshield-local[ocr] to scan real screenshots") from exc
        self._engine = PaddleOCR(
            lang=language,
            device="cpu",
            enable_mkldnn=False,
            use_doc_orientation_classify=False,
            use_doc_unwarping=False,
            use_textline_orientation=False,
        )

    def read(self, path: Path, language: str = "en") -> list[OCRToken]:
        results = self._engine.predict(str(path))
        tokens: list[OCRToken] = []
        for page in results:
            data = getattr(page, "json", page)
            if callable(data):
                data = data()
            data = data.get("res", data) if isinstance(data, dict) else {}
            for text, score, box in zip(
                data.get("rec_texts", []), data.get("rec_scores", []), data.get("rec_boxes", []), strict=False
            ):
                x1, y1, x2, y2 = [int(value) for value in box]
                tokens.append(
                    OCRToken(
                        text=str(text),
                        confidence=float(score),
                        bounding_box=BoundingBox(x1=x1, y1=y1, x2=x2, y2=y2),
                    )
                )
        return tokens


class AutoOCRBackend:
    def __init__(self) -> None:
        self._paddle_backends: dict[str, PaddleOCRBackend] = {}

    def read(self, path: Path, language: str = "en") -> list[OCRToken]:
        sidecar_tokens = SidecarOCRBackend().read(path, language)
        if sidecar_tokens:
            return sidecar_tokens
        backend = self._paddle_backends.get(language)
        if backend is None:
            backend = PaddleOCRBackend(language)
            self._paddle_backends[language] = backend
        return backend.read(path, language)
