from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from uuid import uuid4

from .models import BoundingBox, Detection, OCRToken


@dataclass(frozen=True)
class PatternSpec:
    category: str
    pattern: re.Pattern[str]
    confidence: float
    default_selected: bool
    validator: object | None = None


def _valid_luhn(value: str) -> bool:
    digits = [int(char) for char in re.sub(r"\D", "", value)]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


PATTERNS = [
    PatternSpec(
        "PRIVATE_KEY",
        re.compile(r"-----BEGIN ((?:RSA |EC |OPENSSH )?PRIVATE KEY)-----[\s\S]{0,4096}?-----END \1-----"),
        1.0,
        True,
    ),
    PatternSpec(
        "PRIVATE_KEY",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        0.95,
        True,
    ),
    PatternSpec(
        "DATABASE_URL",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s]+", re.I),
        0.99,
        True,
    ),
    PatternSpec(
        "JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0.99, True
    ),
    PatternSpec("BEARER_TOKEN", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{16,}", re.I), 0.98, True),
    PatternSpec("GITHUB_TOKEN", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}\b"), 0.99, True),
    PatternSpec("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), 0.99, True),
    PatternSpec("OPENAI_STYLE_KEY", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), 0.98, True),
    PatternSpec("EMAIL", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), 0.98, True),
    PatternSpec(
        "PHONE",
        re.compile(r"(?<!\d)(?:\+?7|8|\+?1)[ \t().-]*(?:\d[ \t().-]*){10}(?!\d)"),
        0.9,
        True,
    ),
    PatternSpec("PAYMENT_CARD", re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"), 0.98, True, _valid_luhn),
    PatternSpec(
        "RU_PASSPORT",
        re.compile(r"(?<!\d)\d{2}[ \t]\d{2}[ \t]\d{6}(?!\d)"),
        0.86,
        False,
    ),
    PatternSpec("IP_ADDRESS", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), 0.85, False, _valid_ip),
    PatternSpec(
        "URL_TOKEN", re.compile(r"https?://[^\s]+[?&](?:token|key|auth|signature)=[^\s&]+", re.I), 0.95, True
    ),
    PatternSpec(
        "RU_ADDRESS",
        re.compile(r"\b(?:ул\.|улица|проспект|пр-т|дом|д\.)\s+[А-ЯЁA-Z][^,\n]{2,45}", re.I),
        0.65,
        False,
    ),
    PatternSpec(
        "PERSON_NAME",
        re.compile(r"\b(?:Name|Имя)\s*:\s*([A-ZА-ЯЁ][a-zа-яё]+(?:\s+[A-ZА-ЯЁ][a-zа-яё]+){1,2})"),
        0.7,
        False,
    ),
]


def _masked(value: str) -> str:
    if len(value) <= 4:
        return "•" * len(value)
    return f"{value[:2]}{'•' * min(10, len(value) - 4)}{value[-2:]}"


def _value_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _join_tokens(tokens: list[OCRToken]) -> tuple[str, list[tuple[int, int, OCRToken]]]:
    parts: list[str] = []
    offsets: list[tuple[int, int, OCRToken]] = []
    cursor = 0
    for token in tokens:
        if parts:
            parts.append("\n")
            cursor += 1
        start = cursor
        parts.append(token.text)
        cursor += len(token.text)
        offsets.append((start, cursor, token))
    return "".join(parts), offsets


def _bbox_for_span(start: int, end: int, offsets: list[tuple[int, int, OCRToken]]) -> BoundingBox | None:
    boxes: list[BoundingBox] = []
    for token_start, token_end, token in offsets:
        if token_end <= start or token_start >= end:
            continue
        length = max(1, token_end - token_start)
        relative_start = max(0, start - token_start) / length
        relative_end = min(length, end - token_start) / length
        source = token.bounding_box
        boxes.append(
            BoundingBox(
                x1=int(source.x1 + source.width * relative_start),
                y1=source.y1,
                x2=int(source.x1 + source.width * relative_end),
                y2=source.y2,
            )
        )
    if not boxes:
        return None
    box = boxes[0]
    for candidate in boxes[1:]:
        box = box.union(candidate)
    return box


def detect_patterns(tokens: list[OCRToken]) -> list[Detection]:
    text, offsets = _join_tokens(tokens)
    detections: list[Detection] = []
    for spec in PATTERNS:
        for match in spec.pattern.finditer(text):
            value = match.group(0)
            if callable(spec.validator) and not spec.validator(value):
                continue
            box = _bbox_for_span(match.start(), match.end(), offsets)
            if box is None:
                continue
            detections.append(
                Detection(
                    id=str(uuid4()),
                    category=spec.category,
                    bounding_box=box,
                    confidence=spec.confidence,
                    detector="local-pattern",
                    masked_preview=_masked(value),
                    value_sha256=_value_digest(value),
                    default_selected=spec.default_selected,
                )
            )
    return detections


class PresidioRecognizer:
    """Optional adapter for low-confidence names and locations."""

    def __init__(self) -> None:
        try:
            from presidio_analyzer import AnalyzerEngine
        except ImportError as exc:  # pragma: no cover - optional integration
            raise RuntimeError("Install screenshield-local[pii] to enable Presidio") from exc
        self._analyzer = AnalyzerEngine()

    def detect(self, tokens: list[OCRToken], language: str = "en") -> list[Detection]:
        text, offsets = _join_tokens(tokens)
        if language != "en":
            return []
        results = self._analyzer.analyze(text=text, language="en", entities=["PERSON", "LOCATION"])
        detections: list[Detection] = []
        for result in results:
            box = _bbox_for_span(result.start, result.end, offsets)
            if box is None:
                continue
            value = text[result.start : result.end]
            detections.append(
                Detection(
                    id=str(uuid4()),
                    category=result.entity_type,
                    bounding_box=box,
                    confidence=float(result.score),
                    detector="presidio",
                    masked_preview=_masked(value),
                    value_sha256=_value_digest(value),
                    default_selected=False,
                )
            )
        return detections
