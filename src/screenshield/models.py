from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class RedactionMode(StrEnum):
    SOLID = "solid"
    PIXELATE = "pixelate"
    BLUR = "blur"


class BoundingBox(BaseModel):
    x1: int
    y1: int
    x2: int
    y2: int

    @property
    def width(self) -> int:
        return max(0, self.x2 - self.x1)

    @property
    def height(self) -> int:
        return max(0, self.y2 - self.y1)

    def padded(self, amount: int, image_size: tuple[int, int]) -> BoundingBox:
        width, height = image_size
        return BoundingBox(
            x1=max(0, self.x1 - amount),
            y1=max(0, self.y1 - amount),
            x2=min(width, self.x2 + amount),
            y2=min(height, self.y2 + amount),
        )

    def intersects(self, other: BoundingBox) -> bool:
        return not (self.x2 <= other.x1 or other.x2 <= self.x1 or self.y2 <= other.y1 or other.y2 <= self.y1)

    def union(self, other: BoundingBox) -> BoundingBox:
        return BoundingBox(
            x1=min(self.x1, other.x1),
            y1=min(self.y1, other.y1),
            x2=max(self.x2, other.x2),
            y2=max(self.y2, other.y2),
        )

    def as_tuple(self) -> tuple[int, int, int, int]:
        return self.x1, self.y1, self.x2, self.y2


class OCRToken(BaseModel):
    text: str
    bounding_box: BoundingBox
    confidence: float = Field(ge=0, le=1)


class Detection(BaseModel):
    id: str
    category: str
    bounding_box: BoundingBox
    confidence: float = Field(ge=0, le=1)
    detector: str
    masked_preview: str
    value_sha256: str
    default_selected: bool


class Redaction(BaseModel):
    detection_id: str
    mode: RedactionMode = RedactionMode.SOLID
    padding: int = Field(default=4, ge=0, le=100)


class SanitizationReport(BaseModel):
    input_sha256: str
    output_sha256: str
    selected_detections: list[dict[str, str | float | list[int]]]
    skipped_detections: list[dict[str, str | float | list[int]]]
    stripped_metadata: bool = True
    policy_version: str = "1.0"
