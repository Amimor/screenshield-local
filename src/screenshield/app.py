from __future__ import annotations

import tempfile
from pathlib import Path

import streamlit as st
from PIL import Image, ImageDraw

from .models import Detection, Redaction, RedactionMode
from .pipeline import scan_image
from .redact import sanitize_image


def _annotated(source: Path, detections: list[Detection]) -> Image.Image:
    image = Image.open(source).convert("RGB")
    draw = ImageDraw.Draw(image)
    for detection in detections:
        draw.rectangle(detection.bounding_box.as_tuple(), outline="#d1242f", width=4)
        draw.text(
            (detection.bounding_box.x1, max(0, detection.bounding_box.y1 - 18)),
            detection.category,
            fill="#d1242f",
        )
    return image


def main() -> None:
    st.set_page_config(page_title="ScreenShield Local", page_icon="🛡️", layout="wide")
    st.title("ScreenShield Local")
    st.caption("Review secrets, PII, faces and QR codes before sharing a screenshot.")
    language = st.selectbox("OCR language", ["en", "ru"])
    upload = st.file_uploader("Screenshot", type=["png", "jpg", "jpeg", "webp"])
    if upload is None:
        st.info("Run `screenshield demo` for a deterministic local walkthrough.")
        return
    with tempfile.TemporaryDirectory(prefix="screenshield-") as temp:
        source = Path(temp) / upload.name
        source.write_bytes(upload.getvalue())
        try:
            detections, _ = scan_image(source, language)
        except (ValueError, RuntimeError) as exc:
            st.error(str(exc))
            return
        left, right = st.columns(2)
        left.image(source.read_bytes(), caption="Original")
        right.image(_annotated(source, detections), caption="Review detections")
        st.subheader("Review")
        selections: list[Redaction] = []
        for detection in detections:
            cols = st.columns([1, 2, 2, 2])
            selected = cols[0].checkbox("Redact", detection.default_selected, key=detection.id)
            cols[1].code(detection.category)
            cols[2].write(detection.masked_preview)
            mode = cols[3].selectbox(
                "Mode",
                [x.value for x in RedactionMode],
                key=f"mode-{detection.id}",
                label_visibility="collapsed",
            )
            if selected:
                selections.append(Redaction(detection_id=detection.id, mode=RedactionMode(mode), padding=6))
        if st.button("Create safe copy", type="primary"):
            destination = Path(temp) / f"safe-{upload.name}"
            report = sanitize_image(source, destination, detections, selections)
            st.download_button("Download safe image", destination.read_bytes(), destination.name, upload.type)
            st.download_button(
                "Download privacy report",
                report.model_dump_json(indent=2),
                "privacy-report.json",
                "application/json",
            )


if __name__ == "__main__":
    main()
