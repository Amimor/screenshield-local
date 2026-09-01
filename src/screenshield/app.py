from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import streamlit as st
from PIL import Image, ImageDraw

from screenshield.model_store import install_yunet, installed_yunet_path
from screenshield.models import Detection, Redaction, RedactionMode, SanitizationReport
from screenshield.ocr import AutoOCRBackend
from screenshield.pipeline import scan_image
from screenshield.recognizers import PresidioRecognizer
from screenshield.redact import sanitize_image


@st.cache_resource(show_spinner=False)
def _ocr_backend() -> AutoOCRBackend:
    return AutoOCRBackend()


@st.cache_resource(show_spinner="Loading the local Presidio NLP model...")
def _presidio_backend() -> PresidioRecognizer:
    return PresidioRecognizer()


def _workspace() -> Path:
    current = st.session_state.get("workspace")
    if current:
        return Path(current)
    path = Path(tempfile.mkdtemp(prefix="screenshield-local-"))
    st.session_state.workspace = str(path)
    return path


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


def _save_upload(upload: Any) -> Path:
    name = Path(str(upload.name)).name
    path = _workspace() / f"input-{name}"
    path.write_bytes(upload.getvalue())
    return path


def _selection_key(detection: Detection) -> str:
    return f"selected-{detection.id}"


def _mode_key(detection: Detection) -> str:
    return f"mode-{detection.id}"


def _redactions(detections: list[Detection]) -> list[Redaction]:
    redactions: list[Redaction] = []
    for detection in detections:
        if st.session_state.get(_selection_key(detection), detection.default_selected):
            redactions.append(
                Redaction(
                    detection_id=detection.id,
                    mode=RedactionMode(st.session_state.get(_mode_key(detection), RedactionMode.SOLID.value)),
                    padding=int(st.session_state.get(f"padding-{detection.id}", 6)),
                )
            )
    return redactions


def _render_preview(source: Path, detections: list[Detection]) -> tuple[Path, SanitizationReport]:
    suffix = source.suffix.lower() if source.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"} else ".png"
    destination = _workspace() / f"preview{suffix}"
    report = sanitize_image(source, destination, detections, _redactions(detections))
    return destination, report


def main() -> None:
    st.set_page_config(page_title="ScreenShield Local", page_icon="🛡️", layout="wide")
    st.title("ScreenShield Local")
    st.caption("Review secrets, PII, faces and QR codes before sharing a screenshot.")
    language = st.selectbox("OCR language", ["en", "ru"], format_func=lambda value: value.upper())
    use_presidio = st.checkbox(
        "Detect low-confidence people and locations with Presidio",
        value=True,
        help="English only. These detections are never selected automatically.",
    )
    model_path = installed_yunet_path()
    status_columns = st.columns([3, 1])
    if model_path:
        status_columns[0].success("YuNet face detector is installed and verified.")
    else:
        status_columns[0].info("YuNet is optional. QR and text detectors work without it.")
        if status_columns[1].button("Install YuNet"):
            try:
                with st.spinner("Downloading the pinned YuNet model and verifying SHA-256..."):
                    model_path = install_yunet()
            except (OSError, RuntimeError) as exc:
                st.error(f"Could not install YuNet: {exc}")
            else:
                st.success("YuNet installed.")
                st.rerun()
    upload = st.file_uploader("Screenshot", type=["png", "jpg", "jpeg", "webp"])
    if upload is None:
        st.info("Run `screenshield demo` for a deterministic local walkthrough.")
        return

    if st.button("Scan locally", type="primary"):
        source = _save_upload(upload)
        try:
            with st.spinner("Running local OCR, secret detection and visual checks..."):
                detections, _ = scan_image(
                    source,
                    language,
                    ocr=_ocr_backend(),
                    include_presidio=use_presidio,
                    presidio=_presidio_backend() if use_presidio else None,
                    face_model=model_path,
                )
        except (ValueError, RuntimeError) as exc:
            st.error(str(exc))
        else:
            st.session_state.source_path = str(source)
            st.session_state.detections = detections
            st.session_state.language = language
            for detection in detections:
                st.session_state[_selection_key(detection)] = detection.default_selected
                st.session_state[_mode_key(detection)] = RedactionMode.SOLID.value
                st.session_state[f"padding-{detection.id}"] = 6

    if "detections" not in st.session_state:
        return
    source = Path(st.session_state.source_path)
    detections = st.session_state.detections

    action_columns = st.columns([1, 1, 3])
    if action_columns[0].button("Select high-risk"):
        for detection in detections:
            st.session_state[_selection_key(detection)] = detection.default_selected
        st.rerun()
    if action_columns[1].button("Clear"):
        for detection in detections:
            st.session_state[_selection_key(detection)] = False
        st.rerun()
    action_columns[2].caption("Faces, people, locations and addresses require explicit confirmation.")

    st.subheader("Review detections")
    for detection in detections:
        columns = st.columns([0.8, 1.5, 1.7, 1.2, 1])
        columns[0].checkbox("Redact", key=_selection_key(detection))
        columns[1].code(detection.category)
        columns[2].write(detection.masked_preview)
        columns[3].selectbox(
            "Mode",
            [mode.value for mode in RedactionMode],
            key=_mode_key(detection),
            label_visibility="collapsed",
        )
        columns[4].number_input(
            "Padding",
            min_value=0,
            max_value=100,
            key=f"padding-{detection.id}",
            label_visibility="collapsed",
        )

    preview, report = _render_preview(source, detections)
    left, right = st.columns(2)
    left.image(_annotated(source, detections), caption="Original with review boxes", use_container_width=True)
    right.image(preview.read_bytes(), caption="Sanitized preview", use_container_width=True)

    selected_count = len(report.selected_detections)
    st.caption(f"{selected_count} of {len(detections)} detections selected. Output metadata is stripped.")
    if st.button("Prepare export", type="primary"):
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        destination = _workspace() / f"safe-{stamp}{source.suffix.lower()}"
        report = sanitize_image(source, destination, detections, _redactions(detections))
        st.session_state.export_path = str(destination)
        st.session_state.report_json = report.model_dump_json(indent=2)
    export_path = st.session_state.get("export_path")
    if export_path and Path(export_path).is_file():
        destination = Path(export_path)
        st.download_button("Download safe image", destination.read_bytes(), destination.name, upload.type)
        st.download_button(
            "Download privacy report",
            st.session_state.report_json,
            "privacy-report.json",
            "application/json",
        )


if __name__ == "__main__":
    main()
