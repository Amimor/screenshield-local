from __future__ import annotations

import hashlib
import os
import tempfile
import urllib.request
from pathlib import Path

YUNET_REVISION = "3cc26e7f1014a5ee5d74a42acee58bafc9d0a310"
YUNET_FILENAME = "face_detection_yunet_2023mar.onnx"
YUNET_SHA256 = "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4"
YUNET_URL = (
    "https://huggingface.co/opencv/face_detection_yunet/resolve/"
    f"{YUNET_REVISION}/{YUNET_FILENAME}"
)
MAX_MODEL_BYTES = 5 * 1024 * 1024


def model_directory() -> Path:
    configured = os.environ.get("SCREENSHIELD_MODEL_DIR")
    if configured:
        return Path(configured).expanduser()
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "screenshield-local" / "models"
    return Path.home() / ".cache" / "screenshield-local" / "models"


def yunet_model_path(directory: Path | None = None) -> Path:
    return (directory or model_directory()) / YUNET_FILENAME


def installed_yunet_path(directory: Path | None = None) -> Path | None:
    path = yunet_model_path(directory)
    if not path.is_file():
        return None
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return path if digest == YUNET_SHA256 else None


def install_yunet(directory: Path | None = None) -> Path:
    destination = yunet_model_path(directory)
    existing = installed_yunet_path(directory)
    if existing is not None:
        return existing
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as temporary:
        temporary_path = Path(temporary.name)
        try:
            with urllib.request.urlopen(YUNET_URL, timeout=120) as response:  # noqa: S310
                copied = 0
                while chunk := response.read(65536):
                    copied += len(chunk)
                    if copied > MAX_MODEL_BYTES:
                        raise RuntimeError("Downloaded YuNet model exceeds the expected size limit")
                    temporary.write(chunk)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
    digest = hashlib.sha256(temporary_path.read_bytes()).hexdigest()
    if digest != YUNET_SHA256:
        temporary_path.unlink(missing_ok=True)
        raise RuntimeError("Downloaded YuNet model failed SHA-256 verification")
    temporary_path.replace(destination)
    return destination
