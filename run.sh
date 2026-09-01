#!/usr/bin/env sh
set -eu

case "$0" in
    */*) SCRIPT_DIR=${0%/*} ;;
    *) SCRIPT_DIR=. ;;
esac
SCRIPT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR" && pwd)
cd "$SCRIPT_DIR"

skip_model=false
setup_only=false
for argument in "$@"; do
    case "$argument" in
        --skip-model) skip_model=true ;;
        --setup-only) setup_only=true ;;
        --help)
            echo "Usage: ./run.sh [--skip-model] [--setup-only]"
            echo "  --skip-model  Do not install the optional YuNet face model."
            echo "  --setup-only  Install dependencies without starting Streamlit."
            exit 0
            ;;
        *) echo "Unknown option: $argument"; exit 2 ;;
    esac
done

if ! command -v uv >/dev/null 2>&1; then
    echo "[ScreenShield] uv is not installed."
    echo "Install it from https://docs.astral.sh/uv/getting-started/installation/"
    exit 1
fi

echo "[ScreenShield] Preparing the local environment..."
uv sync --locked --python 3.12 --extra app --extra ocr --extra pii --extra vision

if [ "$skip_model" = false ]; then
    echo "[ScreenShield] Checking the pinned YuNet face model..."
    uv run screenshield install-models
fi

if [ "$setup_only" = true ]; then
    echo "[ScreenShield] Setup complete."
    exit 0
fi

echo "[ScreenShield] Opening http://127.0.0.1:8501"
exec uv run streamlit run src/screenshield/app.py
