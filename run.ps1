param(
    [switch]$SkipModel,
    [switch]$SetupOnly,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

if ($Help) {
    Write-Host "Usage: .\run.ps1 [-SkipModel] [-SetupOnly]"
    Write-Host "  -SkipModel  Do not download or verify the optional YuNet face model."
    Write-Host "  -SetupOnly  Install dependencies without starting Streamlit."
    exit 0
}

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Error "uv is not installed. See https://docs.astral.sh/uv/getting-started/installation/"
}

Write-Host "[ScreenShield] Preparing the local environment..."
& uv sync --locked --python 3.12 --extra app --extra ocr --extra pii --extra vision
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

if (-not $SkipModel) {
    Write-Host "[ScreenShield] Checking the pinned YuNet face model..."
    & uv run screenshield install-models
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

if ($SetupOnly) {
    Write-Host "[ScreenShield] Setup complete."
    exit 0
}

Write-Host "[ScreenShield] Opening http://127.0.0.1:8501"
& uv run streamlit run src/screenshield/app.py
exit $LASTEXITCODE
