from __future__ import annotations

import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from screenshield.demo import generate_demo
from screenshield.pipeline import sanitize


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in (Path("C:/Windows/Fonts/arial.ttf"), Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")):
        if path.exists():
            return ImageFont.truetype(str(path), size)
    return ImageFont.load_default()


def _frame(image: Image.Image, heading: str, caption: str) -> Image.Image:
    canvas = Image.new("RGB", (1000, 650), "#f6f8fa")
    draw = ImageDraw.Draw(canvas)
    draw.rectangle((0, 0, 1000, 65), fill="#24292f")
    draw.text((25, 15), heading, fill="white", font=_font(28))
    preview = image.convert("RGB")
    preview.thumbnail((950, 520))
    canvas.paste(preview, ((1000 - preview.width) // 2, 85))
    draw.text((25, 615), caption, fill="#1f2328", font=_font(19))
    return canvas


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="screenshield-assets-") as temp:
        source = generate_demo(Path(temp))
        destination = Path(temp) / "safe.png"
        report, _ = sanitize(source, destination)
        before = Image.open(source)
        after = Image.open(destination)
        frames = [
            _frame(before, "Before: review locally", "Synthetic screenshot — no real personal data"),
            _frame(
                after,
                "After: high-risk findings redacted",
                f"{len(report.selected_detections)} selected; raw values excluded from the report",
            ),
        ]
        frames[0].save(
            root / "docs" / "demo.gif",
            save_all=True,
            append_images=frames[1:],
            duration=1700,
            loop=0,
            optimize=True,
        )
        before.save(root / "docs" / "before.png")
        after.save(root / "docs" / "after.png")


if __name__ == "__main__":
    main()
