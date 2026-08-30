from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from PIL import Image, ImageDraw, ImageFont

from .models import BoundingBox, OCRToken

DEMO_LINES = [
    ("Name: Alex Morgan", "PERSON_NAME", False),
    ("Email: alex.morgan@example.com", "EMAIL", True),
    ("Телефон: +7 (999) 123-45-67", "PHONE", True),
    ("Card: 4111 1111 1111 1111", "PAYMENT_CARD", True),
    ("GitHub: ghp_abcdefghijklmnopqrstuvwxyz1234567890", "GITHUB_TOKEN", True),
    ("API: sk-demoKey_abcdefghijklmnopqrstuvwxyz", "OPENAI_STYLE_KEY", True),
    ("Database: postgres://admin:secret@localhost:5432/app", "DATABASE_URL", True),
    ("Server: 192.168.10.25", "IP_ADDRESS", False),
    ("Адрес: ул. Примерная, дом 7", "RU_ADDRESS", False),
]


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in (
        Path("C:/Windows/Fonts/consola.ttf"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
    ):
        if path.exists():
            return ImageFont.truetype(str(path), size)
    return ImageFont.load_default()


def _qr_image(data: str, size: int) -> Image.Image:
    try:
        import qrcode
    except ImportError:
        # A clearly labeled placeholder keeps the core demo dependency-free.
        # Installing the `demo` extra produces a standards-compliant QR code.
        image = Image.new("RGB", (size, size), "white")
        draw = ImageDraw.Draw(image)
        for row in range(21):
            for col in range(21):
                if (row * 17 + col * 31 + row * col) % 5 < 2:
                    step = size / 21
                    draw.rectangle(
                        (int(col * step), int(row * step), int((col + 1) * step), int((row + 1) * step)),
                        fill="black",
                    )
        return image
    qr = qrcode.QRCode(version=2, box_size=6, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    generated = qr.make_image(fill_color="black", back_color="white").convert("RGB").resize((size, size))
    return cast(Image.Image, generated)


def generate_demo(folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    output = folder / "unsafe-screenshot.png"
    image = Image.new("RGB", (1500, 900), "#f6f8fa")
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 1500, 64), fill="#24292f")
    draw.text((30, 16), "Internal support console — DO NOT SHARE", fill="white", font=_font(26))
    draw.rounded_rectangle((35, 95, 1080, 830), radius=16, fill="white", outline="#d0d7de", width=3)
    tokens: list[OCRToken] = []
    y = 130
    line_font = _font(25)
    for line, _, _ in DEMO_LINES:
        draw.text((75, y), line, fill="#1f2328", font=line_font)
        rendered = draw.textbbox((75, y), line, font=line_font)
        box = BoundingBox(x1=int(rendered[0]), y1=int(rendered[1]), x2=int(rendered[2]), y2=int(rendered[3]))
        tokens.append(OCRToken(text=line, bounding_box=box, confidence=1.0))
        y += 68

    # A generated avatar is marked as a visual review fixture, not claimed as a detector benchmark.
    draw.ellipse((1180, 115, 1405, 340), fill="#e6b89c", outline="#57606a", width=4)
    draw.ellipse((1235, 190, 1260, 215), fill="#24292f")
    draw.ellipse((1325, 190, 1350, 215), fill="#24292f")
    draw.arc((1245, 215, 1340, 285), 10, 170, fill="#24292f", width=5)
    qr_box = (1190, 480, 1390, 680)
    image.paste(_qr_image("https://example.invalid/reset?token=demo-only", 200), qr_box[:2])
    draw.text((1188, 700), "Account reset QR", fill="#24292f", font=_font(20))
    image.save(output, pnginfo=None)
    output.with_suffix(output.suffix + ".ocr.json").write_text(
        json.dumps([token.model_dump(mode="json") for token in tokens], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    output.with_suffix(output.suffix + ".visual.json").write_text(
        json.dumps(
            [
                {
                    "category": "FACE",
                    "bounding_box": {"x1": 1175, "y1": 110, "x2": 1410, "y2": 345},
                    "confidence": 1.0,
                },
                {
                    "category": "QR_CODE",
                    "bounding_box": {"x1": 1190, "y1": 480, "x2": 1390, "y2": 680},
                    "confidence": 1.0,
                },
            ],
            indent=2,
        ),
        encoding="utf-8",
    )
    (folder / "ground-truth.json").write_text(
        json.dumps(
            {
                "required_categories": [category for _, category, selected in DEMO_LINES if selected]
                + ["QR_CODE"],
                "review_categories": [category for _, category, selected in DEMO_LINES if not selected]
                + ["FACE"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return output
