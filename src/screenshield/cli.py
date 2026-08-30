from __future__ import annotations

import argparse
import json
from pathlib import Path

from .demo import generate_demo
from .evaluate import evaluate_demo
from .models import Detection, RedactionMode
from .pipeline import sanitize, scan_image


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="screenshield", description="Local screenshot privacy review")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("image", type=Path)
    scan.add_argument("--lang", choices=["en", "ru"], default="en")
    clean = commands.add_parser("sanitize")
    clean.add_argument("image", type=Path)
    clean.add_argument("--output", type=Path)
    clean.add_argument("--lang", choices=["en", "ru"], default="en")
    clean.add_argument("--mode", choices=[mode.value for mode in RedactionMode], default="solid")
    batch = commands.add_parser("batch")
    batch.add_argument("folder", type=Path)
    batch.add_argument("--output", type=Path, required=True)
    batch.add_argument("--lang", choices=["en", "ru"], default="en")
    demo = commands.add_parser("demo")
    demo.add_argument("--output", type=Path, default=Path("demo/generated"))
    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("--output", type=Path)
    return parser


def _print_public(detections: list[Detection]) -> None:
    print(json.dumps([item.model_dump(mode="json") for item in detections], ensure_ascii=False, indent=2))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "evaluate":
        payload = json.dumps(evaluate_demo(), indent=2)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(payload + "\n", encoding="utf-8")
        print(payload)
        return 0
    if args.command == "demo":
        source = generate_demo(args.output)
        report, _ = sanitize(source, args.output / "safe-screenshot.png")
        (args.output / "sanitization-report.json").write_text(
            report.model_dump_json(indent=2), encoding="utf-8"
        )
        print(args.output / "safe-screenshot.png")
        return 0
    if args.command == "scan":
        detections, _ = scan_image(args.image, args.lang)
        _print_public(detections)
        return 0
    if args.command == "sanitize":
        destination = args.output or args.image.with_name(f"{args.image.stem}.safe{args.image.suffix}")
        report, _ = sanitize(args.image, destination, args.lang, RedactionMode(args.mode))
        report_path = destination.with_suffix(destination.suffix + ".report.json")
        report_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        print(destination)
        return 0
    args.output.mkdir(parents=True, exist_ok=True)
    for image in sorted(args.folder.iterdir()):
        if image.suffix.lower() not in {".png", ".jpg", ".jpeg", ".webp"}:
            continue
        destination = args.output / f"{image.stem}.safe{image.suffix}"
        report, _ = sanitize(image, destination, args.lang)
        destination.with_suffix(destination.suffix + ".report.json").write_text(
            report.model_dump_json(indent=2), encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
