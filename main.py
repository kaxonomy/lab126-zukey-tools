from __future__ import annotations

import argparse
import json

from app.device import discover_device
from app.fido_backend import FidoBackend
from app.legacy import probe_legacy_status
from app.models import model_dict
from app.sanitize import sanitize_diagnostics
from app.ui import run


def headless_check(output: str = "") -> int:
    device = discover_device()
    fido = FidoBackend().refresh(device.serial)
    legacy = probe_legacy_status(device)
    text = json.dumps(
        sanitize_diagnostics(
            {"device": model_dict(device), "fido": model_dict(fido), "legacy": model_dict(legacy)}
        ),
        indent=2,
        default=str,
    )
    if output:
        from pathlib import Path

        Path(output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0 if device.connected else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="ZukeyLab")
    parser.add_argument("--headless-check", action="store_true")
    parser.add_argument("--output", default="")
    args = parser.parse_args()
    if args.headless_check:
        return headless_check(args.output)
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
