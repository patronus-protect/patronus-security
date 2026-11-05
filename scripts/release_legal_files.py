#!/usr/bin/env python3
"""Check that the legal files packaged with each crate and wheel are current."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
# Package copies that must equal their source byte for byte.
COPIES = (
    ("LICENSE", "rust/LICENSE"),
    ("LICENSE-COMMERCIAL.md", "rust/LICENSE-COMMERCIAL.md"),
    ("NOTICE", "rust/NOTICE"),
    ("LICENSE", "python/LICENSE"),
    ("LICENSE-COMMERCIAL.md", "python/LICENSE-COMMERCIAL.md"),
    ("NOTICE", "python/NOTICE"),
    ("ark-core/LICENSE-MIT", "ark-core/python/LICENSE-MIT"),
    ("ark-core/LICENSE-APACHE", "ark-core/python/LICENSE-APACHE"),
    ("ark-core/NOTICE", "ark-core/python/NOTICE"),
)
CORE_NOTICE = "ark-core/NOTICE"
RULE = "-" * 79


def notice_sections(text: str) -> dict[str, str]:
    """Third-party sections keyed by their title without the section number."""
    parts = text.split(RULE + "\n")
    return {
        re.sub(r"^\d+\. ", "", parts[i]): parts[i + 1].rstrip("\n")
        for i in range(1, len(parts) - 1, 2)
    }


def problems(root: Path = ROOT) -> list[str]:
    found = [
        f"{copy} differs from {source}"
        for source, copy in COPIES
        if (root / source).read_bytes() != (root / copy).read_bytes()
    ]
    notice = notice_sections((root / "NOTICE").read_text())
    core = notice_sections((root / CORE_NOTICE).read_text())
    if not core:
        found.append(f"{CORE_NOTICE} has no third-party sections")
    # Core ships inside Ark, so each Core attribution is part of the root NOTICE.
    found += [
        f"{CORE_NOTICE} section {title.splitlines()[0]!r} is missing from NOTICE or differs"
        for title, body in core.items()
        if notice.get(title) != body
    ]
    # Every attribution of Core sources belongs in the Core NOTICE.
    found += [
        f"NOTICE section {title.splitlines()[0]!r} covers ark-core/ but is missing from {CORE_NOTICE}"
        for title in notice
        if "ark-core/" in title and title not in core
    ]
    return found


if __name__ == "__main__":
    if found := problems():
        sys.exit("\n".join(found))
