"""Pytest configuration ensuring root shims and cross-test helpers are importable."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_FORMATS = Path(__file__).resolve().parent / "formats"

for p in (str(TESTS_FORMATS), str(REPO_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)
