"""Re-export of `superghidra.diff.evidence_ledger` for core domain consumers."""
from __future__ import annotations

import sys as _sys

from superghidra.diff import evidence_ledger as _mod
from superghidra.diff.evidence_ledger import *  # noqa: F401,F403

_sys.modules[__name__] = _mod
