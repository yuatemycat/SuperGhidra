"""Backward compatibility shim for cluster_daemon.
Points to superghidra.core.cluster_daemon.
"""
from __future__ import annotations

import sys
import superghidra.core.cluster_daemon as _cluster_daemon
from superghidra.core.cluster_daemon import *  # noqa: F401, F403

sys.modules["cluster_daemon"] = _cluster_daemon
