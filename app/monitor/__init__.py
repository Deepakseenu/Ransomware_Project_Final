"""
Monitor package init (clean)

We intentionally DO NOT import app.monitor.main here, because that causes
double-import issues when running:

    python3 -m app.monitor.main

and results in FileGuard, ProcessGuard, NetGuard starting twice.

This file is intentionally empty to avoid side effects.
"""

__all__ = []
