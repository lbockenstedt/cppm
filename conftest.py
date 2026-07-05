"""Pytest bootstrap: put ``src/`` on sys.path.

The suite mixes import styles — test_queries.py uses ``from src.queries import …``
while test_sync_endpoints.py uses the flat ``from queries import …`` (matching how
the spoke runs in production with ``src/`` on PYTHONPATH). Putting ``src/`` on the
path makes BOTH resolve: flat imports find their module directly, and loading
``src.queries`` still resolves its internal ``from client import CPPMClient``
(previously a ModuleNotFoundError that aborted collection for the whole repo).
"""
import os
import sys

_SRC = os.path.join(os.path.dirname(__file__), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
