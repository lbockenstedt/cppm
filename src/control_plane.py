# Dependency self-heal — MUST run before the third-party imports below. A skewed
# auto-update / partial install can leave the venv missing a declared dep, which
# would hard-crash at import and crash-loop the unit under Restart=always.
# dep_guard is stdlib-only; it find_spec-checks requirements.txt and pip-installs
# any missing. Best-effort — an unavailable dep_guard is skipped, never fatal.
import os as _os
try:
    try:
        from core.src.dep_guard import ensure_requirements as _ensure_requirements
    except ImportError:
        from dep_guard import ensure_requirements as _ensure_requirements
    _ensure_requirements(_os.path.join(
        _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "requirements.txt"))
except Exception:
    pass

import asyncio
import json
import uuid
import time
import websockets
import logging
import hmac
import hashlib
import argparse
import sys
from typing import Any, Dict
from fastapi import FastAPI, HTTPException
import uvicorn

from spoke import CPPMSpoke
try:
    from core.src.messaging.control_plane import BaseControlPlane
except ImportError:
    from messaging.control_plane import BaseControlPlane

try:
    from logging_setup import configure_logging
except ImportError:
    try:
        from core.src.logging_setup import configure_logging
    except ImportError:
        import logging as _logging
        _FMT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        _DFMT = '%Y-%m-%d %H:%M:%S'
        def configure_logging(default_level=_logging.INFO, *, log_file=None, **_):
            handlers = ([_logging.FileHandler(log_file), _logging.StreamHandler()]
                        if log_file else None)
            _logging.basicConfig(level=default_level, force=True,
                                 format=_FMT, datefmt=_DFMT, handlers=handlers)
# configure_logging subsumes the manual sys.stderr/stdout line-buffering
# reconfigure (now standard for every spoke so systemd file redirects flush).
configure_logging()
logger = logging.getLogger("CPPMControlPlane")

class CPPMControlPlane(BaseControlPlane):
    def get_service_name(self) -> str:
        return "lm-cppm"

    def __init__(self, spoke_id: str, secret: str, hub_secret: str = None, hub_url: str = None):
        super().__init__(spoke_id, secret, hub_secret, hub_url)
        self.module_type = "nac"

    def register_module(self, name: str, module_instance: Any):
        self.modules[name] = module_instance
        logger.info(f"Registered module: {name}")

    async def run(self):
        """Native LM Spoke behavior."""
        logger.info(f"Starting CPPM Module in HUB MODE -> {self.hub_url}")

        # Initialize and register the CPPM module
        cppm_spoke = CPPMSpoke(self.spoke_id, {})
        self.register_module("cppm", cppm_spoke)

        await super().run()
    def run_standalone_mode(self):
        """Standalone FastAPI server for local management."""
        logger.info(f"Starting CPPM Module in STANDALONE MODE on port 8000")
        app = FastAPI()
        @app.get("/status")
        async def get_status():
            return {"status": "online", "spoke_id": self.spoke_id}
        uvicorn.run(app, host="0.0.0.0", port=8000)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True, help="Spoke ID")
    parser.add_argument("--secret", nargs='?', const="lm-secret", default="lm-secret", help="Authentication secret (default: lm-secret)")
    parser.add_argument("--hub-secret", nargs='?', default="", const="", help="Hub authentication secret for mutual auth")
    parser.add_argument("--hub", help="Hub WebSocket URL (defaults to standalone mode if omitted)")
    args = parser.parse_args()

    cp = CPPMControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    if args.hub:
        asyncio.run(cp.run())
    else:
        cp.run_standalone_mode()
