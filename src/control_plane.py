"""Entry point that connects the CPPM (ClearPass) spoke to the Lab Manager hub.

Runs either in hub mode (WebSocket link to the hub, commands dispatched to
CPPMSpoke) or in a minimal standalone mode exposing a local status endpoint.
"""
# Dependency self-heal — MUST run before the third-party imports below. A skewed
# auto-update / partial install can leave the venv missing a declared dep, which
# would hard-crash at import and crash-loop the unit under Restart=always.
# dep_guard is stdlib-only; it find_spec-checks requirements.txt and pip-installs
# any missing. Best-effort — an unavailable dep_guard is skipped, never fatal.
# Imported under a private alias so it does not clash with the normal imports below.
import os as _os
# Best-effort: make sure every package in requirements.txt is installed before importing it.
try:
    # Prefer the shared core package path; fall back to a flat install layout.
    try:
        from core.src.dep_guard import ensure_requirements as _ensure_requirements
    except ImportError:
        from dep_guard import ensure_requirements as _ensure_requirements
    # requirements.txt sits one directory above this file (the repo root).
    _ensure_requirements(_os.path.join(
        _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "requirements.txt"))
# Self-heal is optional; never stop the spoke from starting because of it.
except Exception:
    pass

# asyncio runs the hub connection loop.
import asyncio
# json, uuid, time, websockets, hmac and hashlib support the messaging protocol.
import json
import uuid
import time
import websockets
# logging reports progress; argparse and sys handle the command line.
import logging
import hmac
import hashlib
import argparse
import sys
# Type hints only.
from typing import Any, Dict
# FastAPI and uvicorn serve the standalone-mode status endpoint.
from fastapi import FastAPI, HTTPException
import uvicorn

# The spoke implementation that performs the actual ClearPass work.
from spoke import CPPMSpoke
# Shared hub link logic; the import path differs between repo and installed layouts.
try:
    from core.src.messaging.control_plane import BaseControlPlane
except ImportError:
    from messaging.control_plane import BaseControlPlane

# Shared logging setup; try the flat layout, then the core package, then a local fallback.
try:
    from logging_setup import configure_logging
except ImportError:
    try:
        from core.src.logging_setup import configure_logging
    except ImportError:
        # Neither shared helper is available: define a minimal equivalent here.
        import logging as _logging
        # Log line format and timestamp format used by every spoke.
        _FMT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        _DFMT = '%Y-%m-%d %H:%M:%S'
        def configure_logging(default_level=_logging.INFO, *, log_file=None, **_):
            """Fallback logging setup: console output, plus a log file when one is given."""
            # Log to both a file and the console only when a log file was requested.
            handlers = ([_logging.FileHandler(log_file), _logging.StreamHandler()]
                        if log_file else None)
            # force=True replaces any handlers configured earlier.
            _logging.basicConfig(level=default_level, force=True,
                                 format=_FMT, datefmt=_DFMT, handlers=handlers)
# configure_logging subsumes the manual sys.stderr/stdout line-buffering
# reconfigure (now standard for every spoke so systemd file redirects flush).
# Configure logging before anything else logs.
configure_logging()
# One named logger for this control plane.
logger = logging.getLogger("CPPMControlPlane")

class CPPMControlPlane(BaseControlPlane):
    """Control plane connection manager for the CPPM spoke.

    Manages WebSocket communication with the Lab Manager Hub and dispatches
    incoming commands to the registered CPPMSpoke module.
    """

    def get_service_name(self) -> str:
        """Return systemd service name for health reporting."""
        # systemd unit name reported back to the hub for health checks.
        return "lm-cppm"

    def __init__(self, spoke_id: str, secret: str, hub_secret: str = None, hub_url: str = None):
        """Initialize the CPPM control plane client."""
        # Let the base class set up identity, secrets and the hub URL.
        super().__init__(spoke_id, secret, hub_secret, hub_url)
        # Tell the hub this spoke is a network access control (NAC) system.
        self.module_type = "nac"

    def register_module(self, name: str, module_instance: Any):
        """Register a spoke module under a designated namespace."""
        # Commands addressed to this name are routed to the module instance.
        self.modules[name] = module_instance
        logger.info(f"Registered module: {name}")

    async def run(self):
        """Connect to the Lab Manager Hub over WebSocket and handle messages."""
        # Announce which hub this spoke is connecting to.
        logger.info(f"Starting CPPM Module in HUB MODE -> {self.hub_url}")

        # Initialize and register the CPPM module
        cppm_spoke = CPPMSpoke(self.spoke_id, {})
        self.register_module("cppm", cppm_spoke)

        # Hand over to the base class connection/heartbeat/dispatch loop.
        await super().run()

    def run_standalone_mode(self):
        """Run standalone FastAPI server for local management when Hub URL is absent."""
        # Standalone mode only serves a simple health endpoint on port 8000.
        logger.info(f"Starting CPPM Module in STANDALONE MODE on port 8000")
        app = FastAPI()
        # Register GET /status on the local app.
        @app.get("/status")
        async def get_status():
            """Report that the spoke process is alive and which spoke ID it has."""
            return {"status": "online", "spoke_id": self.spoke_id}
        # Serve on all interfaces; this call blocks until the server exits.
        uvicorn.run(app, host="0.0.0.0", port=8000)

if __name__ == "__main__":
    # Command-line flags: spoke identity, shared secrets and the optional hub URL.
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True, help="Spoke ID")
    parser.add_argument("--secret", nargs='?', const="lm-secret", default="lm-secret", help="Authentication secret (default: lm-secret)")
    parser.add_argument("--hub-secret", nargs='?', default="", const="", help="Hub authentication secret for mutual auth")
    parser.add_argument("--hub", help="Hub WebSocket URL (defaults to standalone mode if omitted)")
    # Read the flags the user passed.
    args = parser.parse_args()

    # Build the control plane with the parsed settings.
    cp = CPPMControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    # With a hub URL connect to the hub; otherwise run the local standalone server.
    if args.hub:
        asyncio.run(cp.run())
    else:
        cp.run_standalone_mode()
