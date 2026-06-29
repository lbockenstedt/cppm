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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
# Force line-buffering so logs flush immediately when redirected to a file by systemd
try:
    sys.stderr.reconfigure(line_buffering=True)
    sys.stdout.reconfigure(line_buffering=True)
except AttributeError:
    pass
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
