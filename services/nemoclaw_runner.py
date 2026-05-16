"""FastAPI entrypoint for the SentinelAI agent orchestrator.

In production this service runs inside the real NemoClaw sandbox (see
nemoclaw.config.yaml). The HTTP surface is the same either way.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from .models import RunAgentsRequest
from .orchestrator import stream_pipeline


@asynccontextmanager
async def _lifespan(_: FastAPI):
    yield


app = FastAPI(title="SentinelAI / NemoClaw runner", version="0.1.0", lifespan=_lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "model": os.getenv("NEMOTRON_MODEL", "nvidia/llama-3.1-nemotron-70b-instruct"),
        "has_api_key": bool(os.getenv("NVIDIA_API_KEY") or os.getenv("NEMOCLAW_API_KEY")),
        "has_supabase": bool(os.getenv("SUPABASE_SERVICE_ROLE_KEY")),
    }


@app.post("/run-agents")
async def run_agents(req: RunAgentsRequest):
    if not req.logs:
        raise HTTPException(status_code=400, detail="logs cannot be empty")
    if not (os.getenv("NVIDIA_API_KEY") or os.getenv("NEMOCLAW_API_KEY")):
        return JSONResponse(
            status_code=503,
            content={"error": "No NVIDIA_API_KEY (or NEMOCLAW_API_KEY) configured. Set it in .env."},
        )

    return StreamingResponse(
        stream_pipeline(req.incidentId, req.logs, req.meta),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "services.nemoclaw_runner:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("RELOAD", "false").lower() == "true",
    )
