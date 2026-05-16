"""Nemotron client targeting NVIDIA NIM (build.nvidia.com / integrate.api.nvidia.com).

NemoClaw uses the same NVIDIA API key under the hood when routing to cloud
Nemotron models; we honour both `NVIDIA_API_KEY` and the spec's
`NEMOCLAW_API_KEY` env var.
"""
from __future__ import annotations

import json
import os
from typing import Any, AsyncIterator, Optional

import httpx

NIM_BASE_URL = os.getenv("NEMOTRON_BASE_URL", "https://integrate.api.nvidia.com/v1")
NIM_MODEL = os.getenv("NEMOTRON_MODEL", "nvidia/llama-3.1-nemotron-70b-instruct")


def _api_key() -> str:
    key = os.getenv("NVIDIA_API_KEY") or os.getenv("NEMOCLAW_API_KEY")
    if not key:
        raise RuntimeError(
            "Missing NVIDIA_API_KEY (or NEMOCLAW_API_KEY). "
            "Get one from build.nvidia.com or your NemoClaw setup."
        )
    return key


class NemotronClient:
    def __init__(self, timeout: float = 120.0):
        self._client = httpx.AsyncClient(timeout=timeout)

    async def close(self):
        await self._client.aclose()

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]] = None,
        temperature: float = 0.2,
        max_tokens: int = 1500,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": NIM_MODEL,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"

        r = await self._client.post(
            f"{NIM_BASE_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {_api_key()}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json=body,
        )
        r.raise_for_status()
        return r.json()

    async def stream(
        self,
        messages: list[dict[str, Any]],
        temperature: float = 0.3,
        max_tokens: int = 1500,
    ) -> AsyncIterator[str]:
        body = {
            "model": NIM_MODEL,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
        }
        async with self._client.stream(
            "POST",
            f"{NIM_BASE_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {_api_key()}",
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
            },
            json=body,
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line or not line.startswith("data: "):
                    continue
                payload = line[6:].strip()
                if payload == "[DONE]":
                    break
                try:
                    obj = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                choices = obj.get("choices") or []
                if not choices:
                    continue
                delta = choices[0].get("delta") or {}
                token = delta.get("content")
                if token:
                    yield token
