"""Server-side writes to Supabase via the REST API (service role key)."""
from __future__ import annotations

import os
from typing import Any, Optional

import httpx


def _required(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise RuntimeError(f"Missing required env var: {name}")
    return v


class SupabaseWriter:
    def __init__(self):
        self.url = _required("NEXT_PUBLIC_SUPABASE_URL").rstrip("/")
        self.key = _required("SUPABASE_SERVICE_ROLE_KEY")
        self._client = httpx.AsyncClient(timeout=30.0)

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }

    async def close(self):
        await self._client.aclose()

    async def insert(self, table: str, row: dict[str, Any]) -> dict:
        r = await self._client.post(f"{self.url}/rest/v1/{table}", headers=self._headers, json=row)
        r.raise_for_status()
        data = r.json()
        return data[0] if isinstance(data, list) and data else (data or {})

    async def upsert(self, table: str, row: dict[str, Any], on_conflict: str) -> dict:
        r = await self._client.post(
            f"{self.url}/rest/v1/{table}?on_conflict={on_conflict}",
            headers={**self._headers, "Prefer": "return=representation,resolution=merge-duplicates"},
            json=row,
        )
        r.raise_for_status()
        data = r.json()
        return data[0] if isinstance(data, list) and data else (data or {})

    async def update(self, table: str, *, match: dict[str, Any], patch: dict[str, Any]) -> dict:
        params = "&".join(f"{k}=eq.{v}" for k, v in match.items())
        r = await self._client.patch(
            f"{self.url}/rest/v1/{table}?{params}",
            headers=self._headers,
            json=patch,
        )
        r.raise_for_status()
        data = r.json()
        return data[0] if isinstance(data, list) and data else (data or {})

    async def rpc_increment_benchmark(self, *, agent_name: str, task_ok: bool, challenged: bool = False, overruled: bool = False, jailbreak: bool = False, unhealthy: bool = False):
        # Read-modify-write is fine for hackathon scale; production would use an rpc function.
        r = await self._client.get(
            f"{self.url}/rest/v1/agent_benchmarks?agent_name=eq.{agent_name}",
            headers=self._headers,
        )
        r.raise_for_status()
        rows = r.json() or []
        if not rows:
            base = {
                "agent_name": agent_name,
                "tasks_completed": 1 if task_ok else 0,
                "accuracy_score": 1.0 if task_ok else 0.9,
                "times_challenged": 1 if challenged else 0,
                "times_overruled": 1 if overruled else 0,
                "jailbreak_attempts": 1 if jailbreak else 0,
                "health_status": "compromised" if unhealthy else "healthy",
            }
            return await self.insert("agent_benchmarks", base)

        row = rows[0]
        patch = {
            "tasks_completed": (row.get("tasks_completed") or 0) + (1 if task_ok else 0),
            "accuracy_score": min(1.0, max(0.0, (row.get("accuracy_score") or 1.0) + (0.0 if task_ok else -0.05))),
            "times_challenged": (row.get("times_challenged") or 0) + (1 if challenged else 0),
            "times_overruled": (row.get("times_overruled") or 0) + (1 if overruled else 0),
            "jailbreak_attempts": (row.get("jailbreak_attempts") or 0) + (1 if jailbreak else 0),
            "health_status": "compromised" if unhealthy else (row.get("health_status") or "healthy"),
            "last_updated": "now()",
        }
        return await self.update("agent_benchmarks", match={"agent_name": agent_name}, patch=patch)

    async def save_agent_message(
        self,
        *,
        incident_id: str,
        agent_name: str,
        role: Optional[str],
        content: str,
        is_challenge: bool = False,
        is_flagged: bool = False,
        metadata: Optional[dict] = None,
    ) -> dict:
        return await self.insert("agent_messages", {
            "incident_id": incident_id,
            "agent_name": agent_name,
            "role": role,
            "content": content,
            "is_challenge": is_challenge,
            "is_flagged": is_flagged,
            "metadata": metadata,
        })

    async def save_report(
        self,
        *,
        incident_id: str,
        report_markdown: str,
        severity: str,
        root_cause: str,
        blast_radius: str,
        timeline: list[dict] | None = None,
        immediate_fixes: list[str] | None = None,
        longterm_fixes: list[str] | None = None,
        agent_debate: list[dict] | None = None,
    ) -> dict:
        return await self.upsert(
            "incident_reports",
            {
                "incident_id": incident_id,
                "report_markdown": report_markdown,
                "severity": severity,
                "root_cause": root_cause,
                "blast_radius": blast_radius,
                "timeline": timeline,
                "immediate_fixes": immediate_fixes,
                "longterm_fixes": longterm_fixes,
                "agent_debate": agent_debate,
            },
            on_conflict="incident_id",
        )

    async def append_living_doc(
        self,
        *,
        incident_id: str,
        title: str,
        content_markdown: str,
        tags: list[str],
        severity: str,
        attack_type: str,
    ):
        return await self.insert("living_docs", {
            "incident_id": incident_id,
            "title": title,
            "content_markdown": content_markdown,
            "tags": tags,
            "severity": severity,
            "attack_type": attack_type,
        })

    async def update_incident(self, *, incident_id: str, patch: dict):
        return await self.update("incidents", match={"id": incident_id}, patch=patch)
