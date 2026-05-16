from typing import Any, Optional
from pydantic import BaseModel, Field


class RunAgentsRequest(BaseModel):
    incidentId: str
    logs: list[dict[str, Any]]
    meta: Optional[dict[str, Any]] = None


class StreamEvent(BaseModel):
    event: str
    data: dict[str, Any]


class AgentTurnResult(BaseModel):
    agent: str
    content: str
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    is_challenge: bool = False
    is_flagged: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class FinalReport(BaseModel):
    executive_summary: str
    severity: str
    root_cause: str
    blast_radius: str
    timeline: list[dict[str, Any]]
    immediate_fixes: list[str]
    longterm_fixes: list[str]
    agent_debate: list[dict[str, Any]]
    markdown: str
