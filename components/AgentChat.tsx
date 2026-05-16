"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { AGENT_COLORS, type AgentName, type StreamEvent } from "@/lib/types";

type Bubble = {
  id: string;
  agent: AgentName | "System";
  role?: string;
  content: string;
  is_challenge: boolean;
  is_flagged: boolean;
  done: boolean;
  startedAt: number;
};

type Flag = { id: string; from: string; target: string; reason: string; at: number };

export default function AgentChat({ incidentId, autostart = true }: { incidentId: string; autostart?: boolean }) {
  const router = useRouter();
  const [bubbles, setBubbles] = useState<Bubble[]>([]);
  const [flags, setFlags] = useState<Flag[]>([]);
  const [status, setStatus] = useState<"idle" | "running" | "done" | "error">("idle");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const startedRef = useRef(false);
  const scrollRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!autostart || startedRef.current) return;
    startedRef.current = true;
    run();
    return () => {
      // best-effort; the fetch aborts when the page unmounts via abort controller below
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autostart, incidentId]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [bubbles, flags]);

  async function run() {
    setStatus("running");
    setErrorMsg(null);
    const controller = new AbortController();
    try {
      const res = await fetch("/api/agents", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ incidentId }),
        signal: controller.signal,
      });
      if (!res.ok || !res.body) {
        const txt = await res.text().catch(() => "");
        throw new Error(`agents stream failed: ${res.status} ${txt}`);
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });

        // Split SSE frames (\n\n delimited)
        const frames = buf.split("\n\n");
        buf = frames.pop() || "";

        for (const frame of frames) {
          const evt = parseSSE(frame);
          if (evt) handleEvent(evt);
        }
      }
      setStatus("done");
    } catch (e: any) {
      setStatus("error");
      setErrorMsg(e?.message || "stream error");
    }
  }

  function handleEvent(evt: StreamEvent) {
    switch (evt.event) {
      case "pipeline_start":
        setBubbles((b) => [
          ...b,
          mkBubble("System", "orchestrator", "Pipeline initialised. Spinning up 6 agents.", true),
        ]);
        break;
      case "agent_start": {
        const agent = evt.data.agent as AgentName;
        setBubbles((b) => [
          ...b,
          {
            id: crypto.randomUUID(),
            agent,
            role: evt.data.role,
            content: "",
            is_challenge: !!evt.data.is_challenge,
            is_flagged: false,
            done: false,
            startedAt: Date.now(),
          },
        ]);
        break;
      }
      case "token": {
        const agent = evt.data.agent as AgentName;
        const token = evt.data.token as string;
        setBubbles((b) => {
          // append to the most recent non-done bubble for this agent
          for (let i = b.length - 1; i >= 0; i--) {
            if (b[i].agent === agent && !b[i].done) {
              const copy = b.slice();
              copy[i] = { ...copy[i], content: copy[i].content + token };
              return copy;
            }
          }
          return b;
        });
        break;
      }
      case "agent_end": {
        const agent = evt.data.agent as AgentName;
        setBubbles((b) => {
          for (let i = b.length - 1; i >= 0; i--) {
            if (b[i].agent === agent && !b[i].done) {
              const copy = b.slice();
              copy[i] = {
                ...copy[i],
                content: evt.data.content || copy[i].content,
                is_flagged: !!evt.data.is_flagged,
                done: true,
              };
              return copy;
            }
          }
          return b;
        });
        break;
      }
      case "flag":
        setFlags((f) => [
          ...f,
          {
            id: crypto.randomUUID(),
            from: evt.data.from,
            target: evt.data.target,
            reason: evt.data.reason,
            at: Date.now(),
          },
        ]);
        break;
      case "report_ready":
        setBubbles((b) => [
          ...b,
          mkBubble("System", "orchestrator", `Report generated (severity: ${evt.data.severity}).`, true),
        ]);
        break;
      case "done":
        setStatus("done");
        // Refresh the server component so the structured IncidentReport view
        // replaces the AgentChat (it queries incident_reports on render).
        setTimeout(() => router.refresh(), 1200);
        break;
      case "error":
        setStatus("error");
        setErrorMsg(evt.data.message || "unknown");
        break;
    }
  }

  return (
    <div className="flex flex-col h-[70vh] bg-bg-panel border border-line rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 border-b border-line bg-bg-elev/60">
        <div className="flex items-center gap-2 font-mono text-sm">
          <StatusDot status={status} />
          <span className="text-ink-dim">incident://</span>
          <span className="text-ink">{incidentId.slice(0, 8)}</span>
        </div>
        <div className="text-xs font-mono text-ink-faint">{flags.length > 0 ? `${flags.length} meta-flag${flags.length === 1 ? "" : "s"}` : "no flags"}</div>
      </div>

      <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-3 terminal">
        {bubbles.length === 0 && status === "idle" && (
          <div className="text-ink-dim text-sm">Waiting to start…</div>
        )}
        {bubbles.map((b) => (
          <BubbleView key={b.id} bubble={b} />
        ))}
        {flags.map((f) => (
          <FlagView key={f.id} flag={f} />
        ))}
        {errorMsg && (
          <div className="border border-sev-crit/40 bg-sev-crit/10 rounded p-3 text-sev-crit font-mono text-sm">
            error: {errorMsg}
          </div>
        )}
      </div>
    </div>
  );
}

function mkBubble(
  agent: AgentName | "System",
  role: string,
  content: string,
  done: boolean
): Bubble {
  return {
    id: crypto.randomUUID(),
    agent,
    role,
    content,
    is_challenge: false,
    is_flagged: false,
    done,
    startedAt: Date.now(),
  };
}

function StatusDot({ status }: { status: "idle" | "running" | "done" | "error" }) {
  const color =
    status === "running"
      ? "bg-sev-warn animate-pulse-slow"
      : status === "done"
      ? "bg-sev-ok"
      : status === "error"
      ? "bg-sev-crit"
      : "bg-ink-faint";
  return <span className={`w-2 h-2 rounded-full ${color}`} />;
}

function BubbleView({ bubble }: { bubble: Bubble }) {
  const isSystem = bubble.agent === "System";
  const color = isSystem ? "#8b9bb4" : AGENT_COLORS[bubble.agent as AgentName] || "#8b9bb4";
  const borderClass = bubble.is_flagged
    ? "border-sev-crit"
    : bubble.is_challenge
    ? "border-agent-validator"
    : "border-line";

  return (
    <div className={`border ${borderClass} rounded-lg p-3 bg-bg-elev/60`}>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2 text-xs font-mono">
          <span
            className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-bold"
            style={{ color, backgroundColor: color + "18", border: `1px solid ${color}55` }}
          >
            <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: color }} />
            {bubble.agent}
          </span>
          {bubble.role && <span className="text-ink-faint">{bubble.role}</span>}
          {bubble.is_challenge && (
            <span className="text-agent-validator border border-agent-validator/40 px-1.5 rounded text-[10px]">
              CHALLENGE
            </span>
          )}
          {bubble.is_flagged && (
            <span className="text-sev-crit border border-sev-crit/40 px-1.5 rounded text-[10px]">
              FLAGGED
            </span>
          )}
        </div>
        <span className="text-ink-faint text-[10px] font-mono">
          {new Date(bubble.startedAt).toLocaleTimeString()}
        </span>
      </div>
      <div className="whitespace-pre-wrap break-words text-ink leading-relaxed">
        {bubble.content}
        {!bubble.done && <span className="inline-block w-2 h-4 bg-ink ml-0.5 align-middle animate-blink" />}
      </div>
    </div>
  );
}

function FlagView({ flag }: { flag: Flag }) {
  return (
    <div className="border border-sev-crit/60 bg-sev-crit/10 rounded-lg p-3 glow-red">
      <div className="flex items-center gap-2 text-xs font-mono text-sev-crit">
        <span className="text-base">⚠</span>
        <span className="font-bold">META-FLAG</span>
        <span className="text-ink-dim">from {flag.from} → target {flag.target}</span>
        <span className="text-ink-faint ml-auto">{new Date(flag.at).toLocaleTimeString()}</span>
      </div>
      <div className="mt-1 text-ink text-sm font-mono">{flag.reason}</div>
    </div>
  );
}

function parseSSE(frame: string): StreamEvent | null {
  let event = "";
  let data = "";
  for (const line of frame.split("\n")) {
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) data += line.slice(5).trim();
  }
  if (!event) return null;
  try {
    return { event: event as StreamEvent["event"], data: data ? JSON.parse(data) : {} };
  } catch {
    return { event: event as StreamEvent["event"], data: { raw: data } };
  }
}
