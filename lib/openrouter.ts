// When BREV_NIM_URL is set, calls go to the local Nemotron NIM running on the Brev GPU.
// Otherwise falls back to OpenRouter (for local dev / non-Brev environments).
// Both use the OpenAI-compatible chat completions API — no other code changes needed.
const OPENROUTER_BASE = "https://openrouter.ai/api/v1/chat/completions";
export const NEMOTRON_MODEL = "nvidia/llama-3.1-nemotron-70b-instruct";

function inferenceURL(): string {
  return process.env.BREV_NIM_URL
    ? `${process.env.BREV_NIM_URL}/v1/chat/completions`
    : OPENROUTER_BASE;
}

function isLocalNIM(): boolean {
  return !!process.env.BREV_NIM_URL;
}

export interface Message {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface CallOptions {
  messages: Message[];
  temperature?: number;
  maxTokens?: number;
  stream?: boolean;
}

function headers() {
  if (isLocalNIM()) {
    // NIM on Brev doesn't need an auth header — it's local
    return { "Content-Type": "application/json" };
  }
  return {
    Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`,
    "Content-Type": "application/json",
    "HTTP-Referer": process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000",
    "X-Title": "SentinelAI",
  };
}

// NIM uses "meta/llama-3.1-70b-nemotron" as the model string locally;
// OpenRouter uses the full namespaced form. This picks the right one.
function modelName(): string {
  return isLocalNIM() ? "meta/llama-3.1-70b-nemotron" : NEMOTRON_MODEL;
}

export async function callNemotron(opts: CallOptions): Promise<string> {
  if (process.env.MOCK_AGENTS === "true") {
    return getMockResponse(opts.messages);
  }

  const res = await fetch(inferenceURL(), {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({
      model: modelName(),
      messages: opts.messages,
      temperature: opts.temperature ?? 0.2,
      max_tokens: opts.maxTokens ?? 2048,
      stream: false,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${isLocalNIM() ? "NIM" : "OpenRouter"} ${res.status}: ${body}`);
  }

  const data = await res.json();
  return data.choices[0].message.content as string;
}

export async function streamNemotron(
  opts: CallOptions,
  onChunk: (text: string) => void
): Promise<string> {
  if (process.env.MOCK_AGENTS === "true") {
    const mock = getMockResponse(opts.messages);
    onChunk(mock);
    return mock;
  }

  const res = await fetch(inferenceURL(), {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({
      model: modelName(),
      messages: opts.messages,
      temperature: opts.temperature ?? 0.2,
      max_tokens: opts.maxTokens ?? 2048,
      stream: true,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${isLocalNIM() ? "NIM" : "OpenRouter"} ${res.status}: ${body}`);
  }

  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let full = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    for (const line of decoder.decode(value).split("\n")) {
      if (!line.startsWith("data: ")) continue;
      const payload = line.slice(6);
      if (payload === "[DONE]") continue;

      try {
        const delta = JSON.parse(payload)?.choices?.[0]?.delta?.content ?? "";
        if (delta) {
          full += delta;
          onChunk(delta);
        }
      } catch {
        // malformed SSE chunk — skip
      }
    }
  }

  return full;
}

// Lightweight mock responses so the UI works without an API key during dev
function getMockResponse(messages: Message[]): string {
  const systemRole = messages.find((m) => m.role === "system")?.content ?? "";

  if (systemRole.includes("Detective")) {
    return JSON.stringify({
      anomalies: [
        {
          eventId: "a7t4ck00-0007-4bb2-c222-222222222001",
          eventName: "GetCallerIdentity",
          timestamp: "2024-01-07T08:12:03Z",
          severity: "HIGH",
          description: "Identity recon from known Tor exit node 185.220.101.47 — never seen in 6-day baseline",
          evidence: ["sourceIPAddress: 185.220.101.47", "userAgent: Linux/kali — deviates from baseline macOS"],
        },
        {
          eventId: "a7t4ck00-0007-4bb2-c222-222222222004",
          eventName: "AttachUserPolicy",
          timestamp: "2024-01-07T08:15:47Z",
          severity: "CRITICAL",
          description: "Privilege escalation: AdministratorAccess attached to dev-john from suspicious IP",
          evidence: ["policyArn: arn:aws:iam::aws:policy/AdministratorAccess", "sourceIPAddress: 185.220.101.47"],
        },
        {
          eventId: "a7t4ck00-0007-4bb2-c222-222222222008",
          eventName: "GetObject",
          timestamp: "2024-01-07T08:21:08Z",
          severity: "CRITICAL",
          description: "1.8 MB download of hr/employees.csv from private sensitive-data bucket",
          evidence: ["bytesTransferredOut: 1843200", "bucket: acme-corp-sensitive-data"],
        },
      ],
      attackPath: [
        { step: 1, timestamp: "2024-01-07T08:12:03Z", action: "Identity recon", actor: "dev-john (stolen key)", target: "AWS STS", sourceIp: "185.220.101.47", significance: "Attacker confirms key is valid" },
        { step: 2, timestamp: "2024-01-07T08:14:58Z", action: "IAM enumeration", actor: "dev-john (stolen key)", target: "IAM", sourceIp: "185.220.101.47", significance: "Attacker maps existing permissions" },
        { step: 3, timestamp: "2024-01-07T08:15:47Z", action: "Privilege escalation", actor: "dev-john (stolen key)", target: "IAM Policy", sourceIp: "185.220.101.47", significance: "CRITICAL — dev user now has full admin access" },
        { step: 4, timestamp: "2024-01-07T08:19:15Z", action: "Bucket discovery", actor: "dev-john (stolen key)", target: "S3", sourceIp: "185.220.101.47", significance: "Attacker surveys all accessible buckets" },
        { step: 5, timestamp: "2024-01-07T08:21:08Z", action: "Data exfiltration", actor: "dev-john (stolen key)", target: "acme-corp-sensitive-data/hr/employees.csv", sourceIp: "185.220.101.47", significance: "PII data downloaded" },
        { step: 6, timestamp: "2024-01-07T08:23:11Z", action: "Cover tracks (failed)", actor: "dev-john (stolen key)", target: "CloudTrail", sourceIp: "185.220.101.47", significance: "DeleteTrail blocked by SCP — attacker detected" },
      ],
      overallSeverity: "CRITICAL",
      suspiciousIPs: ["185.220.101.47"],
      compromisedCredentials: ["AKIAIOSFODNN7EXAMPLE"],
      summary: "Compromised developer credential used from Tor exit node to escalate to admin, exfiltrate HR and finance data, then attempt to delete audit trail.",
    });
  }

  return JSON.stringify({ result: "mock response", status: "ok" });
}
