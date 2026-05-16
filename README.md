# SentinelAI

Multi-agent cloud security investigation platform. Six cooperating agents
(Detective, Forensics, Remediation, Validator, Reporter, MetaSecurity) ingest
AWS CloudTrail logs, debate findings, and produce a structured incident
report. Powered by **NVIDIA Nemotron** running via **NemoClaw** sandboxing.

```
┌─────────────────┐    SSE     ┌──────────────────────────────┐    Nemotron NIM
│  Next.js 14 UI  │ ←────────→ │  Python orchestrator         │ ←─────────────→  build.nvidia.com
│  (Tailwind)     │            │  (FastAPI, NemoClaw sandbox) │
└─────────────────┘            └──────────────────────────────┘
        │                                  │
        └─────── Supabase (auth + realtime + persistence) ───────┘
```

---

## What you need before running

1. **Supabase project** — free tier is fine. From <https://supabase.com>, create a new project, then grab from **Project Settings → API**:
   - `URL` → `NEXT_PUBLIC_SUPABASE_URL`
   - `anon public` key → `NEXT_PUBLIC_SUPABASE_ANON_KEY`
   - `service_role` key → `SUPABASE_SERVICE_ROLE_KEY` (keep this secret)

2. **NVIDIA API key** — from <https://build.nvidia.com> (sign in, click any Nemotron model, "Get API Key"). Use it for `NVIDIA_API_KEY` and/or `NEMOCLAW_API_KEY`.

3. **Docker + docker-compose** installed locally (or use Brev — see bottom).

---

## Run it locally (docker-compose)

### 1. Clone + env

```bash
git clone <this repo>
cd Sentinel-AI
cp .env.example .env
# fill in: NVIDIA_API_KEY, NEXT_PUBLIC_SUPABASE_URL, NEXT_PUBLIC_SUPABASE_ANON_KEY,
# SUPABASE_SERVICE_ROLE_KEY, NEXTAUTH_SECRET (any long random string)
```

### 2. Apply the Supabase schema

In the Supabase dashboard, open **SQL Editor → New query**, paste the entire contents of `supabase/migrations/001_initial.sql`, and click **Run**.

This creates the 5 tables (`incidents`, `agent_messages`, `incident_reports`, `agent_benchmarks`, `living_docs`), enables RLS, seeds the 6 agent benchmark rows, and adds them to the realtime publication.

### 3. Configure Supabase auth

In the Supabase dashboard, **Authentication → Providers → Email**:

- Enable email provider.
- For local demo, disable "Confirm email" so accounts work instantly without an SMTP setup. (Re-enable for production.)

### 4. Build and start the stack

```bash
docker compose up --build
```

Two services come up:

| service     | port  | what                                              |
| ----------- | ----- | ------------------------------------------------- |
| `nemoclaw`  | 8000  | Python FastAPI orchestrator (calls Nemotron NIM)  |
| `web`       | 3000  | Next.js 14 frontend + API routes                  |

Open **<http://localhost:3000>**, sign up, then click **▶ Trigger demo incident** on the dashboard.

---

## What the demo shows

1. Click **Trigger demo incident** → a new `incidents` row is created in Supabase, status: `investigating`.
2. The frontend opens an SSE stream to `/api/agents`, which proxies to the Python orchestrator.
3. The 6-agent pipeline runs:
   - **Detective** ingests `/data/cloudtrail-demo.json`, flags anomalies, maps the attack path.
   - **Validator** challenges Detective, demands evidence.
   - **Forensics** traces credential usage and assesses data exposure.
   - **Validator** challenges Forensics.
   - **Remediation** proposes immediate + long-term fixes (each validated).
   - **Reporter** generates the final structured markdown report (token-streamed).
   - **MetaSecurity** runs after every other agent, flagging prompt-injection / scope violations.
4. Every message is persisted to `agent_messages` and rendered live in the AgentChat.
5. The final report is written to `incident_reports` and auto-appended to `living_docs`.
6. Agent benchmark rows update live via Supabase realtime — visible at `/benchmarks` and the dashboard sidebar.

---

## The attack scenario (built into `data/cloudtrail-demo.json`)

- **Days 1–6**: 30+ baseline developer events from internal IPs (`10.0.x.x`).
- **Day 7, 09:14 UTC**: `GetCallerIdentity` from **185.220.101.47** (Tor exit) — recon.
- **Day 7, 09:15 UTC**: `ListAttachedUserPolicies` — attacker enumerates own privs.
- **Day 7, 09:17 UTC**: **`AttachUserPolicy`** with `arn:aws:iam::aws:policy/AdministratorAccess` on dev-alice — privilege escalation.
- **Day 7, 09:21–09:25 UTC**: `ListBuckets` → `ListObjectsV2 sensitive-data/` → **`GetObject sensitive-data/employees.csv`** → `GetObject sensitive-data/payroll-2026Q1.xlsx` — exfiltration.

---

## Project layout

```
/app
  /auth/{signin,signup}/page.tsx
  /dashboard/page.tsx
  /incident/[id]/page.tsx
  /docs/page.tsx
  /benchmarks/page.tsx
  /api/{trigger,agents,report,monitor}/route.ts
/components
  AgentChat.tsx        ← live SSE consumer
  IncidentReport.tsx   ← final report view + markdown/PDF export
  AgentBenchmark.tsx   ← live benchmark table
  AttackTimeline.tsx   ← visual chronological timeline
  LiveDocumentation.tsx← searchable docs with cross-incident patterns
  Navigation.tsx, SeverityBadge.tsx, TriggerIncidentButton.tsx, DashboardClient.tsx
/lib
  supabase-server.ts, supabase-client.ts   ← Supabase clients (server + browser)
  nemoclaw.ts                               ← TS contract for the Python service
  /agents/{detective,forensics,remediation,validator,reporter,metaAgent}.ts
  types.ts
/services                                   ← Python NemoClaw-sandboxed orchestrator
  nemoclaw_runner.py    ← FastAPI entrypoint
  orchestrator.py       ← multi-agent pipeline
  agents.py             ← agent definitions + system prompts
  tools.py              ← tool implementations + NIM tool schemas
  nemotron_client.py    ← NVIDIA NIM client (chat + streaming)
  supabase_writer.py    ← service-role writes to Supabase REST
  nemoclaw.config.yaml  ← real NemoClaw sandbox config
  Dockerfile, requirements.txt
/supabase/migrations/001_initial.sql        ← apply in Supabase SQL editor
/data/cloudtrail-demo.json                  ← the synthetic attack dataset
docker-compose.yml, Dockerfile.next, brev.yaml, middleware.ts
```

---

## Running on NVIDIA Brev

The repo ships a `brev.yaml`. To deploy:

```bash
# 1. one-time
brev create sentinelai --gpu A10G
brev open sentinelai

# 2. push secrets (read from your local .env)
brev secret set NVIDIA_API_KEY=$(grep ^NVIDIA_API_KEY .env | cut -d= -f2)
brev secret set NEXT_PUBLIC_SUPABASE_URL=$(grep ^NEXT_PUBLIC_SUPABASE_URL .env | cut -d= -f2)
brev secret set NEXT_PUBLIC_SUPABASE_ANON_KEY=$(grep ^NEXT_PUBLIC_SUPABASE_ANON_KEY .env | cut -d= -f2)
brev secret set SUPABASE_SERVICE_ROLE_KEY=$(grep ^SUPABASE_SERVICE_ROLE_KEY .env | cut -d= -f2)
brev secret set NEXTAUTH_SECRET=$(grep ^NEXTAUTH_SECRET .env | cut -d= -f2)

# 3. start (runs `docker compose up --build` on the Brev box)
brev exec -- docker compose up --build
```

To run **inside the real NemoClaw sandbox** on Brev (the most defensible "we used NemoClaw" story for the hackathon judges):

```bash
brev exec -- bash -c '
  curl -fsSL https://www.nvidia.com/nemoclaw.sh | \
    NEMOCLAW_NON_INTERACTIVE=1 NEMOCLAW_ACCEPT_THIRD_PARTY_SOFTWARE=1 bash
  nemoclaw sentinelai connect --config services/nemoclaw.config.yaml
  docker compose up --build web
'
```

That config (`services/nemoclaw.config.yaml`) tells NemoClaw to run the Python orchestrator inside OpenShell with Landlock + seccomp + namespaced networking that only allows egress to `integrate.api.nvidia.com` and `*.supabase.co`.

---

## Honest notes on NemoClaw

- **NemoClaw is real** — NVIDIA open-sourced it in March 2026 at <https://github.com/NVIDIA/NemoClaw>.
- It is primarily a **CLI sandboxing tool** for running OpenClaw assistants inside the NVIDIA OpenShell runtime with Linux isolation primitives (Landlock, seccomp, namespaces). It is **not** itself a Python multi-agent orchestration library — there is no `from nemoclaw import NemoClaw, Agent, Tool` class API in the published package.
- This project therefore **uses NemoClaw for what it actually does** (sandbox the orchestrator service) and implements the 6-agent debate / pipeline in `/services/orchestrator.py` directly against the Nemotron NIM API (`integrate.api.nvidia.com`), which is exactly the inference path NemoClaw uses under the hood.
- The `services/nemoclaw.config.yaml` is a real config file you can `nemoclaw … connect` to. Without NemoClaw installed, the Python service still runs identically via docker-compose — the sandboxing simply isn't applied.

---

## Troubleshooting

| symptom                                          | fix                                                                                          |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| `agents stream failed: 502`                      | The Python service didn't start or crashed. `docker compose logs nemoclaw` to see the error. |
| `agents stream failed: 503 No NVIDIA_API_KEY`    | Set `NVIDIA_API_KEY` (or `NEMOCLAW_API_KEY`) in `.env` and rebuild.                          |
| Sign-up succeeds but redirect loops to /signin   | "Confirm email" is still enabled in Supabase. Disable it, or click the confirm link.         |
| Realtime updates not appearing                   | Re-run the migration — the `alter publication supabase_realtime add table …` lines matter.   |
| `Permission denied` errors when inserting rows   | RLS is on. The Python service uses the **service role** key; check `SUPABASE_SERVICE_ROLE_KEY`. |
| Reporter writes a report but sections are empty  | Nemotron skipped the `## Section` heading. Re-run; for production, switch to a JSON-mode call. |

---

## Demo script (90 seconds)

1. Open `localhost:3000` → sign in.
2. Dashboard: point out the empty incident feed + the 6 agents in the sidebar all marked `healthy`.
3. Click **▶ Trigger demo incident** → land on `/incident/<uuid>`.
4. Watch the agents stream in order: Detective → Validator (challenge) → Forensics → Validator (challenge) → Remediation → Reporter.
5. When the report appears, scroll: severity badge, visual attack timeline, root cause, blast radius, immediate + long-term fix checklists, agent debate summary, full markdown.
6. Click **↓ markdown** to prove the report exports.
7. Go to `/docs` — the new incident appears in living documentation with cross-incident tags.
8. Go to `/benchmarks` — MetaSecurity has incremented `tasks_completed` for every agent. Refresh the dashboard to watch it update live.
