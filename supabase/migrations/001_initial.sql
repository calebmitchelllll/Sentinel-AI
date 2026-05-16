-- SentinelAI initial schema
-- Run this in the Supabase SQL editor (Dashboard > SQL Editor > New query)

create extension if not exists "pgcrypto";

-- =========================
-- Incidents
-- =========================
create table if not exists public.incidents (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  severity text,
  status text not null default 'investigating',
  summary text,
  attack_type text,
  triggered_by uuid references auth.users(id) on delete set null
);

create index if not exists incidents_created_at_idx on public.incidents (created_at desc);
create index if not exists incidents_severity_idx on public.incidents (severity);

-- =========================
-- Agent messages (live conversation)
-- =========================
create table if not exists public.agent_messages (
  id uuid primary key default gen_random_uuid(),
  incident_id uuid not null references public.incidents(id) on delete cascade,
  agent_name text not null,
  role text,
  content text not null,
  timestamp timestamptz not null default now(),
  is_challenge boolean not null default false,
  is_flagged boolean not null default false,
  metadata jsonb
);

create index if not exists agent_messages_incident_idx on public.agent_messages (incident_id, timestamp);
create index if not exists agent_messages_agent_idx on public.agent_messages (agent_name);

-- =========================
-- Incident reports
-- =========================
create table if not exists public.incident_reports (
  id uuid primary key default gen_random_uuid(),
  incident_id uuid not null references public.incidents(id) on delete cascade,
  report_markdown text not null,
  severity text,
  root_cause text,
  blast_radius text,
  timeline jsonb,
  immediate_fixes jsonb,
  longterm_fixes jsonb,
  agent_debate jsonb,
  created_at timestamptz not null default now()
);

create index if not exists incident_reports_incident_idx on public.incident_reports (incident_id);
create unique index if not exists incident_reports_one_per_incident on public.incident_reports (incident_id);

-- =========================
-- Agent benchmarks
-- =========================
create table if not exists public.agent_benchmarks (
  id uuid primary key default gen_random_uuid(),
  agent_name text unique not null,
  tasks_completed int not null default 0,
  accuracy_score float not null default 1.0,
  times_challenged int not null default 0,
  times_overruled int not null default 0,
  jailbreak_attempts int not null default 0,
  health_status text not null default 'healthy',
  last_updated timestamptz not null default now()
);

-- Seed baseline rows for all 6 agents (idempotent)
insert into public.agent_benchmarks (agent_name, health_status)
values
  ('Detective',   'healthy'),
  ('Forensics',   'healthy'),
  ('Remediation', 'healthy'),
  ('Validator',   'healthy'),
  ('Reporter',    'healthy'),
  ('MetaSecurity','healthy')
on conflict (agent_name) do nothing;

-- =========================
-- Living documentation
-- =========================
create table if not exists public.living_docs (
  id uuid primary key default gen_random_uuid(),
  incident_id uuid references public.incidents(id) on delete set null,
  title text not null,
  content_markdown text not null,
  tags text[] not null default '{}',
  severity text,
  attack_type text,
  search_tsv tsvector generated always as (
    setweight(to_tsvector('english', coalesce(title, '')), 'A') ||
    setweight(to_tsvector('english', coalesce(content_markdown, '')), 'B') ||
    setweight(to_tsvector('english', coalesce(attack_type, '')), 'C')
  ) stored,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists living_docs_search_idx on public.living_docs using gin (search_tsv);
create index if not exists living_docs_tags_idx on public.living_docs using gin (tags);
create index if not exists living_docs_created_at_idx on public.living_docs (created_at desc);

-- =========================
-- RLS — authenticated users can read; only service role writes
-- =========================
alter table public.incidents          enable row level security;
alter table public.agent_messages     enable row level security;
alter table public.incident_reports   enable row level security;
alter table public.agent_benchmarks   enable row level security;
alter table public.living_docs        enable row level security;

-- Read policies (any authenticated user)
drop policy if exists "read incidents"          on public.incidents;
drop policy if exists "read agent_messages"     on public.agent_messages;
drop policy if exists "read incident_reports"   on public.incident_reports;
drop policy if exists "read agent_benchmarks"   on public.agent_benchmarks;
drop policy if exists "read living_docs"        on public.living_docs;

create policy "read incidents"          on public.incidents          for select to authenticated using (true);
create policy "read agent_messages"     on public.agent_messages     for select to authenticated using (true);
create policy "read incident_reports"   on public.incident_reports   for select to authenticated using (true);
create policy "read agent_benchmarks"   on public.agent_benchmarks   for select to authenticated using (true);
create policy "read living_docs"        on public.living_docs        for select to authenticated using (true);

-- Insert policy — allow authenticated users to trigger incidents
drop policy if exists "insert incidents" on public.incidents;
create policy "insert incidents" on public.incidents for insert to authenticated with check (true);

-- Realtime: enable publication for live UIs
do $$ begin
  if not exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    create publication supabase_realtime;
  end if;
end $$;

alter publication supabase_realtime add table public.incidents;
alter publication supabase_realtime add table public.agent_messages;
alter publication supabase_realtime add table public.incident_reports;
alter publication supabase_realtime add table public.agent_benchmarks;
alter publication supabase_realtime add table public.living_docs;
