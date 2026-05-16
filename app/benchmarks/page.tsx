import { requireSession, createSupabaseServerClient } from "@/lib/supabase-server";
import AgentBenchmarkTable from "@/components/AgentBenchmark";

export const dynamic = "force-dynamic";

export default async function BenchmarksPage() {
  await requireSession();
  const supabase = createSupabaseServerClient();

  const { data } = await supabase
    .from("agent_benchmarks")
    .select("*")
    .order("agent_name");

  return (
    <div className="space-y-5">
      <header>
        <div className="font-mono text-xs text-ink-faint">// meta-oversight</div>
        <h1 className="text-2xl font-bold mt-1">Agent Benchmarks</h1>
        <p className="text-ink-dim text-sm mt-1">
          MetaSecurity tracks every other agent. Live updates via Supabase realtime.
        </p>
      </header>
      <AgentBenchmarkTable initial={(data as any) || []} />
    </div>
  );
}
