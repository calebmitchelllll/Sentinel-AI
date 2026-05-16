import { requireSession, createSupabaseServerClient } from "@/lib/supabase-server";
import DashboardClient from "@/components/DashboardClient";

export const dynamic = "force-dynamic";

export default async function DashboardPage() {
  await requireSession();
  const supabase = createSupabaseServerClient();

  const [{ data: incidents }, { data: benchmarks }] = await Promise.all([
    supabase
      .from("incidents")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(30),
    supabase.from("agent_benchmarks").select("*").order("agent_name"),
  ]);

  return (
    <DashboardClient
      initialIncidents={(incidents as any) || []}
      initialBenchmarks={(benchmarks as any) || []}
    />
  );
}
