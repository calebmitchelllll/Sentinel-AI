import { requireSession, createSupabaseServerClient } from "@/lib/supabase-server";
import LiveDocumentation from "@/components/LiveDocumentation";

export const dynamic = "force-dynamic";

export default async function DocsPage() {
  await requireSession();
  const supabase = createSupabaseServerClient();

  const { data: docs } = await supabase
    .from("living_docs")
    .select("*")
    .order("created_at", { ascending: false })
    .limit(200);

  return (
    <div className="space-y-5">
      <header>
        <div className="font-mono text-xs text-ink-faint">// auto-updating runbook</div>
        <h1 className="text-2xl font-bold mt-1">Living Documentation</h1>
        <p className="text-ink-dim text-sm mt-1">
          Every resolved incident is auto-appended here by the Reporter agent. Searchable, taggable,
          cross-referenced.
        </p>
      </header>
      <LiveDocumentation docs={(docs as any) || []} />
    </div>
  );
}
