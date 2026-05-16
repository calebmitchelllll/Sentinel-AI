"use client";

import { useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { createSupabaseBrowserClient } from "@/lib/supabase-client";

export default function SignInPage() {
  const router = useRouter();
  const params = useSearchParams();
  const supabase = createSupabaseBrowserClient();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    setLoading(false);
    if (error) return setError(error.message);
    router.push(params.get("redirectedFrom") || "/dashboard");
    router.refresh();
  }

  return (
    <div className="min-h-[80vh] flex items-center justify-center">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-md bg-bg-panel border border-line rounded-lg p-8 space-y-5 glow-blue"
      >
        <div>
          <div className="font-mono text-agent-detective text-sm">$ sentinelai login --</div>
          <h1 className="text-2xl font-bold mt-2">Authenticate</h1>
          <p className="text-ink-dim text-sm mt-1">Sign in to triage active incidents.</p>
        </div>

        <label className="block">
          <span className="text-xs text-ink-dim font-mono">EMAIL</span>
          <input
            type="email"
            required
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1 w-full bg-bg-elev border border-line rounded px-3 py-2 font-mono text-sm focus:outline-none focus:border-agent-detective"
          />
        </label>

        <label className="block">
          <span className="text-xs text-ink-dim font-mono">PASSWORD</span>
          <input
            type="password"
            required
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 w-full bg-bg-elev border border-line rounded px-3 py-2 font-mono text-sm focus:outline-none focus:border-agent-detective"
          />
        </label>

        {error && (
          <div className="text-sev-crit text-sm font-mono border border-sev-crit/30 bg-sev-crit/10 rounded p-2">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-agent-detective/20 hover:bg-agent-detective/30 border border-agent-detective text-agent-detective font-mono py-2 rounded transition disabled:opacity-50"
        >
          {loading ? "authenticating…" : "Sign in"}
        </button>

        <div className="text-xs text-ink-dim text-center">
          No account?{" "}
          <Link href="/auth/signup" className="text-agent-reporter underline">
            Create one
          </Link>
        </div>
      </form>
    </div>
  );
}
