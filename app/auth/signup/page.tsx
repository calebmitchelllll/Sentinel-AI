"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { createSupabaseBrowserClient } from "@/lib/supabase-client";

export default function SignUpPage() {
  const router = useRouter();
  const supabase = createSupabaseBrowserClient();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setInfo(null);
    const { data, error } = await supabase.auth.signUp({ email, password });
    setLoading(false);
    if (error) return setError(error.message);

    if (data.session) {
      router.push("/dashboard");
      router.refresh();
    } else {
      setInfo("Account created. Check your email to confirm, then sign in.");
    }
  }

  return (
    <div className="min-h-[80vh] flex items-center justify-center">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-md bg-bg-panel border border-line rounded-lg p-8 space-y-5 glow-green"
      >
        <div>
          <div className="font-mono text-agent-remediation text-sm">$ sentinelai register --</div>
          <h1 className="text-2xl font-bold mt-2">Create operator account</h1>
        </div>

        <label className="block">
          <span className="text-xs text-ink-dim font-mono">EMAIL</span>
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1 w-full bg-bg-elev border border-line rounded px-3 py-2 font-mono text-sm focus:outline-none focus:border-agent-remediation"
          />
        </label>

        <label className="block">
          <span className="text-xs text-ink-dim font-mono">PASSWORD</span>
          <input
            type="password"
            required
            minLength={6}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 w-full bg-bg-elev border border-line rounded px-3 py-2 font-mono text-sm focus:outline-none focus:border-agent-remediation"
          />
        </label>

        {error && (
          <div className="text-sev-crit text-sm font-mono border border-sev-crit/30 bg-sev-crit/10 rounded p-2">
            {error}
          </div>
        )}
        {info && (
          <div className="text-sev-info text-sm font-mono border border-sev-info/30 bg-sev-info/10 rounded p-2">
            {info}
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-agent-remediation/20 hover:bg-agent-remediation/30 border border-agent-remediation text-agent-remediation font-mono py-2 rounded transition disabled:opacity-50"
        >
          {loading ? "creating…" : "Create account"}
        </button>

        <div className="text-xs text-ink-dim text-center">
          Already have one?{" "}
          <Link href="/auth/signin" className="text-agent-reporter underline">
            Sign in
          </Link>
        </div>
      </form>
    </div>
  );
}
