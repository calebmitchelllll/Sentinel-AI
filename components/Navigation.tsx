"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { Session } from "@supabase/supabase-js";

const LINKS = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/docs", label: "Living Docs" },
  { href: "/benchmarks", label: "Agent Benchmarks" },
];

export default function Navigation({ session }: { session: Session | null }) {
  const pathname = usePathname();
  if (pathname?.startsWith("/auth")) return null;

  return (
    <nav className="border-b border-line bg-bg-elev/70 backdrop-blur sticky top-0 z-30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center h-14">
        <Link href="/dashboard" className="flex items-center gap-2">
          <div className="w-2.5 h-2.5 rounded-full bg-agent-remediation glow-green animate-pulse-slow" />
          <span className="font-mono font-bold text-lg tracking-tight">
            sentinel<span className="text-agent-detective">AI</span>
          </span>
          <span className="text-ink-faint font-mono text-xs ml-1 hidden sm:inline">
            // NemoClaw + Nemotron
          </span>
        </Link>

        <div className="flex-1 flex items-center gap-1 ml-8">
          {LINKS.map((l) => {
            const active = pathname?.startsWith(l.href);
            return (
              <Link
                key={l.href}
                href={l.href}
                className={`px-3 py-1.5 text-sm font-mono rounded transition ${
                  active
                    ? "bg-bg-panel text-ink border border-line"
                    : "text-ink-dim hover:text-ink hover:bg-bg-panel"
                }`}
              >
                {l.label}
              </Link>
            );
          })}
        </div>

        {session?.user ? (
          <div className="flex items-center gap-3">
            <span className="hidden md:inline text-xs font-mono text-ink-dim">
              {session.user.email}
            </span>
            <form action="/api/auth/signout" method="post">
              <button
                type="submit"
                className="text-xs font-mono px-2 py-1 border border-line rounded text-ink-dim hover:text-sev-crit hover:border-sev-crit/50"
              >
                logout
              </button>
            </form>
          </div>
        ) : null}
      </div>
    </nav>
  );
}
