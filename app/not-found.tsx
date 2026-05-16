import Link from "next/link";

export default function NotFound() {
  return (
    <div className="min-h-[60vh] flex flex-col items-center justify-center gap-4">
      <div className="font-mono text-ink-dim text-sm">404</div>
      <h2 className="text-xl font-bold">Page not found</h2>
      <Link
        href="/dashboard"
        className="font-mono px-4 py-2 bg-bg-panel border border-line rounded hover:border-agent-detective transition text-sm"
      >
        Back to dashboard
      </Link>
    </div>
  );
}
