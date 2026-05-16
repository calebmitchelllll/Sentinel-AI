"use client";

import { useEffect } from "react";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <div className="min-h-[60vh] flex flex-col items-center justify-center gap-4">
      <div className="font-mono text-sev-crit text-sm">ERROR</div>
      <h2 className="text-xl font-bold">{error.message || "Something went wrong"}</h2>
      <button
        onClick={reset}
        className="font-mono px-4 py-2 bg-bg-panel border border-line rounded hover:border-agent-detective transition text-sm"
      >
        Try again
      </button>
    </div>
  );
}
