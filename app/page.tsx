import { redirect } from "next/navigation";

// Root → redirect to dashboard once auth/dashboard is built by teammates
// For now, show a minimal placeholder so the app boots.
export default function Home() {
  // Uncomment when dashboard is ready:
  // redirect("/dashboard");

  return (
    <main className="flex min-h-screen items-center justify-center">
      <div className="text-center space-y-4">
        <h1 className="text-3xl font-bold text-green-400 tracking-widest">
          SENTINEL<span className="text-white">AI</span>
        </h1>
        <p className="text-slate-400 text-sm">
          Autonomous Cloud Security Investigation Platform
        </p>
        <p className="text-slate-600 text-xs">
          Agent layer ready. Awaiting dashboard integration.
        </p>
      </div>
    </main>
  );
}
