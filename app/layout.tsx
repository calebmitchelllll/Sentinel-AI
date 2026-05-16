import type { Metadata } from "next";
import "./globals.css";
import Navigation from "@/components/Navigation";
import { getSession } from "@/lib/supabase-server";

export const metadata: Metadata = {
  title: "SentinelAI — Multi-Agent Cloud Security Investigation",
  description:
    "Autonomous multi-agent system for cloud security incident investigation, powered by NVIDIA Nemotron and NemoClaw.",
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const session = await getSession();

  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-bg text-ink antialiased scanline">
        <Navigation session={session} />
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">{children}</main>
      </body>
    </html>
  );
}
