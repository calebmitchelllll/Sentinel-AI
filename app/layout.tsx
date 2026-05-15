import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SentinelAI — Cloud Security Investigation Platform",
  description: "Autonomous multi-agent AWS security incident investigation",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-sentinel-bg text-slate-200 font-mono antialiased">
        {children}
      </body>
    </html>
  );
}
