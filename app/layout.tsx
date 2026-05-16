import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'SentinelAI — Cloud Security Investigation Platform',
  description: 'Multi-agent AI platform for AWS incident response and cloud security investigation.',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#0a0a0a] text-white min-h-screen antialiased">
        {children}
      </body>
    </html>
  )
}
