import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'SentinelAI — Cloud Security Investigation Platform',
  description: 'Multi-agent AI platform for AWS incident response and cloud security investigation.',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#050508] text-white min-h-screen antialiased relative overflow-x-hidden">
        {/* Ambient gradient blobs — fixed behind all content */}
        <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
          <div className="blob absolute -top-40 -right-40 w-[700px] h-[700px] rounded-full"
            style={{ background: 'radial-gradient(circle, rgba(217,70,239,0.18) 0%, transparent 65%)' }} />
          <div className="blob-2 absolute top-10 right-1/4 w-[500px] h-[500px] rounded-full"
            style={{ background: 'radial-gradient(circle, rgba(124,58,237,0.13) 0%, transparent 65%)' }} />
          <div className="blob-3 absolute top-1/3 -right-20 w-[450px] h-[450px] rounded-full"
            style={{ background: 'radial-gradient(circle, rgba(236,72,153,0.09) 0%, transparent 65%)' }} />
          <div className="blob absolute bottom-0 right-1/3 w-[350px] h-[350px] rounded-full"
            style={{ background: 'radial-gradient(circle, rgba(139,92,246,0.08) 0%, transparent 65%)' }} />
        </div>
        <div className="relative z-10">
          {children}
        </div>
      </body>
    </html>
  )
}
