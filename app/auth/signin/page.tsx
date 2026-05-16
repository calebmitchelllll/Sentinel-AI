'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { supabase } from '@/lib/supabase'

export default function SignInPage() {
  const router = useRouter()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSignIn(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)

    const { error: signInError } = await supabase.auth.signInWithPassword({ email, password })

    if (signInError) {
      setError(signInError.message)
      setLoading(false)
      return
    }

    router.push('/dashboard')
    router.refresh()
  }

  return (
    <div className="min-h-screen bg-[#0a0a0a] flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold font-mono">
            <span className="text-[#00ff88]">Sentinel</span>
            <span className="text-white">AI</span>
          </h1>
          <p className="text-[#888888] text-sm mt-2">Cloud Security Investigation Platform</p>
        </div>

        {/* Card */}
        <div className="rounded-lg border border-[#2a2a2a] bg-[#111111] p-8">
          <h2 className="text-white font-bold text-lg mb-6">Sign In</h2>

          <form onSubmit={handleSignIn} className="space-y-4">
            <div>
              <label className="block text-[#888888] text-xs font-mono uppercase tracking-widest mb-2">
                Email
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="w-full px-4 py-3 bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg text-white text-sm placeholder-[#444444] focus:outline-none focus:border-[#00ff88] transition-colors"
                placeholder="you@example.com"
              />
            </div>

            <div>
              <label className="block text-[#888888] text-xs font-mono uppercase tracking-widest mb-2">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full px-4 py-3 bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg text-white text-sm placeholder-[#444444] focus:outline-none focus:border-[#00ff88] transition-colors"
                placeholder="••••••••"
              />
            </div>

            {error && (
              <div className="px-4 py-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-[#00ff88] text-black font-bold rounded-lg hover:bg-[#00cc66] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>

          <p className="text-[#888888] text-sm text-center mt-6">
            Don&apos;t have an account?{' '}
            <Link href="/auth/signup" className="text-[#00ff88] hover:underline">
              Sign up
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
