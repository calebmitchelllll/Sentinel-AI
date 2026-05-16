'use client'

import { useState } from 'react'
import Link from 'next/link'
import { supabase } from '@/lib/supabase'

export default function SignUpPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)
  const [loading, setLoading] = useState(false)

  async function handleSignUp(e: React.FormEvent) {
    e.preventDefault()
    setError('')

    if (password !== confirm) {
      setError('Passwords do not match.')
      return
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters.')
      return
    }

    setLoading(true)
    const { error: signUpError } = await supabase.auth.signUp({ email, password })

    if (signUpError) {
      setError(signUpError.message)
      setLoading(false)
      return
    }

    setSuccess(true)
    setLoading(false)
  }

  return (
    <div className="min-h-screen bg-[#0a0a0a] flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold font-mono">
            <span className="text-[#00ff88]">Sentinel</span>
            <span className="text-white">AI</span>
          </h1>
          <p className="text-[#888888] text-sm mt-2">Cloud Security Investigation Platform</p>
        </div>

        <div className="rounded-lg border border-[#2a2a2a] bg-[#111111] p-8">
          <h2 className="text-white font-bold text-lg mb-6">Create Account</h2>

          {success ? (
            <div className="text-center py-4">
              <div className="text-4xl mb-4">✉️</div>
              <p className="text-[#00ff88] font-bold mb-2">Check your email</p>
              <p className="text-[#888888] text-sm">
                We sent a confirmation link to <strong className="text-white">{email}</strong>.
                Click it to activate your account.
              </p>
              <Link href="/auth/signin" className="mt-6 inline-block text-[#00ff88] hover:underline text-sm">
                Back to Sign In
              </Link>
            </div>
          ) : (
            <form onSubmit={handleSignUp} className="space-y-4">
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

              <div>
                <label className="block text-[#888888] text-xs font-mono uppercase tracking-widest mb-2">
                  Confirm Password
                </label>
                <input
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
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
                {loading ? 'Creating account...' : 'Create Account'}
              </button>
            </form>
          )}

          {!success && (
            <p className="text-[#888888] text-sm text-center mt-6">
              Already have an account?{' '}
              <Link href="/auth/signin" className="text-[#00ff88] hover:underline">
                Sign in
              </Link>
            </p>
          )}
        </div>
      </div>
    </div>
  )
}
