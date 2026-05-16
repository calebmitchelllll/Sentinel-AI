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
    <div className="min-h-screen flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-10">
          <p className="text-white/30 text-xs font-mono tracking-[0.4em] uppercase mb-4">Enterprise Security Platform</p>
          <h1 className="text-4xl font-thin tracking-[0.25em] uppercase">
            <span className="gradient-text">Sentinel</span>
            <span className="text-white/90">AI</span>
          </h1>
          <p className="text-white/30 text-sm mt-3 tracking-wide">Cloud Security Investigation Platform</p>
        </div>

        <div className="glass rounded-2xl p-8">
          <h2 className="text-white/80 font-light text-sm uppercase tracking-[0.2em] mb-8">Create Account</h2>

          {success ? (
            <div className="text-center py-6">
              <div className="text-5xl mb-5">✉️</div>
              <p className="text-purple-400 font-semibold mb-2">Check your email</p>
              <p className="text-white/40 text-sm leading-relaxed">
                We sent a confirmation link to <strong className="text-white/70">{email}</strong>.
                Click it to activate your account.
              </p>
              <Link href="/auth/signin" className="mt-8 inline-block text-purple-400 hover:text-purple-300 transition-colors text-sm">
                Back to Sign In
              </Link>
            </div>
          ) : (
            <form onSubmit={handleSignUp} className="space-y-5">
              <div>
                <label className="block text-white/30 text-xs font-mono uppercase tracking-widest mb-2">Email</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  className="w-full px-4 py-3 bg-white/[0.04] border border-white/[0.08] rounded-xl text-white text-sm placeholder-white/20 focus:outline-none focus:border-purple-500/50 focus:bg-white/[0.06] transition-all"
                  placeholder="you@example.com"
                />
              </div>

              <div>
                <label className="block text-white/30 text-xs font-mono uppercase tracking-widest mb-2">Password</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="w-full px-4 py-3 bg-white/[0.04] border border-white/[0.08] rounded-xl text-white text-sm placeholder-white/20 focus:outline-none focus:border-purple-500/50 focus:bg-white/[0.06] transition-all"
                  placeholder="••••••••"
                />
              </div>

              <div>
                <label className="block text-white/30 text-xs font-mono uppercase tracking-widest mb-2">Confirm Password</label>
                <input
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  required
                  className="w-full px-4 py-3 bg-white/[0.04] border border-white/[0.08] rounded-xl text-white text-sm placeholder-white/20 focus:outline-none focus:border-purple-500/50 focus:bg-white/[0.06] transition-all"
                  placeholder="••••••••"
                />
              </div>

              {error && (
                <div className="px-4 py-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-sm">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="w-full py-3 rounded-xl font-semibold text-sm text-white transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                style={{ background: 'linear-gradient(135deg, #c026d3 0%, #7c3aed 100%)' }}
              >
                {loading ? 'Creating account...' : 'Create Account'}
              </button>
            </form>
          )}

          {!success && (
            <p className="text-white/30 text-sm text-center mt-8">
              Already have an account?{' '}
              <Link href="/auth/signin" className="text-purple-400 hover:text-purple-300 transition-colors">
                Sign in
              </Link>
            </p>
          )}
        </div>
      </div>
    </div>
  )
}
