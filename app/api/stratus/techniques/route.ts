import { NextResponse } from 'next/server'
import { TECHNIQUES } from '@/lib/stratus'

export async function GET() {
  return NextResponse.json({ techniques: TECHNIQUES })
}
