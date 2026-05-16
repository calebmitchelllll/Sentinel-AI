/**
 * POST /api/cloudtrail/simulate
 * Triggers Stratus Red Team attack simulations, waits for CloudTrail logs
 * to propagate, then returns the captured logs ready for agent investigation.
 *
 * Stratus Red Team (https://stratus-red-team.cloud) must be installed on the
 * server running this app. On Brev: `brew install datadog-labs/stratus-red-team/stratus-red-team`
 *
 * Body (optional):
 *   { techniques: string[] }  — override the default technique list
 *   { waitSeconds: number }   — override the 10s propagation wait (default 10)
 */

import { NextRequest, NextResponse } from "next/server";
import { exec } from "child_process";
import { promisify } from "util";
import { fetchEventsInWindow } from "@/lib/cloudtrail";
import { processLogsForAgents } from "@/lib/parseCloudTrail";

export const runtime = "nodejs";
export const maxDuration = 120; // Stratus + propagation wait can take ~60s total

const execAsync = promisify(exec);

const DEFAULT_TECHNIQUES = [
  "aws.credential-access.steal-ec2-instance-credentials",
  "aws.exfiltration.s3-backdoor-bucket-policy",
  "aws.privilege-escalation.iam-create-admin-user",
];

interface StratusResult {
  technique: string;
  status: "success" | "failed" | "skipped";
  stdout?: string;
  stderr?: string;
  error?: string;
}

async function detonateStratus(technique: string): Promise<StratusResult> {
  try {
    // Warm up (idempotent prereq setup) then detonate
    await execAsync(`stratus warmup ${technique}`, {
      env: {
        ...process.env,
        AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
        AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
        AWS_REGION: process.env.AWS_REGION ?? "us-east-1",
      },
      timeout: 30_000,
    });

    const { stdout, stderr } = await execAsync(`stratus detonate ${technique}`, {
      env: {
        ...process.env,
        AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
        AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
        AWS_REGION: process.env.AWS_REGION ?? "us-east-1",
      },
      timeout: 30_000,
    });

    return { technique, status: "success", stdout, stderr };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; message?: string };
    // Don't fail the whole route if one technique fails (e.g. prereqs not met)
    console.warn(`[Stratus] ${technique} failed:`, e.message);
    return {
      technique,
      status: "failed",
      stdout: e.stdout,
      stderr: e.stderr,
      error: e.message,
    };
  }
}

async function isStratusAvailable(): Promise<boolean> {
  try {
    await execAsync("which stratus");
    return true;
  } catch {
    return false;
  }
}

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const techniques: string[] = body.techniques ?? DEFAULT_TECHNIQUES;
  const waitSeconds: number = body.waitSeconds ?? 10;

  const simulationStart = new Date();
  const stratusAvailable = await isStratusAvailable();

  let stratusResults: StratusResult[] = [];
  let source: "stratus" | "demo" = "demo";

  if (!stratusAvailable) {
    console.warn("[Simulate] stratus binary not found — returning demo logs");
  } else {
    // Run all attack techniques sequentially (order matters for realistic log sequence)
    for (const technique of techniques) {
      const result = await detonateStratus(technique);
      stratusResults.push(result);

      // Small delay between techniques so CloudTrail timestamps are distinct
      await new Promise((r) => setTimeout(r, 1500));
    }
    source = "stratus";
    console.log(`[Simulate] Stratus detonation complete. Waiting ${waitSeconds}s for CloudTrail propagation...`);
  }

  // Wait for CloudTrail to capture the events (typically 5–15 seconds)
  await new Promise((r) => setTimeout(r, waitSeconds * 1000));

  const simulationEnd = new Date();

  // Fetch logs from the window that covers the simulation + propagation wait
  // Add 60s buffer on each end to catch any timing drift
  const fetchStart = new Date(simulationStart.getTime() - 60_000);
  const fetchEnd = new Date(simulationEnd.getTime() + 30_000);

  const logs = await fetchEventsInWindow(fetchStart, fetchEnd);
  const { all, suspicious, agentLogs, stats } = processLogsForAgents(logs);

  return NextResponse.json({
    source,
    simulation: {
      techniques,
      results: stratusResults,
      startedAt: simulationStart.toISOString(),
      completedAt: simulationEnd.toISOString(),
      propagationWaitSeconds: waitSeconds,
    },
    logs: {
      all,
      suspicious,
      agentLogs,
      stats,
    },
    meta: {
      stratusAvailable,
      fetchWindow: {
        from: fetchStart.toISOString(),
        to: fetchEnd.toISOString(),
      },
    },
  });
}
