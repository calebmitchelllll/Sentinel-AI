/**
 * AWS CloudTrail client for SentinelAI.
 * Connects to real CloudTrail using credentials from .env.local.
 * Automatically falls back to cloudtrail-demo.json if the AWS connection fails.
 */

import {
  CloudTrailClient,
  LookupEventsCommand,
  LookupEventsCommandInput,
  Event as CTEvent,
} from "@aws-sdk/client-cloudtrail";
import { CloudTrailLogs, CloudTrailRecord } from "./agents/types";
import demoLogs from "@/data/cloudtrail-demo.json";

// IAM, S3, STS, and cover-track events that indicate potential attack activity
const ATTACK_EVENT_NAMES = new Set([
  // Privilege escalation
  "AttachUserPolicy",
  "DetachUserPolicy",
  "PutUserPolicy",
  "DeleteUserPolicy",
  "AttachRolePolicy",
  "DetachRolePolicy",
  "CreateRole",
  "DeleteRole",
  "CreateUser",
  "DeleteUser",
  "CreateAccessKey",
  "DeleteAccessKey",
  "UpdateAccessKey",
  "CreateLoginProfile",
  "UpdateLoginProfile",
  "CreatePolicyVersion",
  "SetDefaultPolicyVersion",
  // Data access / exfiltration
  "GetObject",
  "ListBuckets",
  "ListObjectsV2",
  "ListObjects",
  "PutBucketPolicy",
  "DeleteBucketPolicy",
  "PutBucketAcl",
  "GetBucketPolicy",
  // Recon / credential abuse
  "GetCallerIdentity",
  "ListRoles",
  "ListUsers",
  "ListAttachedUserPolicies",
  "ListAttachedRolePolicies",
  "AssumeRole",
  "AssumeRoleWithWebIdentity",
  "GetSessionToken",
  // Cover tracks
  "DeleteTrail",
  "StopLogging",
  "UpdateTrail",
  "DeleteLogGroup",
  // Auth
  "ConsoleLogin",
]);

function makeClient(): CloudTrailClient {
  return new CloudTrailClient({
    region: process.env.AWS_REGION ?? "us-east-1",
    credentials: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
    },
  });
}

/** Parse the CloudTrailEvent JSON string embedded in each SDK Event object */
function parseRawEvent(event: CTEvent): CloudTrailRecord | null {
  if (!event.CloudTrailEvent) return null;
  try {
    return JSON.parse(event.CloudTrailEvent) as CloudTrailRecord;
  } catch {
    return null;
  }
}

/** Paginate through LookupEvents and collect all records up to maxRecords */
async function paginateLookup(
  client: CloudTrailClient,
  input: LookupEventsCommandInput,
  maxRecords = 200
): Promise<CloudTrailRecord[]> {
  const records: CloudTrailRecord[] = [];
  let nextToken: string | undefined;

  do {
    const res = await client.send(
      new LookupEventsCommand({ ...input, NextToken: nextToken })
    );
    for (const event of res.Events ?? []) {
      const record = parseRawEvent(event);
      if (record) records.push(record);
    }
    nextToken = res.NextToken;
  } while (nextToken && records.length < maxRecords);

  return records;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Fetch all CloudTrail events from the last `minutes` minutes.
 * Falls back to demo data on any AWS error.
 */
export async function fetchRecentEvents(minutes = 30): Promise<CloudTrailLogs> {
  try {
    const client = makeClient();
    const endTime = new Date();
    const startTime = new Date(endTime.getTime() - minutes * 60 * 1000);

    const records = await paginateLookup(client, {
      StartTime: startTime,
      EndTime: endTime,
      MaxResults: 50,
    });

    if (records.length === 0) {
      console.warn(`[CloudTrail] No events in last ${minutes}m — falling back to demo logs`);
      return demoLogs as unknown as CloudTrailLogs;
    }

    console.log(`[CloudTrail] Fetched ${records.length} events from last ${minutes} minutes`);
    return { Records: records };
  } catch (err) {
    console.warn("[CloudTrail] AWS connection failed — falling back to demo logs:", (err as Error).message);
    return demoLogs as unknown as CloudTrailLogs;
  }
}

/**
 * Fetch only security-relevant events from the last 24 hours.
 * Filters client-side because CloudTrail LookupEvents only supports
 * one attribute filter at a time.
 * Falls back to demo data if no suspicious events found or on error.
 */
export async function fetchAttackEvents(): Promise<CloudTrailLogs> {
  try {
    const client = makeClient();
    const endTime = new Date();
    const startTime = new Date(endTime.getTime() - 24 * 60 * 60 * 1000);

    const allRecords = await paginateLookup(client, {
      StartTime: startTime,
      EndTime: endTime,
      MaxResults: 50,
    });

    const attackRecords = allRecords.filter((r) =>
      ATTACK_EVENT_NAMES.has(r.eventName)
    );

    if (attackRecords.length === 0) {
      console.warn("[CloudTrail] No attack-pattern events found — falling back to demo logs");
      return demoLogs as unknown as CloudTrailLogs;
    }

    console.log(`[CloudTrail] Found ${attackRecords.length} suspicious events`);
    return { Records: attackRecords };
  } catch (err) {
    console.warn("[CloudTrail] AWS connection failed — falling back to demo logs:", (err as Error).message);
    return demoLogs as unknown as CloudTrailLogs;
  }
}

/**
 * Fetch events for a specific time window — used after a Stratus simulation
 * to capture exactly the events the attack generated.
 */
export async function fetchEventsInWindow(
  startTime: Date,
  endTime: Date
): Promise<CloudTrailLogs> {
  try {
    const client = makeClient();
    const records = await paginateLookup(client, {
      StartTime: startTime,
      EndTime: endTime,
      MaxResults: 50,
    });

    console.log(`[CloudTrail] Fetched ${records.length} events in window ${startTime.toISOString()} → ${endTime.toISOString()}`);
    return { Records: records };
  } catch (err) {
    console.warn("[CloudTrail] fetchEventsInWindow failed — falling back to demo logs:", (err as Error).message);
    return demoLogs as unknown as CloudTrailLogs;
  }
}
