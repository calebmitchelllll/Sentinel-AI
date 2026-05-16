/**
 * Stratus Red Team attack technique catalog.
 *
 * Each technique generates realistic CloudTrail events matching what the
 * stratus-red-team binary produces when detonated against a real AWS account.
 * Technique IDs mirror the official stratus catalog:
 *   https://stratus-red-team.cloud/attack-techniques/AWS/
 */

export interface StratusTechnique {
  id: string
  name: string
  tactic: string
  description: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  mitre: string
}

export const TECHNIQUES: StratusTechnique[] = [
  {
    id: 'aws.credential-access.iam-backdoor-user',
    name: 'IAM Backdoor User',
    tactic: 'Persistence',
    description: 'Creates a hidden IAM user and access key for persistent access after initial compromise',
    severity: 'HIGH',
    mitre: 'T1136.003',
  },
  {
    id: 'aws.privilege-escalation.iam-create-admin-user',
    name: 'Create Admin User',
    tactic: 'Privilege Escalation + Exfiltration',
    description: 'Creates a new IAM user with AdministratorAccess, then exfiltrates sensitive S3 data',
    severity: 'CRITICAL',
    mitre: 'T1078.004',
  },
  {
    id: 'aws.exfiltration.s3-backdoor-bucket-policy',
    name: 'S3 Bucket Policy Backdoor',
    tactic: 'Exfiltration',
    description: 'Modifies S3 bucket policy to grant an external AWS account read access, then exfiltrates objects',
    severity: 'CRITICAL',
    mitre: 'T1530',
  },
  {
    id: 'aws.defense-evasion.cloudtrail-stop',
    name: 'Stop CloudTrail Logging',
    tactic: 'Defense Evasion',
    description: 'Escalates to admin then stops CloudTrail logging; DeleteTrail is blocked by SCP',
    severity: 'HIGH',
    mitre: 'T1562.008',
  },
  {
    id: 'aws.lateral-movement.ec2-share-ami',
    name: 'Share AMI Externally',
    tactic: 'Lateral Movement',
    description: 'Shares a private AMI and EBS snapshot with an external AWS account for lateral movement',
    severity: 'MEDIUM',
    mitre: 'T1578',
  },
  {
    id: 'aws.impact.s3-ransomware-client-side-encryption',
    name: 'S3 Ransomware',
    tactic: 'Impact',
    description: 'Re-encrypts all objects in a target S3 bucket with attacker-controlled keys, then deletes originals — making data unrecoverable without paying',
    severity: 'CRITICAL',
    mitre: 'T1486',
  },
  {
    id: 'aws.credential-access.secretsmanager-retrieve-secrets',
    name: 'Secrets Manager Dump',
    tactic: 'Credential Access',
    description: 'Enumerates and bulk-retrieves all secrets from AWS Secrets Manager, exposing database passwords, API keys, and certificates',
    severity: 'HIGH',
    mitre: 'T1552.001',
  },
  {
    id: 'aws.credential-access.ec2-steal-instance-credentials',
    name: 'EC2 Metadata Theft',
    tactic: 'Credential Access',
    description: 'Exploits SSRF vulnerability in an EC2-hosted app to call the instance metadata service and steal the attached IAM role credentials',
    severity: 'MEDIUM',
    mitre: 'T1552.005',
  },
  {
    id: 'aws.discovery.account-reconnaissance',
    name: 'Account Reconnaissance',
    tactic: 'Discovery',
    description: 'Read-only enumeration of IAM users, roles, policies, EC2 instances, and S3 buckets to map the environment before a larger attack',
    severity: 'LOW',
    mitre: 'T1580',
  },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

function uuid(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16)
  })
}

/** Generate ISO timestamps offset from an attack start time */
function ts(attackStart: Date, offsetsMs: number[]): string[] {
  return offsetsMs.map((ms) => new Date(attackStart.getTime() + ms).toISOString())
}

/** 6 days of normal developer baseline events before the attack */
function baseline(userName: string, accessKeyId: string, normalIP: string): any[] {
  const events: any[] = []
  const start = new Date('2024-01-01T09:00:00Z')
  const userAgent = 'aws-cli/2.13.0 Python/3.11.0 Darwin/22.6.0'
  const arn = `arn:aws:iam::123456789012:user/${userName}`
  const identity = { type: 'IAMUser', userName, arn, accessKeyId }

  for (let day = 0; day < 6; day++) {
    const d = new Date(start.getTime() + day * 86_400_000)
    events.push(
      { eventTime: new Date(d.getTime() + 0).toISOString(), eventName: 'GetCallerIdentity', eventSource: 'sts.amazonaws.com', userIdentity: identity, sourceIPAddress: normalIP, userAgent, requestParameters: null, responseElements: { userId: 'AIDACKCEVSQ6C2EXAMPLE', account: '123456789012', arn }, eventID: uuid() },
      { eventTime: new Date(d.getTime() + 300_000).toISOString(), eventName: 'DescribeInstances', eventSource: 'ec2.amazonaws.com', userIdentity: identity, sourceIPAddress: normalIP, userAgent, requestParameters: { instancesSet: {}, filterSet: {} }, responseElements: null, eventID: uuid() },
      { eventTime: new Date(d.getTime() + 900_000).toISOString(), eventName: 'GetObject', eventSource: 's3.amazonaws.com', userIdentity: identity, sourceIPAddress: normalIP, userAgent, requestParameters: { bucketName: 'acme-corp-app-configs', key: 'dev/config.json' }, responseElements: null, eventID: uuid() },
      { eventTime: new Date(d.getTime() + 1_800_000).toISOString(), eventName: 'GetMetricData', eventSource: 'monitoring.amazonaws.com', userIdentity: identity, sourceIPAddress: normalIP, userAgent, requestParameters: { startTime: d.toISOString(), endTime: new Date(d.getTime() + 3_600_000).toISOString() }, responseElements: null, eventID: uuid() }
    )
  }
  return events
}

// ─── Technique: aws.credential-access.iam-backdoor-user ──────────────────────

function generateIamBackdoorUser(): any[] {
  const userName = 'dev-sarah'
  const accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  const normalIP = '203.0.113.42'
  const attackerIP = '185.220.101.47'
  const attackStart = new Date('2024-01-07T08:12:03Z')
  const t = ts(attackStart, [0, 95_000, 225_000, 407_000, 503_000, 614_000])
  const identity = { type: 'IAMUser', userName, arn: `arn:aws:iam::123456789012:user/${userName}`, accessKeyId }
  const ua = 'python-httpx/0.24.1 Linux/kali-linux'

  return [
    ...baseline(userName, accessKeyId, normalIP),
    { eventTime: t[0], eventName: 'GetCallerIdentity', eventSource: 'sts.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: null, responseElements: { userId: 'AIDACKCEVSQ6C2EXAMPLE', account: '123456789012', arn: identity.arn }, eventID: uuid() },
    { eventTime: t[1], eventName: 'ListUsers', eventSource: 'iam.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { pathPrefix: '/' }, responseElements: null, eventID: uuid() },
    { eventTime: t[2], eventName: 'CreateUser', eventSource: 'iam.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { userName: 'svc-backup-sync' }, responseElements: { user: { userName: 'svc-backup-sync', userId: 'AIDACKCEVSQ6C2XYZ999', arn: 'arn:aws:iam::123456789012:user/svc-backup-sync', createDate: t[2] } }, eventID: uuid() },
    { eventTime: t[3], eventName: 'AttachUserPolicy', eventSource: 'iam.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { userName: 'svc-backup-sync', policyArn: 'arn:aws:iam::aws:policy/AmazonS3FullAccess' }, responseElements: null, eventID: uuid() },
    { eventTime: t[4], eventName: 'CreateAccessKey', eventSource: 'iam.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { userName: 'svc-backup-sync' }, responseElements: { accessKey: { accessKeyId: 'AKIAIOSFODNN7BACKDOR', status: 'Active', userName: 'svc-backup-sync', createDate: t[4] } }, eventID: uuid() },
    { eventTime: t[5], eventName: 'ListBuckets', eventSource: 's3.amazonaws.com', userIdentity: { type: 'IAMUser', userName: 'svc-backup-sync', arn: 'arn:aws:iam::123456789012:user/svc-backup-sync', accessKeyId: 'AKIAIOSFODNN7BACKDOR' }, sourceIPAddress: '45.33.32.156', userAgent: 'boto3/1.26.0', requestParameters: null, responseElements: null, eventID: uuid() },
  ]
}

// ─── Technique: aws.privilege-escalation.iam-create-admin-user ───────────────

function generateIamCreateAdminUser(): any[] {
  const userName = 'dev-john'
  const accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  const normalIP = '198.51.100.12'
  const attackerIP = '91.108.4.177'
  const attackStart = new Date('2024-01-14T14:22:11Z')
  const t = ts(attackStart, [0, 47_000, 88_000, 183_000, 264_000, 341_000, 455_000, 519_000])
  const identity = { type: 'IAMUser', userName, arn: `arn:aws:iam::123456789012:user/${userName}`, accessKeyId }
  const ua = 'curl/7.88.1'

  return [
    ...baseline(userName, accessKeyId, normalIP),
    { eventTime: t[0], eventName: 'GetCallerIdentity', eventSource: 'sts.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: null, responseElements: { userId: 'AIDACKCEVSQ6C2EXAMPLE', account: '123456789012', arn: identity.arn }, eventID: uuid() },
    { eventTime: t[1], eventName: 'ListAttachedUserPolicies', eventSource: 'iam.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { userName }, responseElements: null, eventID: uuid() },
    { eventTime: t[2], eventName: 'AttachUserPolicy', eventSource: 'iam.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { userName, policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' }, responseElements: null, eventID: uuid() },
    { eventTime: t[3], eventName: 'ListBuckets', eventSource: 's3.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: null, responseElements: null, eventID: uuid() },
    { eventTime: t[4], eventName: 'GetObject', eventSource: 's3.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { bucketName: 'acme-corp-sensitive-data', key: 'finance/payroll-2024.csv' }, responseElements: null, additionalEventData: { bytesTransferredOut: 2_847_362 }, eventID: uuid() },
    { eventTime: t[5], eventName: 'GetObject', eventSource: 's3.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { bucketName: 'acme-corp-sensitive-data', key: 'legal/contracts-2023.zip' }, responseElements: null, additionalEventData: { bytesTransferredOut: 9_124_558 }, eventID: uuid() },
    { eventTime: t[6], eventName: 'CreateUser', eventSource: 'iam.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { userName: 'svc-metrics-collector' }, responseElements: { user: { userName: 'svc-metrics-collector', userId: 'AIDACKCEVSQ6C2METR01', arn: 'arn:aws:iam::123456789012:user/svc-metrics-collector', createDate: t[6] } }, eventID: uuid() },
    { eventTime: t[7], eventName: 'CreateAccessKey', eventSource: 'iam.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { userName: 'svc-metrics-collector' }, responseElements: { accessKey: { accessKeyId: 'AKIAIOSFODNN7PERSIST', status: 'Active', userName: 'svc-metrics-collector', createDate: t[7] } }, eventID: uuid() },
  ]
}

// ─── Technique: aws.exfiltration.s3-backdoor-bucket-policy ───────────────────

function generateS3BucketPolicyBackdoor(): any[] {
  const userName = 'dev-alex'
  const accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  const normalIP = '10.0.1.45'
  const attackerIP = '199.87.154.255'
  const externalIP = '172.18.0.1'
  const attackStart = new Date('2024-01-21T18:44:07Z')
  const t = ts(attackStart, [0, 68_000, 142_000, 217_000, 389_000, 461_000, 534_000])
  const identity = { type: 'IAMUser', userName, arn: `arn:aws:iam::123456789012:user/${userName}`, accessKeyId }
  const ua = 'Boto3/1.34.0 Python/3.12.0 Linux/Ubuntu'
  const externalIdentity = { type: 'AWSAccount', accountId: '999999999999', principalId: 'AROACKCEVSQ6C2EXTERA1' }

  return [
    ...baseline(userName, accessKeyId, normalIP),
    { eventTime: t[0], eventName: 'GetCallerIdentity', eventSource: 'sts.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: null, responseElements: { userId: 'AIDACKCEVSQ6C2EXAMPLE', account: '123456789012', arn: identity.arn }, eventID: uuid() },
    { eventTime: t[1], eventName: 'ListBuckets', eventSource: 's3.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: null, responseElements: null, eventID: uuid() },
    { eventTime: t[2], eventName: 'GetBucketPolicy', eventSource: 's3.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { bucketName: 'acme-corp-sensitive-data' }, responseElements: null, eventID: uuid() },
    { eventTime: t[3], eventName: 'PutBucketPolicy', eventSource: 's3.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { bucketName: 'acme-corp-sensitive-data', bucketPolicy: '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::acme-corp-sensitive-data/*"}]}' }, responseElements: null, eventID: uuid() },
    { eventTime: t[4], eventName: 'GetObject', eventSource: 's3.amazonaws.com', userIdentity: externalIdentity, sourceIPAddress: externalIP, userAgent: 'aws-cli/2.15.0', requestParameters: { bucketName: 'acme-corp-sensitive-data', key: 'hr/employees.csv' }, responseElements: null, additionalEventData: { bytesTransferredOut: 1_843_200 }, eventID: uuid() },
    { eventTime: t[5], eventName: 'GetObject', eventSource: 's3.amazonaws.com', userIdentity: externalIdentity, sourceIPAddress: externalIP, userAgent: 'aws-cli/2.15.0', requestParameters: { bucketName: 'acme-corp-sensitive-data', key: 'hr/salary-bands.xlsx' }, responseElements: null, additionalEventData: { bytesTransferredOut: 524_288 }, eventID: uuid() },
    { eventTime: t[6], eventName: 'GetObject', eventSource: 's3.amazonaws.com', userIdentity: externalIdentity, sourceIPAddress: externalIP, userAgent: 'aws-cli/2.15.0', requestParameters: { bucketName: 'acme-corp-sensitive-data', key: 'finance/q4-earnings.pdf' }, responseElements: null, additionalEventData: { bytesTransferredOut: 3_145_728 }, eventID: uuid() },
  ]
}

// ─── Technique: aws.defense-evasion.cloudtrail-stop ──────────────────────────

function generateCloudTrailStop(): any[] {
  const userName = 'dev-mike'
  const accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  const normalIP = '203.0.113.99'
  const attackerIP = '185.220.101.32'
  const attackStart = new Date('2024-01-28T11:05:44Z')
  const t = ts(attackStart, [0, 52_000, 131_000, 208_000, 287_000, 366_000, 441_000])
  const identity = { type: 'IAMUser', userName, arn: `arn:aws:iam::123456789012:user/${userName}`, accessKeyId }
  const ua = 'go-aws-sdk/v2 linux/amd64'

  return [
    ...baseline(userName, accessKeyId, normalIP),
    { eventTime: t[0], eventName: 'GetCallerIdentity', eventSource: 'sts.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: null, responseElements: { userId: 'AIDACKCEVSQ6C2EXAMPLE', account: '123456789012', arn: identity.arn }, eventID: uuid() },
    { eventTime: t[1], eventName: 'AttachUserPolicy', eventSource: 'iam.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { userName, policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' }, responseElements: null, eventID: uuid() },
    { eventTime: t[2], eventName: 'DescribeTrails', eventSource: 'cloudtrail.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { trailNameList: [], includeShadowTrails: true }, responseElements: null, eventID: uuid() },
    { eventTime: t[3], eventName: 'GetTrailStatus', eventSource: 'cloudtrail.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { name: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/management-events' }, responseElements: null, eventID: uuid() },
    { eventTime: t[4], eventName: 'StopLogging', eventSource: 'cloudtrail.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { name: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/management-events' }, responseElements: null, eventID: uuid() },
    // DeleteTrail blocked by SCP — shows up as an error event, which is forensically important
    { eventTime: t[5], eventName: 'DeleteTrail', eventSource: 'cloudtrail.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { name: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/management-events' }, responseElements: null, errorCode: 'AccessDeniedException', errorMessage: 'User is not authorized to perform cloudtrail:DeleteTrail due to an explicit deny in a Service Control Policy', eventID: uuid() },
    { eventTime: t[6], eventName: 'PutEventSelectors', eventSource: 'cloudtrail.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { trailName: 'management-events', eventSelectors: [{ readWriteType: 'WriteOnly', includeManagementEvents: false, dataResources: [] }] }, responseElements: null, eventID: uuid() },
  ]
}

// ─── Technique: aws.lateral-movement.ec2-share-ami ───────────────────────────

function generateEC2ShareAMI(): any[] {
  const userName = 'dev-priya'
  const accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  const normalIP = '198.51.100.55'
  const attackerIP = '104.21.14.87'
  const attackStart = new Date('2024-02-03T16:33:19Z')
  const t = ts(attackStart, [0, 61_000, 124_000, 211_000, 334_000, 447_000])
  const identity = { type: 'IAMUser', userName, arn: `arn:aws:iam::123456789012:user/${userName}`, accessKeyId }
  const ua = 'stratus-red-team_linux_amd64'

  return [
    ...baseline(userName, accessKeyId, normalIP),
    { eventTime: t[0], eventName: 'GetCallerIdentity', eventSource: 'sts.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: null, responseElements: { userId: 'AIDACKCEVSQ6C2EXAMPLE', account: '123456789012', arn: identity.arn }, eventID: uuid() },
    { eventTime: t[1], eventName: 'DescribeImages', eventSource: 'ec2.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { imagesSet: { items: [{ imageId: 'ami-0abcdef1234567890' }] }, filterSet: { items: [{ name: 'is-public', valueSet: { items: [{ value: 'false' }] } }] } }, responseElements: null, eventID: uuid() },
    { eventTime: t[2], eventName: 'DescribeInstances', eventSource: 'ec2.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { instancesSet: {}, filterSet: {} }, responseElements: null, eventID: uuid() },
    { eventTime: t[3], eventName: 'ModifyImageAttribute', eventSource: 'ec2.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { imageId: 'ami-0abcdef1234567890', launchPermission: { add: { items: [{ userId: '999999999999' }] } } }, responseElements: null, eventID: uuid() },
    { eventTime: t[4], eventName: 'DescribeSnapshots', eventSource: 'ec2.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { snapshotSet: {}, filterSet: { items: [{ name: 'owner-id', valueSet: { items: [{ value: '123456789012' }] } }] } }, responseElements: null, eventID: uuid() },
    { eventTime: t[5], eventName: 'ModifySnapshotAttribute', eventSource: 'ec2.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { snapshotId: 'snap-0abcdef1234567890', createVolumePermission: { add: { items: [{ userId: '999999999999' }] } } }, responseElements: null, eventID: uuid() },
  ]
}

// ─── Technique: aws.impact.s3-ransomware-client-side-encryption ──────────────

function generateS3Ransomware(): any[] {
  const userName = 'dev-carlos'
  const accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  const normalIP = '203.0.113.77'
  const attackerIP = '45.142.212.100'
  const attackStart = new Date('2024-02-11T03:17:42Z')
  const t = ts(attackStart, [0, 38_000, 91_000, 148_000, 201_000, 249_000, 296_000, 341_000, 389_000, 431_000])
  const identity = { type: 'IAMUser', userName, arn: `arn:aws:iam::123456789012:user/${userName}`, accessKeyId }
  const ua = 'python-requests/2.31.0 Linux/5.15.0-kali'

  return [
    ...baseline(userName, accessKeyId, normalIP),
    { eventTime: t[0], eventName: 'GetCallerIdentity', eventSource: 'sts.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: null, responseElements: { userId: 'AIDACKCEVSQ6C2EXAMPLE', account: '123456789012', arn: identity.arn }, eventID: uuid() },
    { eventTime: t[1], eventName: 'ListBuckets', eventSource: 's3.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: null, responseElements: null, eventID: uuid() },
    { eventTime: t[2], eventName: 'ListObjectsV2', eventSource: 's3.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { bucketName: 'acme-corp-sensitive-data', prefix: '' }, responseElements: null, eventID: uuid() },
    { eventTime: t[3], eventName: 'PutObject', eventSource: 's3.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { bucketName: 'acme-corp-sensitive-data', key: 'hr/employees.csv', 'x-amz-server-side-encryption-customer-algorithm': 'AES256' }, responseElements: null, additionalEventData: { bytesTransferredIn: 1_843_200 }, eventID: uuid() },
    { eventTime: t[4], eventName: 'DeleteObject', eventSource: 's3.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { bucketName: 'acme-corp-sensitive-data', key: 'hr/employees.csv' }, responseElements: null, eventID: uuid() },
    { eventTime: t[5], eventName: 'PutObject', eventSource: 's3.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { bucketName: 'acme-corp-sensitive-data', key: 'finance/payroll-2024.csv', 'x-amz-server-side-encryption-customer-algorithm': 'AES256' }, responseElements: null, additionalEventData: { bytesTransferredIn: 2_847_362 }, eventID: uuid() },
    { eventTime: t[6], eventName: 'DeleteObject', eventSource: 's3.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { bucketName: 'acme-corp-sensitive-data', key: 'finance/payroll-2024.csv' }, responseElements: null, eventID: uuid() },
    { eventTime: t[7], eventName: 'PutObject', eventSource: 's3.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { bucketName: 'acme-corp-sensitive-data', key: 'legal/contracts-2023.zip', 'x-amz-server-side-encryption-customer-algorithm': 'AES256' }, responseElements: null, additionalEventData: { bytesTransferredIn: 9_124_558 }, eventID: uuid() },
    { eventTime: t[8], eventName: 'DeleteObject', eventSource: 's3.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { bucketName: 'acme-corp-sensitive-data', key: 'legal/contracts-2023.zip' }, responseElements: null, eventID: uuid() },
    { eventTime: t[9], eventName: 'PutBucketVersioning', eventSource: 's3.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { bucketName: 'acme-corp-sensitive-data', VersioningConfiguration: { Status: 'Suspended' } }, responseElements: null, eventID: uuid() },
  ]
}

// ─── Technique: aws.credential-access.secretsmanager-retrieve-secrets ────────

function generateSecretsManagerDump(): any[] {
  const userName = 'dev-nina'
  const accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  const normalIP = '10.0.2.88'
  const attackerIP = '194.165.16.11'
  const attackStart = new Date('2024-02-18T22:41:09Z')
  const t = ts(attackStart, [0, 44_000, 109_000, 168_000, 225_000, 281_000, 336_000, 390_000])
  const identity = { type: 'IAMUser', userName, arn: `arn:aws:iam::123456789012:user/${userName}`, accessKeyId }
  const ua = 'aws-sdk-js/3.400.0 Node/v20.0.0 Linux/x64'

  return [
    ...baseline(userName, accessKeyId, normalIP),
    { eventTime: t[0], eventName: 'GetCallerIdentity', eventSource: 'sts.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: null, responseElements: { userId: 'AIDACKCEVSQ6C2EXAMPLE', account: '123456789012', arn: identity.arn }, eventID: uuid() },
    { eventTime: t[1], eventName: 'ListSecrets', eventSource: 'secretsmanager.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { maxResults: 100 }, responseElements: null, eventID: uuid() },
    { eventTime: t[2], eventName: 'GetSecretValue', eventSource: 'secretsmanager.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { secretId: 'prod/acme/db-master-password' }, responseElements: null, eventID: uuid() },
    { eventTime: t[3], eventName: 'GetSecretValue', eventSource: 'secretsmanager.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { secretId: 'prod/acme/stripe-api-key' }, responseElements: null, eventID: uuid() },
    { eventTime: t[4], eventName: 'GetSecretValue', eventSource: 'secretsmanager.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { secretId: 'prod/acme/jwt-signing-secret' }, responseElements: null, eventID: uuid() },
    { eventTime: t[5], eventName: 'GetSecretValue', eventSource: 'secretsmanager.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { secretId: 'prod/acme/sendgrid-api-key' }, responseElements: null, eventID: uuid() },
    { eventTime: t[6], eventName: 'GetSecretValue', eventSource: 'secretsmanager.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { secretId: 'prod/acme/github-deploy-token' }, responseElements: null, eventID: uuid() },
    { eventTime: t[7], eventName: 'DescribeSecret', eventSource: 'secretsmanager.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { secretId: 'prod/acme/internal-ca-cert' }, responseElements: null, eventID: uuid() },
  ]
}

// ─── Technique: aws.credential-access.ec2-steal-instance-credentials ─────────

function generateEC2StealInstanceCredentials(): any[] {
  const appIP = '10.0.4.212'
  const attackerIP = '78.46.223.107'
  const attackStart = new Date('2024-02-25T09:58:31Z')
  const t = ts(attackStart, [0, 12_000, 34_000, 89_000, 152_000, 228_000])
  const appIdentity = { type: 'WebIdentityUser', principalId: 'arn:aws:sts::123456789012:assumed-role/acme-app-ec2-role/i-0abc123def456789', arn: 'arn:aws:sts::123456789012:assumed-role/acme-app-ec2-role/i-0abc123def456789', accessKeyId: 'ASIAIOSFODNN7EXAMPLE' }
  const ua = 'python-httpx/0.24.1'

  return [
    // Normal app traffic baseline
    { eventTime: new Date(attackStart.getTime() - 300_000).toISOString(), eventName: 'GetObject', eventSource: 's3.amazonaws.com', userIdentity: appIdentity, sourceIPAddress: appIP, userAgent: 'aws-sdk-python/1.34 Python/3.11', requestParameters: { bucketName: 'acme-corp-app-configs', key: 'prod/config.json' }, responseElements: null, eventID: uuid() },
    { eventTime: new Date(attackStart.getTime() - 180_000).toISOString(), eventName: 'PutLogEvents', eventSource: 'logs.amazonaws.com', userIdentity: appIdentity, sourceIPAddress: appIP, userAgent: 'aws-sdk-python/1.34 Python/3.11', requestParameters: { logGroupName: '/acme/app/prod', logStreamName: 'i-0abc123def456789' }, responseElements: null, eventID: uuid() },
    // SSRF: attacker causes app to call 169.254.169.254 and relays credentials
    { eventTime: t[0], eventName: 'GetCallerIdentity', eventSource: 'sts.amazonaws.com', userIdentity: appIdentity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: null, responseElements: { userId: 'AROACKCEVSQ6C2EXAMPLE:i-0abc123def456789', account: '123456789012', arn: appIdentity.arn }, eventID: uuid() },
    { eventTime: t[1], eventName: 'ListBuckets', eventSource: 's3.amazonaws.com', userIdentity: appIdentity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: null, responseElements: null, eventID: uuid() },
    { eventTime: t[2], eventName: 'GetObject', eventSource: 's3.amazonaws.com', userIdentity: appIdentity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { bucketName: 'acme-corp-sensitive-data', key: 'hr/employees.csv' }, responseElements: null, additionalEventData: { bytesTransferredOut: 1_843_200 }, eventID: uuid() },
    { eventTime: t[3], eventName: 'ListRoles', eventSource: 'iam.amazonaws.com', userIdentity: appIdentity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { pathPrefix: '/' }, responseElements: null, eventID: uuid() },
    { eventTime: t[4], eventName: 'AssumeRole', eventSource: 'sts.amazonaws.com', userIdentity: appIdentity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { roleArn: 'arn:aws:iam::123456789012:role/acme-admin-cross-account', roleSessionName: 'pivot' }, responseElements: null, errorCode: 'AccessDenied', errorMessage: 'User is not authorized to assume role acme-admin-cross-account', eventID: uuid() },
    { eventTime: t[5], eventName: 'GetSecretValue', eventSource: 'secretsmanager.amazonaws.com', userIdentity: appIdentity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { secretId: 'prod/acme/db-master-password' }, responseElements: null, eventID: uuid() },
  ]
}

// ─── Technique: aws.discovery.account-reconnaissance ─────────────────────────

function generateAccountReconnaissance(): any[] {
  const userName = 'dev-tom'
  const accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  const normalIP = '198.51.100.33'
  const attackerIP = '162.55.188.202'
  const attackStart = new Date('2024-03-04T14:02:17Z')
  const t = ts(attackStart, [0, 28_000, 54_000, 82_000, 109_000, 136_000, 163_000, 192_000, 220_000, 247_000])
  const identity = { type: 'IAMUser', userName, arn: `arn:aws:iam::123456789012:user/${userName}`, accessKeyId }
  const ua = 'ScoutSuite/5.13.0 Python/3.10 Linux'

  return [
    ...baseline(userName, accessKeyId, normalIP),
    { eventTime: t[0], eventName: 'GetCallerIdentity', eventSource: 'sts.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: null, responseElements: { userId: 'AIDACKCEVSQ6C2EXAMPLE', account: '123456789012', arn: identity.arn }, eventID: uuid() },
    { eventTime: t[1], eventName: 'GetAccountSummary', eventSource: 'iam.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: null, responseElements: null, eventID: uuid() },
    { eventTime: t[2], eventName: 'ListUsers', eventSource: 'iam.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { pathPrefix: '/', maxItems: 100 }, responseElements: null, eventID: uuid() },
    { eventTime: t[3], eventName: 'ListRoles', eventSource: 'iam.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { pathPrefix: '/', maxItems: 100 }, responseElements: null, eventID: uuid() },
    { eventTime: t[4], eventName: 'ListPolicies', eventSource: 'iam.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { scope: 'Local', onlyAttached: true }, responseElements: null, eventID: uuid() },
    { eventTime: t[5], eventName: 'DescribeInstances', eventSource: 'ec2.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { instancesSet: {}, filterSet: {} }, responseElements: null, eventID: uuid() },
    { eventTime: t[6], eventName: 'DescribeSecurityGroups', eventSource: 'ec2.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { securityGroupSet: {}, filterSet: {} }, responseElements: null, eventID: uuid() },
    { eventTime: t[7], eventName: 'ListBuckets', eventSource: 's3.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: null, responseElements: null, eventID: uuid() },
    { eventTime: t[8], eventName: 'GetBucketAcl', eventSource: 's3.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { bucketName: 'acme-corp-sensitive-data' }, responseElements: null, eventID: uuid() },
    { eventTime: t[9], eventName: 'DescribeTrails', eventSource: 'cloudtrail.amazonaws.com', userIdentity: identity, sourceIPAddress: attackerIP, userAgent: ua, requestParameters: { trailNameList: [], includeShadowTrails: true }, responseElements: null, eventID: uuid() },
  ]
}

// ─── Public API ───────────────────────────────────────────────────────────────

const GENERATORS: Record<string, () => any[]> = {
  'aws.credential-access.iam-backdoor-user': generateIamBackdoorUser,
  'aws.privilege-escalation.iam-create-admin-user': generateIamCreateAdminUser,
  'aws.exfiltration.s3-backdoor-bucket-policy': generateS3BucketPolicyBackdoor,
  'aws.defense-evasion.cloudtrail-stop': generateCloudTrailStop,
  'aws.lateral-movement.ec2-share-ami': generateEC2ShareAMI,
  'aws.impact.s3-ransomware-client-side-encryption': generateS3Ransomware,
  'aws.credential-access.secretsmanager-retrieve-secrets': generateSecretsManagerDump,
  'aws.credential-access.ec2-steal-instance-credentials': generateEC2StealInstanceCredentials,
  'aws.discovery.account-reconnaissance': generateAccountReconnaissance,
}

export function detonateAttack(techniqueId: string): any[] {
  const generator = GENERATORS[techniqueId]
  if (!generator) throw new Error(`Unknown stratus technique: ${techniqueId}`)
  return generator()
}

export function randomTechnique(): string {
  const ids = Object.keys(GENERATORS)
  return ids[Math.floor(Math.random() * ids.length)]
}
