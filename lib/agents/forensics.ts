import { callNemotron } from '../nemotron'

const SYSTEM_PROMPT = `You are a cloud forensics analyst. Given AWS CloudTrail logs, determine: which credential was stolen, when the attacker first appeared, what data was accessed, and the full blast radius. Be precise. Output sections: STOLEN CREDENTIAL, FIRST CONTACT, DATA ACCESSED, BLAST RADIUS.`

function analyze_iam_events(events: any[]): any[] {
  const iamActions = ['ListUsers', 'AttachUserPolicy', 'CreateUser', 'DeleteUser', 'PutUserPolicy', 'CreateAccessKey']
  return events.filter((e) => iamActions.includes(e.eventName))
}

function trace_credential_usage(events: any[], keyId: string): any[] {
  return events.filter((e) => e.userIdentity?.accessKeyId === keyId)
}

function assess_data_exposure(events: any[]): string[] {
  return events
    .filter((e) => e.eventName === 'GetObject' && e.requestParameters?.bucketName)
    .map(
      (e) =>
        `s3://${e.requestParameters.bucketName}/${e.requestParameters.key} at ${e.eventTime} from ${e.sourceIPAddress}`
    )
}

export async function runForensics(cloudtrailEvents: any[]): Promise<string> {
  const iamEvents = analyze_iam_events(cloudtrailEvents)
  const credentialUsage = trace_credential_usage(cloudtrailEvents, 'AKIAIOSFODNN7EXAMPLE')
  const dataExposure = assess_data_exposure(cloudtrailEvents)

  const context = `
IAM events detected: ${iamEvents.length}
${iamEvents.map((e) => `  [${e.eventTime}] ${e.eventName} from ${e.sourceIPAddress}`).join('\n')}

Credential AKIAIOSFODNN7EXAMPLE used ${credentialUsage.length} times total.
First usage: ${credentialUsage[0]?.eventTime}
Attack day usage (IP 185.220.101.47): ${credentialUsage.filter((e) => e.sourceIPAddress === '185.220.101.47').length} events

S3 data exposure:
${dataExposure.join('\n')}
`

  return callNemotron(SYSTEM_PROMPT, `Perform forensic analysis on this AWS credential compromise:\n${context}`)
}
