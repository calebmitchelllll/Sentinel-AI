import { callNemotron } from '../nemotron'

const SYSTEM_PROMPT = `You are a security validator and skeptic. Given findings from a detective and forensics agent, challenge any weak conclusions. Ask: is the evidence solid? Could this be a false positive? Could the anomalous IP be a VPN or legitimate remote worker? Is the blast radius overstated? Output sections: CHALLENGED FINDINGS, VERDICT (confirmed / unconfirmed / false positive).`

export async function runValidator(context: string): Promise<string> {
  return callNemotron(
    SYSTEM_PROMPT,
    `Validate and challenge these security findings — look for gaps in evidence, alternative explanations, or overstated conclusions:\n\n${context.slice(0, 2000)}`
  )
}
