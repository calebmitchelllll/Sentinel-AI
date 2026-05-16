import OpenAI from 'openai'

const client = new OpenAI({
  apiKey: process.env.NVIDIA_API_KEY!,
  baseURL: process.env.NEMOTRON_BASE_URL!,
})

export async function callNemotron(
  systemPrompt: string,
  userMessage: string,
  maxTokens = 400,
  jsonMode = false
): Promise<string> {
  const messages: { role: 'system' | 'user' | 'assistant'; content: string }[] = [
    { role: 'system', content: systemPrompt },
    { role: 'user', content: userMessage },
  ]
  // Assistant prefill forces the model to continue from '{' instead of
  // emitting reasoning prose before the JSON object.
  if (jsonMode) {
    messages.push({ role: 'assistant', content: '{' })
  }

  const response = await client.chat.completions.create({
    model: process.env.NEMOTRON_MODEL!,
    messages,
    max_tokens: maxTokens,
    temperature: 0.1,
  })

  const choice = response.choices[0]
  const content = choice?.message?.content
  // This model may put its answer in reasoning_content when content is null
  const reasoning = (choice?.message as any)?.reasoning_content

  const raw = content || reasoning || ''
  if (jsonMode) {
    // Some models include the prefill brace in their response, some don't.
    // Prepend only when the model omitted it to avoid '{{'.
    return raw.trimStart().startsWith('{') ? raw : '{' + raw
  }
  return raw
}
