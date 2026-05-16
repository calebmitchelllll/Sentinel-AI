import OpenAI from 'openai'

const client = new OpenAI({
  apiKey: process.env.NVIDIA_API_KEY!,
  baseURL: process.env.NEMOTRON_BASE_URL!,
})

export async function callNemotron(systemPrompt: string, userMessage: string): Promise<string> {
  const response = await client.chat.completions.create({
    model: process.env.NEMOTRON_MODEL!,
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userMessage },
    ],
    max_tokens: 400,
    temperature: 0.1,
  })

  const choice = response.choices[0]
  const content = choice?.message?.content
  // This model may put its answer in reasoning_content when content is null
  const reasoning = (choice?.message as any)?.reasoning_content

  return content || reasoning || ''
}
