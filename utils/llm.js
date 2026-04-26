import { fetchTimeout } from "./fetch.js";

// Gateway owns entity extraction + LightRAG retrieval + synthesis.
// dndlore just sends messages and gets back the final narrative.
const GATEWAY_ENDPOINT = process.env.GATEWAY_ENDPOINT || "http://localhost:5678/v1";
const GATEWAY_API_KEY  = process.env.GATEWAY_API_KEY  || "";

/**
 * Generates a narrative summary from raw session notes via the Aetherium gateway.
 * Entity extraction, LightRAG retrieval and synthesis are handled server-side.
 *
 * @param {object} opts
 * @param {string} opts.rawText  - Raw session notes from Google Docs
 * @param {object} opts.settings - AppSettings document (systemPrompt, temperature, maxTokens, model, lightragMode)
 * @returns {Promise<string>} The generated narrative text
 */
export async function generateNarrative({ rawText, settings }) {
  const messages = [
    { role: "system", content: settings.systemPrompt },
    {
      role: "system",
      content:
        "Formatta il testo in markdown: usa **grassetto** per nomi propri di personaggi, luoghi e fazioni; usa *corsivo* per atmosfera, pensieri e enfasi narrativa.",
    },
    {
      role: "user",
      content: `Rispettando tutte le indicazioni del system prompt elabora un testo narrativo da queste note dell'ultima sessione.\n\n${rawText}`,
    },
  ];

  const model = settings.model || "dnd-master-lore";
  const headers = {
    "Content-Type": "application/json",
    ...(GATEWAY_API_KEY ? { Authorization: `Bearer ${GATEWAY_API_KEY}` } : {}),
  };

  console.log(
    `[llm] Calling gateway: model=${model}, temperature=${settings.temperature}, maxTokens=${settings.maxTokens}`
  );

  const response = await fetchTimeout(
    `${GATEWAY_ENDPOINT}/chat/completions`,
    600000,
    {
      method: "POST",
      headers,
      body: JSON.stringify({
        model,
        messages,
        temperature: settings.temperature ?? 0.5,
        max_tokens: settings.maxTokens ?? 64000,
        synthesis_mode: "compact",  // session notes are primary input; lore context is supplementary
      }),
    }
  );

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`Gateway returned HTTP ${response.status}: ${text.slice(0, 200)}`);
  }

  const data = await response.json();
  const content = data?.choices?.[0]?.message?.content?.trim();
  if (!content) throw new Error("Gateway returned an empty response");

  return content;
}
