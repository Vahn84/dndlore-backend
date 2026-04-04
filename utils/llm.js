import { fetchTimeout } from "./fetch.js";

const LIGHTRAG_ENDPOINT = process.env.LIGHTRAG_ENDPOINT;
const LIGHTRAG_API_KEY = process.env.LIGHTRAG_API_KEY;

const LLM_ENDPOINT = process.env.LLM_ENDPOINT || "http://localhost:1234/v1";
const LLM_API_KEY = process.env.LLM_API_KEY || "";
const LLM_MODEL = process.env.LLM_MODEL || "gemma-4-26b-a4b-it-8bit";

/**
 * Calls LM Studio to extract named entities from raw session notes.
 * Returns a compact comma-separated string of names suitable for a LightRAG query.
 */
async function extractEntities(rawText) {
  const model = LLM_MODEL;
  const headers = {
    "Content-Type": "application/json",
    ...(LLM_API_KEY ? { Authorization: `Bearer ${LLM_API_KEY}` } : {}),
  };

  const response = await fetchTimeout(
    `${LLM_ENDPOINT}/chat/completions`,
    60000,
    {
      method: "POST",
      headers,
      body: JSON.stringify({
        model,
        messages: [
          {
            role: "system",
            content:
              "You are an assistant that extracts named entities from tabletop RPG session notes. " +
              "Extract every proper name mentioned: characters (PCs and NPCs), locations, factions, artifacts, creatures, and spells. " +
              "Return ONLY a comma-separated list of names, nothing else. No explanations, no punctuation other than commas.",
          },
          {
            role: "user",
            content: rawText,
          },
        ],
        temperature: 0.1,
        max_completion_tokens: 256,
      }),
    }
  );

  if (!response.ok) {
    throw new Error(`LM Studio entity extraction returned HTTP ${response.status}`);
  }

  const data = await response.json();
  const content = data?.choices?.[0]?.message?.content?.trim();
  if (!content) throw new Error("LM Studio returned empty entity list");
  return content;
}

/**
 * Queries LightRAG /query/data and formats the result into a lore context string.
 */
async function retrieveLoreContext(query, mode = "mix") {
  if (!LIGHTRAG_ENDPOINT || !LIGHTRAG_API_KEY) {
    console.warn("[llm] LIGHTRAG_ENDPOINT or LIGHTRAG_API_KEY not set — skipping retrieval");
    return "";
  }

  const response = await fetchTimeout(
    `${LIGHTRAG_ENDPOINT}/query/data`,
    120000,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": LIGHTRAG_API_KEY,
      },
      body: JSON.stringify({ query, mode, top_k: 20 }),
    }
  );

  if (!response.ok) {
    throw new Error(`LightRAG /query/data returned HTTP ${response.status}`);
  }

  const json = await response.json();
  const data = json.data ?? {};

  const parts = [];

  for (const entity of data.entities ?? []) {
    parts.push(
      `ENTITY [${(entity.entity_type ?? "").toUpperCase()}] ${entity.entity_name ?? ""}: ${entity.description ?? ""}`
    );
  }

  for (const rel of data.relationships ?? []) {
    parts.push(
      `RELATIONSHIP: ${rel.src_id ?? ""} → ${rel.tgt_id ?? ""}: ${rel.description ?? ""} (keywords: ${rel.keywords ?? ""})`
    );
  }

  for (const chunk of data.chunks ?? []) {
    if (chunk.content) parts.push(chunk.content);
  }

  const context = parts.join("\n");

  // Cap lore context at ~64k tokens (64,000 × 4 chars/token = 256,000 chars).
  // The full session notes are always passed separately as the user message —
  // this only limits the supplementary lore enrichment injected into the prompt.
  const MAX_CHARS = 256000;
  if (context.length > MAX_CHARS) {
    console.warn(`[llm] Lore context capped: ${context.length} → ${MAX_CHARS} chars`);
    return context.slice(0, MAX_CHARS);
  }

  return context;
}

/**
 * Generates a narrative summary from raw session notes.
 *
 * @param {object} opts
 * @param {string} opts.rawText  - Raw session notes from Google Docs
 * @param {object} opts.settings - AppSettings document (or plain object with same fields)
 * @returns {Promise<string>} The generated narrative text
 */
export async function generateNarrative({ rawText, settings }) {
  // 1. Extract entities from raw notes, then use them to query LightRAG
  let loreContext = "";
  try {
    const entities = await extractEntities(rawText);
    console.log(`[llm] Extracted entities: ${entities}`);
    loreContext = await retrieveLoreContext(entities, settings.lightragMode ?? "mix");
    console.log(`[llm] Retrieved lore context (${loreContext.length} chars)`);
  } catch (err) {
    console.warn("[llm] LightRAG retrieval failed, proceeding without context:", err.message);
  }

  // 2. Build messages
  const messages = [
    { role: "system", content: settings.systemPrompt },
    {
      role: "system",
      content:
        "Formatta il testo in markdown: usa **grassetto** per nomi propri di personaggi, luoghi e fazioni; usa *corsivo* per atmosfera, pensieri e enfasi narrativa.",
    },
  ];

  if (loreContext) {
    messages.push({ role: "system", content: `CONTESTO DELLA LORE:\n${loreContext}` });
  }

  messages.push({
    role: "user",
    content: `Rispettando tutte le indicazioni del system prompt elabora un testo narrativo da queste note dell'ultima sessione.\n\n${rawText}`,
  });

  // 3. Call LM Studio
  const model = settings.model || LLM_MODEL;
  const headers = {
    "Content-Type": "application/json",
    ...(LLM_API_KEY ? { Authorization: `Bearer ${LLM_API_KEY}` } : {}),
  };

  console.log(`[llm] Calling LM Studio: model=${model}, temperature=${settings.temperature}, maxTokens=${settings.maxTokens}`);

  const response = await fetchTimeout(
    `${LLM_ENDPOINT}/chat/completions`,
    300000,
    {
      method: "POST",
      headers,
      body: JSON.stringify({
        model,
        messages,
        temperature: settings.temperature ?? 0.5,
        max_completion_tokens: settings.maxTokens ?? 64000,
      }),
    }
  );

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`LM Studio returned HTTP ${response.status}: ${text.slice(0, 200)}`);
  }

  const data = await response.json();
  const content = data?.choices?.[0]?.message?.content?.trim();
  if (!content) throw new Error("LM Studio returned an empty response");

  return content;
}
