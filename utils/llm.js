import { fetchTimeout } from "./fetch.js";

// wiki-server is the new retrieval+synthesis engine (Karpathy two-pass over the
// Aetherium markdown wiki against an OpenAI-compatible LLM server).
// It exposes /elaborate (rich) and /v1/chat/completions (drop-in for the old
// gateway). We use /elaborate so we can pass include_spoilers explicitly.
//
// Set WIKI_SERVER_URL in env. GATEWAY_ENDPOINT is kept as legacy fallback so
// existing deployments don't break before the env is updated.
const WIKI_SERVER_URL =
  process.env.WIKI_SERVER_URL ||
  process.env.GATEWAY_ENDPOINT?.replace(/\/v1\/?$/, "") ||
  "http://localhost:5678";
const WIKI_SERVER_KEY = process.env.WIKI_SERVER_KEY || process.env.GATEWAY_API_KEY || "";

/**
 * Generates a narrative from raw session notes using the wiki-server.
 *
 * Audience-aware:
 *  - 'player' (default) → spoiler-safe recap using AppSettings.playerSystemPrompt
 *    + include_spoilers=false on the wiki side. Suitable for publication.
 *  - 'dm' → DM-prep / analysis using AppSettings.dmSystemPrompt + include_spoilers=true.
 *
 * @param {object} opts
 * @param {string} opts.rawText  - Raw session notes
 * @param {object} opts.settings - AppSettings document
 * @param {'player'|'dm'} [opts.audience='player']
 * @returns {Promise<string>} The generated narrative text
 */
export async function generateNarrative({ rawText, settings, audience = "player" }) {
  // Pick prompt + temperature based on audience.
  let systemPrompt;
  let temperature;
  if (audience === "dm") {
    systemPrompt = settings.dmSystemPrompt || settings.systemPrompt;
    temperature = settings.dmTemperature ?? settings.temperature ?? 0.4;
  } else {
    systemPrompt = settings.playerSystemPrompt || settings.systemPrompt;
    temperature = settings.playerTemperature ?? settings.temperature ?? 0.65;
  }
  const includeSpoilers = audience === "dm";

  // Compose the user-side task. wiki-server's /elaborate already injects its
  // own discipline-prompt for pass 2; we layer the audience-specific
  // systemPrompt on top of the task description so the user's preferences
  // (tone, format) ride alongside.
  const task = audience === "dm"
    ? `Analizza queste note di sessione dal punto di vista del DM.\n\n${systemPrompt}`
    : `Elabora queste note di sessione in un capitolo narrativo per i giocatori.\n\n${systemPrompt}`;

  const body = {
    task,
    notes: rawText,
    include_spoilers: includeSpoilers,
    pass2_temperature: temperature,
    pass2_max_tokens: settings.maxTokens ?? 4096,
  };
  if (settings.model) body.model = settings.model;

  const headers = {
    "Content-Type": "application/json",
    ...(WIKI_SERVER_KEY ? { Authorization: `Bearer ${WIKI_SERVER_KEY}` } : {}),
  };

  console.log(
    `[llm] wiki-server elaborate: audience=${audience} include_spoilers=${includeSpoilers} temperature=${temperature} model=${settings.model || "(server default)"}`
  );

  const response = await fetchTimeout(
    `${WIKI_SERVER_URL.replace(/\/$/, "")}/elaborate`,
    600000,
    {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    }
  );

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`wiki-server returned HTTP ${response.status}: ${text.slice(0, 400)}`);
  }

  const data = await response.json();
  const content = (data?.content || "").trim();
  if (!content) throw new Error("wiki-server returned empty content");

  // Surface retrieval debug info in logs so we can audit which pages were used.
  if (Array.isArray(data?.seeds)) {
    console.log(`[llm] seeds: ${data.seeds.join(", ")}`);
  }
  if (Array.isArray(data?.selected)) {
    console.log(`[llm] selected ${data.selected.length} pages`);
  }

  return content;
}

// Streaming variant. Opens an SSE connection to wiki-server's /elaborate/stream
// and returns the raw response stream so the caller can pipe it onward.
// Returns { response, body } where body is a Node ReadableStream of SSE bytes.
export async function streamNarrative({ rawText, settings, audience = "player" }) {
  let systemPrompt;
  let temperature;
  if (audience === "dm") {
    systemPrompt = settings.dmSystemPrompt || settings.systemPrompt;
    temperature = settings.dmTemperature ?? settings.temperature ?? 0.4;
  } else {
    systemPrompt = settings.playerSystemPrompt || settings.systemPrompt;
    temperature = settings.playerTemperature ?? settings.temperature ?? 0.65;
  }
  const includeSpoilers = audience === "dm";
  const task = audience === "dm"
    ? `Analizza queste note di sessione dal punto di vista del DM.\n\n${systemPrompt}`
    : `Elabora queste note di sessione in un capitolo narrativo per i giocatori.\n\n${systemPrompt}`;

  const body = {
    task,
    notes: rawText,
    include_spoilers: includeSpoilers,
    pass2_temperature: temperature,
    pass2_max_tokens: settings.maxTokens ?? 4096,
  };
  if (settings.model) body.model = settings.model;

  const headers = {
    "Content-Type": "application/json",
    Accept: "text/event-stream",
    ...(WIKI_SERVER_KEY ? { Authorization: `Bearer ${WIKI_SERVER_KEY}` } : {}),
  };

  console.log(
    `[llm] wiki-server elaborate/stream: audience=${audience} include_spoilers=${includeSpoilers} temperature=${temperature}`
  );

  const response = await fetch(
    `${WIKI_SERVER_URL.replace(/\/$/, "")}/elaborate/stream`,
    { method: "POST", headers, body: JSON.stringify(body) }
  );
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`wiki-server stream returned HTTP ${response.status}: ${text.slice(0, 400)}`);
  }
  return response;
}
