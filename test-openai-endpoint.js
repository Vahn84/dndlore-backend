// Clean version of the test endpoint - copy this into index.js

app.post('/test/openai/summarize', requireDM, async (req, res) => {
	try {
		const {
			text,
			model,
			language = 'it',
			bulletPoints = false,
			targetWords = 120,
			temperature = 0.3,
			style = 'neutral',
			returnPrompt = true,
		} = req.body || {};

		if (!text || typeof text !== 'string' || !text.trim()) {
			return res.status(400).json({ error: 'text is required' });
		}

		const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
		if (!OPENAI_API_KEY) {
			return res.status(400).json({ error: 'OPENAI_API_KEY missing on server' });
		}

		const modelToUse = model || 'gpt-4o-mini';

		const langHint = language === 'it' ? 'Italiano' : 'English';
		const lengthRule = `Keep it under ~${targetWords} words.`;
		const styleRule =
			style === 'executive'
				? 'Use crisp, non-poetic language suitable for an executive summary.'
				: style === 'narrative'
				? 'Use a light narrative tone, but stay concise and avoid flowery prose.'
				: 'Use neutral, concise language.';
		const formatRule = bulletPoints
			? 'Return 5–8 bullet points, each on its own line. No preamble.'
			: 'Return a single concise paragraph. No preamble.';

		// Extract explicit dialogue candidates from input text to prevent invention
		const extractDialogues = (src) => {
			const lines = String(src).split(/\r?\n/);
			const map = new Map([
				['O:', 'Owen'], ['A:', 'Ardi'], ['F:', 'Farek'], ['BRUNO>', 'Bruno'], ['BRUNO:', 'Bruno'],
				['OWEN:', 'Owen'], ['ARDI:', 'Ardi'], ['FAREK:', 'Farek'], ['LYSARA:', 'Lysara'], ['OBYRON:', 'Obyron'], ['RAIDAN:', 'Raidan']
			]);
			const found = [];
			for (const raw of lines) {
				const line = raw.trim();
				if (!line) continue;
				let matched = false;
				for (const [mk, name] of map.entries()) {
					if (line.startsWith(mk)) {
						let content = line.slice(mk.length).trim();
						if (content) found.push({ speaker: name, text: content });
						matched = true;
						break;
					}
				}
				if (matched) continue;
				const m = line.match(/^(Owen|Ardi|Farek|Bruno|Lysara|Obyron|Raidan)\s*:\s*(.+)$/i);
				if (m) {
					found.push({ speaker: m[1][0].toUpperCase() + m[1].slice(1).toLowerCase(), text: m[2].trim() });
				}
			}
			const uniq = [];
			const seen = new Set();
			for (const d of found) {
				const key = d.speaker + '|' + d.text;
				if (seen.has(key)) continue;
				seen.add(key);
				uniq.push({ speaker: d.speaker, text: d.text.slice(0, 200) });
			}
			return uniq.slice(0, 12);
		};
		const allowed = extractDialogues(text);
		const allowedList = allowed.length
			? `\n\nUse ONLY these explicit lines if you include dialogue (otherwise omit dialogue if none match):\n` +
			  allowed.map(d => `- ${d.speaker}: ${d.text}`).join('\n')
			: '';

		const systemPrompt = `You are a narrative chronicler for D&D sessions. Always:
${lengthRule}
${styleRule}
${formatRule}
Write in ${langHint}.
Return 4–7 short paragraphs separated by blank lines.
DO NOT INVENT ANYTHING: no facts, no dialogues. Include ONLY direct quotes that explicitly appear in the notes (verbatim or with minimal punctuation cleanup), with speaker attribution (e.g., Ardi: “…”). If the notes contain markers like O:, A:, F:, BRUNO>, map them to names (Owen, Ardi, Farek, Bruno). If fewer than 3 quotes exist, include only those; if none exist, include zero dialogues. Do not paraphrase non-dialogue text as dialogue. Preserve names, places, spells, wounds.`;

		const userPrompt = `Trasforma le note in un resoconto narrativo coerente. Riporta SOLO dialoghi che compaiono esplicitamente nelle note (con eventuali minime correzioni di punteggiatura), con attribuzione del parlante (es. Owen: “…”). Se nelle note compaiono marcatori come O:, A:, F:, BRUNO>, mappali a Owen, Ardi, Farek, Bruno. Se i dialoghi espliciti sono meno di tre, includi solo quelli; se non ci sono, non inserirne. NON INVENTARE fatti o battute. Mantieni atmosfera ed eventi.${allowedList}\n\n${text}`;

		const maxTokens = Math.max(64, Math.min(2048, Math.ceil((targetWords || 120) * 1.5)));

		const headers = {
			Authorization: `Bearer ${OPENAI_API_KEY}`,
			'Content-Type': 'application/json',
		};
		if (process.env.OPENAI_ORG_ID) headers['OpenAI-Organization'] = process.env.OPENAI_ORG_ID;
		if (process.env.OPENAI_PROJECT_ID) headers['OpenAI-Project'] = process.env.OPENAI_PROJECT_ID;

		const resp = await fetch('https://api.openai.com/v1/chat/completions', {
			method: 'POST',
			headers,
			body: JSON.stringify({
				model: modelToUse,
				temperature: temperature || 0.7,
				max_completion_tokens: maxTokens,
				messages: [
					{ role: 'system', content: systemPrompt },
					{ role: 'user', content: userPrompt },
				],
			}),
		});

		const data = await resp.json();
		if (!resp.ok) {
			return res.status(resp.status).json({
				error: 'OpenAI request failed',
				status: resp.status,
				details: data,
			});
		}

		const choice = data?.choices?.[0];
		let output = '';
		
		if (choice?.message?.content) {
			output = choice.message.content.trim();
		} else if (choice?.text) {
			output = choice.text.trim();
		}
		
		if (!output && choice) {
			console.log('Empty output detected. Full choice:', JSON.stringify(choice, null, 2));
		}
		
		return res.json({
			ok: true,
			usedOpenAI: true,
			model: modelToUse,
			output,
			usage: data?.usage || null,
			rawChoice: !output ? choice : undefined,
			prompt: returnPrompt ? { system: systemPrompt, user: userPrompt } : undefined,
			params: { language, bulletPoints, targetWords, temperature, style },
		});
	} catch (err) {
		console.error('TEST /test/openai/summarize failed', err);
		return res.status(500).json({ error: 'Internal error' });
	}
});
