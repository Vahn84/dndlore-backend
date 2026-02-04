import express from "express";
import { requireDM } from "../../middleware/auth.js";
import { formatEventDate } from "../../utils/time.js";
import { Page, User, Group, Event, TimeSystem } from "../../models.js";
import { refreshGoogleToken } from "../auth/index.js";
import { fetchTimeout } from "../../utils/fetch.js";

//SYNC
const router = express.Router();

// -----------------------------------------------------------------------------
// Sync Step 1: Preview - Fetch and summarize from Google Doc
// -----------------------------------------------------------------------------
router.post("/sync/campaign/preview", requireDM, async (req, res) => {
  try {
    let { docId, url, summarize, googleAccessToken } = req.body || {};

    // Fallback to token embedded in JWT (set by Google login) if not provided in body
    if (!googleAccessToken && req.user && req.user.googleAccessToken) {
      googleAccessToken = req.user.googleAccessToken;
    }

    // Helper to attempt token refresh if we have user context
    const tryRefreshToken = async () => {
      if (!req.user || !req.user.id) return null;
      const user = await User.findById(req.user.id);
      if (!user || !user.googleRefreshToken) return null;

      const refreshed = await refreshGoogleToken(user.googleRefreshToken);
      if (!refreshed) return null;

      // Update database
      user.googleAccessToken = refreshed.access_token;
      user.googleTokenExpiry = new Date(
        Date.now() + (refreshed.expires_in || 3600) * 1000,
      );
      await user.save();

      return refreshed.access_token;
    };

    if (!docId && url) {
      const m = url.match(/\/document\/d\/([a-zA-Z0-9_-]+)/);
      docId = m ? m[1] : null;
    }
    if (!docId) {
      return res.status(400).json({ error: "docId or url required" });
    }

    const doSummarize = summarize !== false;

    // 1) Find the latest existing page by sessionDate to avoid duplicate imports
    const pages = await Page.find({
      type: "campaign",
      sessionDate: { $exists: true },
    });
    const parseDDMMYYYY = (str) => {
      if (!str) return null;
      const m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec(String(str).trim());
      if (!m) return null;
      const [_, dd, mm, yyyy] = m;
      const d = new Date(Number(yyyy), Number(mm) - 1, Number(dd));
      return isNaN(d.getTime()) ? null : d;
    };
    const latestLocal = pages.reduce((acc, p) => {
      const d = parseDDMMYYYY(p.sessionDate);
      return d && (!acc || d > acc) ? d : acc;
    }, null);

    // 2) Fetch Google Doc as plain text
    let txt = null;

    // Try public export first
    const exportUrl = `https://docs.google.com/document/d/${docId}/export?format=txt`;
    const publicResp = await fetch(exportUrl);

    if (publicResp.ok) {
      txt = await publicResp.text();
    } else if (googleAccessToken) {
      // Use user's Google access token to fetch via Docs API
      let docsResp = await fetch(
        `https://docs.googleapis.com/v1/documents/${docId}`,
        { headers: { Authorization: `Bearer ${googleAccessToken}` } },
      );

      // If 401, attempt token refresh and retry once
      if (docsResp.status === 401) {
        console.log("Google API returned 401, attempting token refresh...");
        const newToken = await tryRefreshToken();
        if (newToken) {
          googleAccessToken = newToken;
          docsResp = await fetch(
            `https://docs.googleapis.com/v1/documents/${docId}`,
            { headers: { Authorization: `Bearer ${newToken}` } },
          );
        }
      }

      try {
        if (docsResp.ok) {
          const doc = await docsResp.json();
          // Extract plain text from structured document
          if (doc.body && doc.body.content) {
            const textParts = [];
            const extractText = (elements) => {
              for (const el of elements) {
                if (el.paragraph && el.paragraph.elements) {
                  for (const elem of el.paragraph.elements) {
                    if (elem.textRun && elem.textRun.content) {
                      textParts.push(elem.textRun.content);
                    }
                  }
                }
                if (el.table && el.table.tableRows) {
                  for (const row of el.table.tableRows) {
                    if (row.tableCells) {
                      for (const cell of row.tableCells) {
                        if (cell.content) {
                          extractText(cell.content);
                        }
                      }
                    }
                  }
                }
              }
            };
            extractText(doc.body.content);
            txt = textParts.join("");
          }
        }
      } catch (err) {
        console.error("Error parsing Docs API response:", err);
      }
    } // Close else if (googleAccessToken) block

    if (!txt) {
      return res.status(400).json({
        error:
          "Could not fetch document. Make sure it is publicly accessible or provide a valid Google access token.",
      });
    }

    // 3) Parse out sections by date headers (DD.MM.YYYY format)
    const dateRegex = /^(\d{1,2})\.(\d{1,2})\.(\d{4})$/;
    const sections = [];
    const lines = txt.split(/\r?\n/);
    let currSection = null;

    for (const line of lines) {
      const trimmed = line.trim();
      const match = dateRegex.exec(trimmed);
      if (match) {
        // Found a date header
        if (currSection) sections.push(currSection);
        const [_, dd, mm, yyyy] = match;
        currSection = {
          date: trimmed.replace(/\./g, '/'), // Convert DD.MM.YYYY to DD/MM/YYYY
          content: [],
        };
      } else if (currSection) {
        currSection.content.push(line);
      }
    }
    if (currSection) sections.push(currSection);

    if (sections.length === 0) {
      return res.json({
        message: "No date section found (looking for DD.MM.YYYY format)",
        availableDates: [],
      });
    }

    // Filter out dates that already exist in the database
    const existingDates = new Set(
      pages.filter((p) => p.sessionDate).map((p) => p.sessionDate.trim()),
    );

    const availableSections = sections.filter((section) => {
      // Check if this date already exists in DB (as DD.MM.YYYY or DD/MM/YYYY)
      const dateWithDots = section.date; // DD.MM.YYYY
      const dateWithSlashes = section.date.replace(/\./g, "/"); // DD/MM/YYYY
      return (
        !existingDates.has(dateWithDots) && !existingDates.has(dateWithSlashes)
      );
    });

    if (availableSections.length === 0) {
      return res.json({
        message:
          "No new dates found (all dates from document already exist in database)",
        availableDates: [],
      });
    }

    // Return all available dates with their content
    const availableDates = availableSections.map((section) => ({
      date: section.date, // DD.MM.YYYY format
      content: section.content.join("\n").trim(),
    }));

    // Sort by date (most recent first)
    availableDates.sort((a, b) => {
      const dateA = parseDDMMYYYY(a.date.replace(/\./g, "/"));
      const dateB = parseDDMMYYYY(b.date.replace(/\./g, "/"));
      if (!dateA || !dateB) return 0;
      return dateB.getTime() - dateA.getTime();
    });

    res.json({
      availableDates,
      message: `Found ${availableDates.length} new session(s)`,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Server error" });
  }
});

// -----------------------------------------------------------------------------
// Sync Step 1.5: Summarize - Summarize selected date content with OpenAI
// -----------------------------------------------------------------------------
router.post("/sync/campaign/summarize", requireDM, async (req, res) => {
  try {
    const { rawText, sessionDate } = req.body || {};

    if (!rawText) {
      return res.status(400).json({ error: "rawText is required" });
    }

    const OWUI_MODEL = process.env.OWUI_MODEL || "qwen3-next-80b-a3b-thinking";
    const OWUI_API_KEY = process.env.OWUI_API_KEY;
    if (!OWUI_API_KEY) {
      return res
        .status(400)
        .json({ error: "Open WebUI API key (OWUI) not configured" });
    }

    const OWUI_ENDPOINT = process.env.OWUI_ENDPOINT || "http://localhost:3000";

    console.log("Summarizing session via Open WebUI...");
    let summary = rawText;

    try {
      const targetWords = 520;
      const maxTokens = Math.max(
        800,
        Math.min(6000, Math.ceil(targetWords * 2.5)),
      );
      const headers = {
        Authorization: `Bearer ${OWUI_API_KEY}`,
        "Content-Type": "application/json",
      };

      console.log("max tokens:", maxTokens);

      const timeout = 240000;
      const controller = new AbortController();
      const resp = await fetchTimeout(`${OWUI_ENDPOINT}/chat/completions`, timeout, {
        signal: controller.signal,
        method: "POST",
        headers,
        body: JSON.stringify({
          model: OWUI_MODEL,
          messages: [
            {
              role: "system",
              content:
                "Elabora un riassunto da queste note dell'ultima sessione",
            },
            { role: "user", content: rawText },
          ],
          temperature: 0.5,
          max_completion_tokens: maxTokens,
        }),
      });
      // Check if response is HTML (likely an error page)
      const contentType = resp.headers.get('content-type') || '';
      if (contentType.includes('text/html')) {
        const htmlContent = await resp.text();
        console.error("Open WebUI returned HTML instead of JSON:", htmlContent);
        throw new Error(`Open WebUI server returned HTML response. Check if Open WebUI is running at ${OWUI_ENDPOINT}`);
      }

      const data = await resp.json();
      console.log("OWUI Summary:", data);
      const choice = data?.choices?.[0];
      const finishReason = choice?.finish_reason;
      const content = choice?.message?.content?.trim() || choice?.text?.trim();

      if (finishReason === "length") {
        console.warn(
          `Open WebUI response was truncated. Consider increasing max_completion_tokens (current: ${maxTokens})`,
        );
      }

      if (content) summary = content;
    } catch (e) {
      console.error("Open WebUI call failed", e);
      return res.status(500).json({ error: "Open WebUI summarization failed" });
    }

    // Return the raw or summarized text
    const resultSummary = summary;
    res.json({
      summary: resultSummary,
      sessionDate,
      suggestedTitle: sessionDate ? `Session ${sessionDate}` : "Session",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Server error" });
  }
});

// -----------------------------------------------------------------------------
// Sync Step 2: Create - Save the page and event with custom fields
// -----------------------------------------------------------------------------
router.post("/sync/campaign/create", requireDM, async (req, res) => {
  try {
    const { summary, sessionDate, title, subtitle, worldDate, bannerUrl } =
      req.body || {};

    if (!summary || !sessionDate) {
      return res
        .status(400)
        .json({ error: "summary and sessionDate are required" });
    }

    // Split summary into paragraphs for TipTap format
    const paragraphs = String(summary)
      .replace(/\r\n/g, "\n")
      .split(/\n{2,}/)
      .map((p) => p.trim())
      .filter(Boolean);

    const tiptap = {
      type: "doc",
      content:
        paragraphs.length > 0
          ? paragraphs.map((p) => ({
              type: "paragraph",
              content: [{ type: "text", text: p }],
            }))
          : [
              {
                type: "paragraph",
                content: [{ type: "text", text: summary }],
              },
            ],
    };

    const page = await Page.create({
      title: title || "Untitled Session",
      subtitle: subtitle || "",
      type: "campaign",
      blocks: [{ type: "rich", rich: tiptap, plainText: summary }],
      sessionDate,
      worldDate: worldDate || null,
      bannerUrl: bannerUrl || "",
      draft: true,
    });

    // Create a timeline event in the Campaign group
    let campaignGroup = await Group.findOne({
      name: { $regex: /(campaign|session)/i },
    });
    if (!campaignGroup) {
      const count = await Group.countDocuments();
      campaignGroup = await Group.create({
        name: "Campaign",
        order: count,
      });
    }

    let createdEvent = null;
    try {
      const last = await Event.findOne().sort({ order: -1 });
      const order = last ? last.order + 1 : 0;

      // Parse worldDate object into separate fields for Event
      let eventDateFields = {};
      if (worldDate && typeof worldDate === "object") {
        eventDateFields = {
          startEraId: worldDate.eraId || null,
          startYear: worldDate.year ? Number(worldDate.year) : null,
          startMonthIndex: worldDate.monthIndex
            ? Number(worldDate.monthIndex)
            : null,
          startDay: worldDate.day ? Number(worldDate.day) : null,
          startHour:
            worldDate.hour !== undefined ? Number(worldDate.hour) : null,
          startMinute:
            worldDate.minute !== undefined ? Number(worldDate.minute) : null,
        };

        // Format startDate string using time system if available
        const ts = await TimeSystem.findOne();
        const tsConfig = ts?.config || null;
        if (tsConfig && eventDateFields.startYear != null) {
          eventDateFields.startDate = formatEventDate(
            tsConfig,
            eventDateFields.startEraId,
            eventDateFields.startYear,
            eventDateFields.startMonthIndex,
            eventDateFields.startDay,
          );
        }
      }

      console.log("Creating event with:", {
        title: page.title,
        type: "campaign",
        groupId: campaignGroup._id,
        pageId: page._id,
        hidden: true,
        linkSync: true,
        order,
        detailLevel: "Day",
        ...eventDateFields,
      });
      createdEvent = await Event.create({
        title: page.title,
        type: "campaign",
        groupId: campaignGroup._id,
        pageId: page._id,
        hidden: true,
        linkSync: true,
        bannerUrl: bannerUrl || "",
        order,
        detailLevel: "Day",
        ...eventDateFields,
      });
      console.log("Event created successfully:", createdEvent._id);
    } catch (evErr) {
      console.error("Failed to create event for synced session:", evErr);
    }

    console.log("Responding with page and event:", {
      pageId: page._id,
      eventId: createdEvent?._id,
    });
    res.json({ created: page, event: createdEvent });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Server error" });
  }
});

// -----------------------------------------------------------------------------
// Sync (Legacy): import latest session from Google Doc, summarize, create draft campaign page
// -----------------------------------------------------------------------------
router.post("/sync/campaign/from-google", requireDM, async (req, res) => {
  try {
    let {
      docId,
      url,
      summarize,
      title: customTitle,
      googleAccessToken,
      summaryTargetWords,
      keepDialogues,
      worldDate,
    } = req.body || {};

    // Fallback to token embedded in JWT (set by Google login) if not provided in body
    if (!googleAccessToken && req.user && req.user.googleAccessToken) {
      googleAccessToken = req.user.googleAccessToken;
    }

    // Helper to attempt token refresh if we have user context
    const tryRefreshToken = async () => {
      if (!req.user || !req.user.id) return null;
      const user = await User.findById(req.user.id);
      if (!user || !user.googleRefreshToken) return null;

      const refreshed = await refreshGoogleToken(user.googleRefreshToken);
      if (!refreshed) return null;

      // Update database
      user.googleAccessToken = refreshed.accessToken;
      user.googleTokenExpiry = new Date(
        Date.now() + refreshed.expiresIn * 1000,
      );
      await user.save();

      return refreshed.accessToken;
    };

    if (!docId && url) {
      const m = String(url).match(/\/document\/d\/([a-zA-Z0-9_-]+)/);
      if (m) docId = m[1];
    }
    if (!docId) return res.status(400).json({ error: "docId is required" });
    const doSummarize = summarize !== false; // default true

    // 1) Fetch existing campaign pages and determine latest sessionDate
    const pages = await Page.find({ type: "campaign" });
    const parseDDMMYYYY = (s) => {
      if (!s || typeof s !== "string") return null;
      const m = s.match(/^(\d{2})[./-](\d{2})[./-](\d{4})$/);
      if (!m) return null;
      const [_, dd, mm, yyyy] = m;
      const d = new Date(Number(yyyy), Number(mm) - 1, Number(dd));
      return isNaN(d.getTime()) ? null : d;
    };
    const latestLocal = pages.reduce((acc, p) => {
      const d = parseDDMMYYYY(p.sessionDate);
      return d && (!acc || d > acc) ? d : acc;
    }, null);

    // 2) Fetch Google Doc as plain text
    let txt = null;

    // Try public export first
    const exportUrl = `https://docs.google.com/document/d/${docId}/export?format=txt`;
    const publicResp = await fetch(exportUrl);

    if (publicResp.ok) {
      txt = await publicResp.text();
    } else if (googleAccessToken) {
      // Use user's Google access token to fetch via Docs API
      let docsResp = await fetch(
        `https://docs.googleapis.com/v1/documents/${docId}`,
        { headers: { Authorization: `Bearer ${googleAccessToken}` } },
      );

      // If 401, attempt token refresh and retry once
      if (docsResp.status === 401) {
        console.log("Google API returned 401, attempting token refresh...");
        const newToken = await tryRefreshToken();
        if (newToken) {
          googleAccessToken = newToken;
          docsResp = await fetch(
            `https://docs.googleapis.com/v1/documents/${docId}`,
            { headers: { Authorization: `Bearer ${newToken}` } },
          );
        }
      }

      try {
        if (docsResp.ok) {
          const doc = await docsResp.json();
          // Extract plain text from structured document
          if (doc.body && doc.body.content) {
            const textParts = [];
            const extractText = (elements) => {
              for (const el of elements) {
                if (el.paragraph && el.paragraph.elements) {
                  for (const elem of el.paragraph.elements) {
                    if (elem.textRun && elem.textRun.content) {
                      textParts.push(elem.textRun.content);
                    }
                  }
                }
              }
            };
            extractText(doc.body.content);
            txt = textParts.join("");
          }
        } else {
          // Log diagnostic to help user understand why it failed
          const errTxt = await docsResp.text().catch(() => "");
          console.warn(
            "Docs API request failed",
            docsResp.status,
            docsResp.statusText,
            errTxt,
          );
        }
      } catch (oauthErr) {
        console.error("OAuth with user token failed:", oauthErr);
      }
    }

    if (!txt) {
      return res.status(400).json({
        error:
          "Failed to fetch Google Doc. Ensure it is public OR shared with the Google account you used to log in. Also verify Docs API is enabled and consent granted.",
      });
    }

    // 3) Parse headings as dates (DD/MM/YYYY). Take last section newer than local latest
    const lines = txt.split(/\r?\n/);
    const dateLineRE = /^(\d{2})[./-](\d{2})[./-](\d{4})$/;
    const sections = [];
    let current = null;
    for (const line of lines) {
      const m = line.trim().match(dateLineRE);
      if (m) {
        if (current) sections.push(current);
        const ddmmyyyy = `${m[1]}/${m[2]}/${m[3]}`; // normalize to slashes
        current = { date: ddmmyyyy, content: [] };
      } else if (current) {
        current.content.push(line);
      }
    }
    if (current) sections.push(current);
    if (sections.length === 0)
      return res.status(400).json({
        error:
          "No date headings found. Use DD/MM/YYYY, DD.MM.YYYY, or DD-MM-YYYY on its own line.",
      });

    // Find the newest section newer than latestLocal
    let chosen = null;
    for (let i = sections.length - 1; i >= 0; i--) {
      const s = sections[i];
      const d = parseDDMMYYYY(s.date);
      if (!d) continue;
      if (!latestLocal || d > latestLocal) {
        chosen = s;
        break;
      }
    }
    if (!chosen) {
      return res.json({
        message: "No newer section found",
        created: null,
      });
    }

    const rawText = chosen.content.join("\n").trim();
    // Use Open WebUI for summarisation – fallback to raw text if not configured
    const OWUI_API_KEY = process.env.OWUI;
    let summary = rawText;
    if (OWUI_API_KEY && doSummarize) {
      console.log("Summarizing session via Open WebUI...");
      try {
        // Desired length – honour any custom target word count
        const targetWords = Math.max(
          300,
          Math.min(900, Number(summaryTargetWords) || 520),
        );
        const maxTokens = Math.max(
          800,
          Math.min(6000, Math.ceil(targetWords * 2.5)),
        );
        const headers = {
          Authorization: `Bearer ${OWUI_API_KEY}`,
          "Content-Type": "application/json",
        };
        // Optional custom endpoint (useful for self‑hosted instances)
        const WEBUI_ENDPOINT =
          process.env.WEBUI_ENDPOINT || "https://api.openwebui.com";

        // Send the raw user prompt unchanged – no dialogue extraction
        const resp = await fetch(`${WEBUI_ENDPOINT}/v1/chat/completions`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            model: "gpt-4o-mini",
            messages: [
              {
                role: "system",
                content: `Cronista D&D. Resoconto narrativo in Italiano, 4–7 paragrafi, stile evocativo. NON INVENTARE. Solo fatti/dialoghi dalle note. Battute tra "" con nome (O:→Owen, A:→Ardi, F:→Farek, BRUNO:→Bruno). No preamboli. ~${targetWords} parole.`,
              },
              {
                role: "user",
                content: rawText,
              },
            ],
            temperature: 0.7,
            max_completion_tokens: maxTokens,
          }),
        });
        const data = await resp.json();
        const choice = data?.choices?.[0];
        const finishReason = choice?.finish_reason;
        const content =
          choice?.message?.content?.trim() || choice?.text?.trim();

        if (finishReason === "length") {
          console.warn(
            `Open WebUI response was truncated. Consider increasing max_completion_tokens (current: ${maxTokens})`,
          );
        }

        if (content) summary = content;
      } catch (e) {
        console.error("OpenWebUI call failed", e);
      }
    }

    // 4) Create a draft campaign page with one rich block from summary
    // Split summary into paragraphs for better formatting in the editor
    const paragraphs = String(summary)
      .replace(/\r\n/g, "\n")
      .split(/\n{2,}/)
      .map((p) => p.trim())
      .filter(Boolean);

    console.log(
      `Summary length: ${summary.length} chars, ${paragraphs.length} paragraphs`,
    );

    const tiptap = {
      type: "doc",
      content:
        paragraphs.length > 0
          ? paragraphs.map((p) => ({
              type: "paragraph",
              content: [{ type: "text", text: p }],
            }))
          : [
              {
                type: "paragraph",
                content: [{ type: "text", text: summary }],
              },
            ],
    };
    const pageTitle = customTitle?.trim() || `Session ${chosen.date}`;
    const page = await Page.create({
      title: pageTitle,
      type: "campaign",
      subtitle: "",
      blocks: [{ type: "rich", rich: tiptap, plainText: summary }],
      sessionDate: chosen.date,
      worldDate: worldDate || null,
      draft: true,
    });

    console.log(
      `Created page with ${page.blocks[0].plainText.length} chars in plainText`,
    );

    // 5) Also create a timeline event in the Campaign group
    let campaignGroup = await Group.findOne({
      name: { $regex: /(campaign|session)/i },
    });
    if (!campaignGroup) {
      // If no groups exist yet, create the Campaign group automatically
      const count = await Group.countDocuments();
      campaignGroup = await Group.create({
        name: "Campaign",
        order: count,
      });
    }
    let createdEvent = null;
    try {
      createdEvent = await Event.create({
        title: pageTitle,
        type: "campaign",
        startDate: chosen.date,
        groupId: campaignGroup?._id,
        pageId: page._id,
        detailLevel: "Day",
        linkSync: true,
        hidden: true,
      });
    } catch (e) {
      console.warn("Failed to auto-create campaign event:", e?.message || e);
    }

    res.json({ created: page, event: createdEvent });
  } catch (e) {
    console.error("/sync/campaign/from-google failed", e);
    res.status(500).json({ error: "Internal error" });
  }
});

export default router;
