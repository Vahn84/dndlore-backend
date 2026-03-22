import express from "express";
import { requireDM } from "../../middleware/auth.js";
import { Page, Event, TimeSystem } from "../../models.js";
import { formatEventDate } from "../../utils/time.js";

/**
 * Strips HTML tags from text while preserving content
 * @param {string} html - The HTML string to process
 * @returns {string} Text content with HTML tags removed
 */
function stripHtmlTags(html) {
  if (!html || typeof html !== "string") return "";

  // Use regex to remove HTML tags but preserve content
  // This handles both <tag> and </tag> formats, including self-closing tags
  let stripped = html.replace(/<[^>]*>/g, "");

  // Add space after periods when followed by a letter (handles "Hello.World" → "Hello. World")
  // Only add space if it's likely a sentence terminator (not version numbers like "1.0")
  stripped = stripped.replace(/\.([a-zA-Z])/g, ". $1");

  return stripped;
}

export { stripHtmlTags, extractDateFromContent };

// -----------------------------------------------------------------------------
// Pagine
// -----------------------------------------------------------------------------
const router = express.Router();

router.get("/pages", async (req, res) => {
  const { type, q, limit } = req.query;
  const query = {};
  if (type) {
    query.type = type;
  }
  if (q && typeof q === "string" && q.trim()) {
    query.title = { $regex: q.trim(), $options: "i" };
  }
  const lim = Math.min(100, Math.max(1, Number(limit) || 9999));

  // Determine sorting based on type
  let sort = { order: 1 };
  if (type === "campaign") {
    // For campaign pages, sort by sessionDate descending (newest first)
    // Fallback to order field for pages without sessionDate
    sort = {
      sessionDate: -1, // Descending order (newest first)
      order: 1, // Fallback to order field
    };
  }

  const pages = await Page.find(query).limit(lim).sort(sort);
  console.log("Pages fetched", pages);
  res.json(pages);
});

router.get("/pages/:id", async (req, res) => {
  const page = await Page.findById(req.params.id);
  if (!page) return res.status(404).json({ error: "Page not found" });
  res.json(page);
});

/**
 * GET endpoint to retrieve page content with HTML tags stripped
 * @param {string} id - The page ID
 * @returns {object} Page data with stripped HTML content
 */
router.get("/pages/:id/strip-html", requireDM, async (req, res) => {
  try {
    const page = await Page.findById(req.params.id);
    if (!page) return res.status(404).json({ error: "Page not found" });

    // Create a deep copy of the page to avoid modifying the original
    const strippedPage = JSON.parse(JSON.stringify(page));

    // Process each block to strip HTML tags from rich text content
    if (strippedPage.blocks && Array.isArray(strippedPage.blocks)) {
      strippedPage.blocks = strippedPage.blocks.map((block) => {
        if (block.type === "rich" && block.rich) {
          // Process the rich text content to strip HTML tags
          if (block.rich.content && Array.isArray(block.rich.content)) {
            block.rich.content = block.rich.content.map((paragraph) => {
              if (paragraph.type === "paragraph" && paragraph.content) {
                paragraph.content = paragraph.content.map((text) => {
                  if (text.text) {
                    text.text = stripHtmlTags(text.text);
                  }
                  return text;
                });
              }
              return paragraph;
            });
          }

          // Also update the plainText field if it exists
          if (block.plainText) {
            block.plainText = stripHtmlTags(block.plainText);
          }
        }
        return block;
      });
    }

    res.json(strippedPage);
  } catch (error) {
    console.error(`Error stripping HTML from page ${req.params.id}:`, error);
    res.status(500).json({ error: "Failed to process page content" });
  }
});

router.post("/pages", requireDM, async (req, res) => {
  const {
    title,
    type,
    placeType,
    coordinates,
    bannerUrl,
    assetId,
    blocks = [],
    sessionDate,
    worldDate,
    hidden = false,
    draft = false,
  } = req.body;
  if (!title) return res.status(400).json({ error: "title is required" });
  if (!type) return res.status(400).json({ error: "type is required" });
  const page = await Page.create({
    title,
    subtitle: "",
    type,
    placeType,
    coordinates,
    bannerUrl,
    assetId,
    blocks,
    sessionDate,
    worldDate,
    hidden,
    draft,
  });

  res.json(page);
});

router.put("/pages/:id", requireDM, async (req, res) => {
  const { id } = req.params;
  const update = {};
  const unset = {};
  const fields = [
    "title",
    "subtitle",
    "type",
    "placeType",
    "coordinates",
    "bannerUrl",
    "bannerThumbUrl",
    "assetId",
    "blocks",
    "sessionDate",
    "worldDate",
    "hidden",
    "draft",
  ];
  fields.forEach((field) => {
    // Check if field exists in request body (even if undefined/null)
    if (req.body.hasOwnProperty(field)) {
      // If explicitly set to null or undefined, remove the field
      if (req.body[field] === null || req.body[field] === undefined) {
        unset[field] = "";
      } else {
        update[field] = req.body[field];
      }
    }
  });

  // Build the MongoDB update operation
  const updateOperation = {};
  if (Object.keys(update).length > 0) {
    updateOperation.$set = update;
  }
  if (Object.keys(unset).length > 0) {
    updateOperation.$unset = unset;
  }

  console.log("Page updated:", update, "Unset:", unset);
  if (update.draft === true) {
    console.log(`Page ${id} is being unpublished (draft=true)`);
  }
  const page = await Page.findByIdAndUpdate(id, updateOperation, {
    new: true,
  });
  if (!page) return res.status(404).json({ error: "Page not found" });

  // After updating a page, propagate to linked events that opt into syncing
  try {
    const linkedEvents = await Event.find({ pageId: id });
    console.log(`Found ${linkedEvents.length} linked events for page ${id}`);

    // Fetch time system once for formatting dates
    const ts = await TimeSystem.findOne();
    const tsConfig = ts?.config || null;

    for (const ev of linkedEvents) {
      let changed = false;

      // If unpublishing (draft=true), hide the event (regardless of linkSync)
      if (update.draft === true && !ev.hidden) {
        ev.hidden = true;
        changed = true;
        console.log(
          `Hiding event ${ev._id} (${ev.title}) linked to unpublished page ${id}`,
        );
      }

      // Only sync other fields if linkSync is enabled
      if (!ev.linkSync) {
        // Still save if we changed hidden status
        if (changed) {
          await ev.save();
          console.log(`Saved hidden status for event ${ev._id}`);
        }
        continue;
      }
      // Sync title
      if (page.title && ev.title !== page.title) {
        ev.title = page.title;
        changed = true;
      }
      // Sync banner
      const pb = page.bannerUrl || "";
      const pbt = page.bannerThumbUrl || "";
      if ((ev.bannerUrl || "") !== pb) {
        ev.bannerUrl = pb;
        changed = true;
      }
      if ((ev.bannerThumbUrl || "") !== pbt) {
        ev.bannerThumbUrl = pbt;
        changed = true;
      }
      // Sync world date
      if (page.worldDate && page.worldDate.eraId) {
        const wd = page.worldDate;
        // Copy structured world date into event start fields
        const nextEra = wd.eraId || null;
        const nextYear = typeof wd.year === "number" ? wd.year : null;
        const nextMonth =
          typeof wd.monthIndex === "number" ? wd.monthIndex : null;
        const nextDay = typeof wd.day === "number" ? wd.day : null;
        const nextHour = typeof wd.hour === "number" ? wd.hour : null;
        const nextMinute = typeof wd.minute === "number" ? wd.minute : null;
        if (
          ev.startEraId !== nextEra ||
          ev.startYear !== nextYear ||
          ev.startMonthIndex !== nextMonth ||
          ev.startDay !== nextDay ||
          ev.startHour !== nextHour ||
          ev.startMinute !== nextMinute
        ) {
          ev.startEraId = nextEra;
          ev.startYear = nextYear;
          ev.startMonthIndex = nextMonth;
          ev.startDay = nextDay;
          ev.startHour = nextHour;
          ev.startMinute = nextMinute;
          // Clear endDate fields for single-day events
          ev.endEraId = null;
          ev.endYear = null;
          ev.endMonthIndex = null;
          ev.endDay = null;
          ev.endDate = "";

          // Format startDate string using time system if available
          if (tsConfig) {
            ev.startDate = formatEventDate(
              tsConfig,
              nextEra,
              nextYear,
              nextMonth,
              nextDay,
            );
          }
          changed = true;
        }
      } else if (
        page.worldDate === null ||
        (page.worldDate && !page.worldDate.eraId)
      ) {
        // Clear world date if page worldDate is null or empty
        if (
          ev.startEraId ||
          ev.startYear ||
          ev.startMonthIndex ||
          ev.startDay
        ) {
          ev.startEraId = null;
          ev.startYear = null;
          ev.startMonthIndex = null;
          ev.startDay = null;
          ev.endEraId = null;
          ev.endYear = null;
          ev.endMonthIndex = null;
          ev.endDay = null;
          ev.startDate = "";
          ev.endDate = "";
          changed = true;
        }
      }
      if (changed) {
        await ev.save();
        console.log(
          `Event ${ev._id} synced. startDate: "${ev.startDate}", startYear: ${ev.startYear}, startMonthIndex: ${ev.startMonthIndex}, startDay: ${ev.startDay}`,
        );
      }
    }
  } catch (propErr) {
    console.warn("Failed to propagate page changes to events:", propErr);
  }
  res.json(page);
});

// Delete a page. Requires DM role. Also clear pageId on events referencing this page.
router.delete("/pages/:id", requireDM, async (req, res) => {
  const { id } = req.params;
  const page = await Page.findByIdAndDelete(id);
  if (!page) return res.status(404).json({ error: "Page not found" });
  // Unlink events referencing this page
  await Event.updateMany({ pageId: id }, { $unset: { pageId: "" } });
  res.json({ success: true });
});

// Update page order for a specific type (for drag-and-drop reordering)
router.patch("/pages/reorder/:type", requireDM, async (req, res) => {
  try {
    const { type } = req.params;
    const { pageIds } = req.body; // Array of page IDs in desired order

    if (!Array.isArray(pageIds)) {
      return res.status(400).json({ error: "pageIds must be an array" });
    }

    // Validate page type
    const validTypes = ["place", "history", "myth", "people", "campaign"];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ error: "Invalid page type" });
    }

    // Update order field for each page
    const updates = pageIds.map((pageId, index) => ({
      updateOne: {
        filter: { _id: pageId, type },
        update: { $set: { order: index } },
      },
    }));

    await Page.bulkWrite(updates);
    res.json({ success: true, updated: pageIds.length });
  } catch (err) {
    console.error("Error updating page order:", err);
    res.status(500).json({ error: "Failed to update page order" });
  }
});

import exportKnowledgeRouter from "./export-knowledge.js";
router.use(exportKnowledgeRouter);

export default router;

// Import JSON endpoint to create campaign pages from FVTT Journal entries
router.post("/pages/import", requireDM, async (req, res) => {
  try {
    const { pages } = req.body;

    if (!pages || !Array.isArray(pages)) {
      return res
        .status(400)
        .json({ error: "Invalid JSON structure. Expected pages array." });
    }

    const createdPages = [];
    let orderCounter = 0;

    for (const pageData of pages) {
      // Extract name and text.content from the FVTT Journal entry structure
      const pageName = pageData.name || pageData.title?.show || "Untitled Page";
      const content = pageData.text?.content || "";

      // Create a rich text block from the content
      const blocks = [];
      if (content) {
        blocks.push({
          type: "rich",
          rich: {
            type: "doc",
            content: [
              {
                type: "paragraph",
                content: [
                  {
                    type: "text",
                    text: content,
                    marks: [],
                  },
                ],
              },
            ],
          },
          plainText: content,
        });
      }

      // Create the campaign page as a draft
      const newPage = await Page.create({
        title: pageName,
        subtitle: "",
        type: "campaign",
        blocks: blocks,
        draft: true, // Set as draft
        order: orderCounter++,
      });

      createdPages.push(newPage);
    }

    res.json({
      success: true,
      pagesCreated: createdPages.length,
      pages: createdPages,
    });
  } catch (error) {
    console.error("Error importing pages:", error);
    res
      .status(500)
      .json({ error: "Failed to import pages", details: error.message });
  }
});

/**
 * POST endpoint to process campaign pages without subtitles, worldDates, or sessionDates
 *
 * This endpoint:
 * 1. Finds all campaign pages that are missing subtitle, worldDate, or sessionDate
 * 2. Extracts in-world dates from the text content (format: "28 Decimos 2130 I.E.")
 * 3. Populates the worldDate field with the extracted date
 * 4. Strips HTML tags from content using stripHtmlTags function
 * 5. Finds the previous page by order field and increments its session number
 * 6. Adds one week to the previous page's sessionDate for the current page
 * 7. Updates all processed pages with the new data
 *
 * @route POST /pages/process-campaign
 * @requires DM role authentication
 * @returns {Object} JSON with success status, message, count of processed pages, and array of updated pages
 */
router.post("/pages/process-campaign", requireDM, async (req, res) => {
  try {
    // Query to find all campaign pages with HTML tags in rich.content.content.text
    const campaignPagesWithHtml = await Page.find({
      type: "campaign",
      "blocks.rich.content.content.text": {
        $regex: /<[a-z][\s\S]*>/,
        $options: "i",
      },
    }).sort({ sessionDate: 1 });

    console.log(
      `Found ${campaignPagesWithHtml.length} campaign pages with HTML tags in rich content`,
    );

    let currentIndex = 0;

    while (currentIndex < campaignPagesWithHtml.length) {
      const page = campaignPagesWithHtml[currentIndex];

      try {
        // First strip HTML tags from all text content to ensure clean processing
        const processedBlocks = JSON.parse(JSON.stringify(page.blocks)); // Deep clone
        if (processedBlocks && Array.isArray(processedBlocks)) {
          for (const block of processedBlocks) {
            if (block.rich) {
              if (block.rich.content && Array.isArray(block.rich.content)) {
                for (const content of block.rich.content) {
                  if (content.text && typeof content.text === "string") {
                    content.text = stripHtmlTags(content.text);
                    console.log(`rich: ${content.text}`);
                  } else if (content.content && content.content[0]?.text) {
                    content.content[0].text = stripHtmlTags(
                      content.content[0].text,
                    );
                    console.log(`content.text: ${content.content[0].text}`);
                  }
                }
              }
            }
            if (block.plainText && typeof block.plainText === "string") {
              block.plainText = stripHtmlTags(block.plainText);
              // console.log(`plainText: ${block.plainText}`);
            }
          }
        }

        // Update page with extracted date, incremented session number, and calculated session date
        const updateData = {
          blocks: processedBlocks,
        };

        const updateOperation = await Page.findByIdAndUpdate(
          page._id,
          { $set: updateData },
          { new: true },
        );

        console.log(`Updated page ${page._id}:`, updateOperation);

        // Update reference page to the newly processed page for next iterations
      } catch (pageError) {
        console.error(`Error processing page ${page._id}:`, pageError);
      }

      currentIndex++;
    }

    res.json({ code: 200, message: "Campaign processed successfully" });
  } catch (error) {
    console.error("Error in process-campaign endpoint:", error);
    res.status(500).json({
      error: "Failed to process campaign pages",
      details: error.message,
    });
  }
});

/**
 * Extracts date from page content in format "28 Decimos 2130 I.E."
 *
 * Searches through rich text blocks and plainText fields for date patterns.
 * When found, extracts day, month (by name), year, and era abbreviation,
 * then maps them to the time system configuration.
 *
 * @param {Array} blocks - Page blocks containing text content
 * @returns {Object|null} Extracted worldDate object with eraId, year, monthIndex, day
 *                         or null if no date pattern is found
 */
function extractDateFromContent(blocks, tsConfig) {
  if (!blocks || !Array.isArray(blocks)) return null;

  // Regex to match date pattern: day month year era (e.g., "28 Decimos 2130 I.E.")
  const dateRegex = /(\d+)\s+([a-zA-Z]+)\s+(\d+)\s+([a-zA-Z.]+)/;

  // Search through all rich text blocks for date patterns
  for (const block of blocks) {
    if (block.type === "rich" && block.rich?.content) {
      for (const paragraph of block.rich.content) {
        if (paragraph.type === "paragraph" && paragraph.content) {
          for (const text of paragraph.content) {
            if (text.text && typeof text.text === "string") {
              // Look for date pattern: day month year era (e.g., "28 Decimos 2130 I.E.")
              // Same regex pattern as above to find date in plainText format
              const match = text.text.match(dateRegex);

              if (match) {
                // Extract components: day, month, year, era
                const [_, dayStr, monthName, yearStr, eraAbbr] = match;
                let _monthName = monthName;
                const day = parseInt(dayStr);
                const year = parseInt(yearStr);
                if (_monthName === "Decimos") {
                  _monthName = "Decis";
                } else if (_monthName === "Primus") {
                  _monthName = "Primos";
                }
                // Find month index by matching month name to time system configuration
                let monthIndex = null;
                if (tsConfig?.months) {
                  const month = tsConfig.months.find(
                    (m) => m.name.toLowerCase() === _monthName.toLowerCase(),
                  );
                  if (month) {
                    monthIndex = parseInt(month.id) - 1; // Convert to 0-based index
                  }
                }

                // Find era ID by matching era abbreviation to time system configuration
                let eraId = "2";

                return {
                  eraId,
                  year,
                  monthIndex,
                  day,
                };
              }
            }
          }
        }
      }
    }

    // Also check plainText field for date patterns if rich content doesn't contain a match
    if (block.plainText && typeof block.plainText === "string") {
      const match = block.plainText.match(dateRegex);

      if (match) {
        const [_, dayStr, monthName, yearStr, eraAbbr] = match;
        const day = parseInt(dayStr);
        const year = parseInt(yearStr);

        // Find month index from time system
        let monthIndex = null;
        if (tsConfig?.months) {
          const month = tsConfig.months.find(
            (m) => m.name.toLowerCase() === monthName.toLowerCase(),
          );
          if (month) {
            monthIndex = parseInt(month.id) - 1; // Convert to 0-based index
          }
        }

        // Find era ID from abbreviation
        let eraId = null;
        if (tsConfig?.eras) {
          const era = tsConfig.eras.find((e) => e.abbreviation === eraAbbr);
          if (era) {
            eraId = era.id;
          }
        }

        return {
          eraId,
          year,
          monthIndex,
          day,
        };
      }
    }
  }

  return null;
}
