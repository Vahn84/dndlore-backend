import express from "express";
import { requireDM } from "../../middleware/auth.js";
import { Page, Event, TimeSystem } from "../../models.js";
import { formatEventDate } from "../../utils/time.js";

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
  const lim = Math.min(100, Math.max(1, Number(limit) || 50));
  // Sort by order field first (ascending), then by updatedAt (descending) as fallback
  const pages = await Page.find(query).limit(lim).sort({ order: 1 });
  console.log("Pages fetched", pages);
  res.json(pages);
});

router.get("/pages/:id", async (req, res) => {
  const page = await Page.findById(req.params.id);
  if (!page) return res.status(404).json({ error: "Page not found" });
  res.json(page);
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

export default router;
