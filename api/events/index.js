import express from "express";
import { requireDM } from "../../middleware/auth.js";
import { Event, Page } from "../../models.js";

// -----------------------------------------------------------------------------
// Eventi
// -----------------------------------------------------------------------------
const router = express.Router();

router.get("/events", async (req, res) => {
  const events = await Event.find().sort({ order: 1 });
  res.json(events);
});

router.put("/events/order", requireDM, async (req, res) => {
  const { newOrder } = req.body;
  await Promise.all(
    newOrder.map((id, index) => Event.findByIdAndUpdate(id, { order: index })),
  );
  res.json({ success: true });
});

router.post("/events", requireDM, async (req, res) => {
  const {
    title,
    type = "other",
    startDate,
    endDate,
    detailLevel,
    bannerUrl,
    groupId,
    startEraId,
    startYear,
    startMonthIndex,
    startDay,
    startHour,
    startMinute,
    endEraId,
    endYear,
    endMonthIndex,
    endDay,
    endHour,
    endMinute,
    pageId,
    hidden = false,
    color,
    icon,
  } = req.body;
  if (!title || !startDate || !groupId)
    return res
      .status(400)
      .json({ error: "title, startDate and groupId are required" });
  // Default linkSync to true when linking to a page
  const linkSync = req.body.linkSync !== undefined ? req.body.linkSync : !!pageId;

  const last = await Event.findOne().sort({ order: -1 });
  const order = last ? last.order + 1 : 0;

  // If linking with sync, hydrate fields from the page
  let syncedBannerUrl = bannerUrl;
  let syncedBannerThumbUrl;
  let syncedTitle = title;
  if (pageId && linkSync) {
    const page = await Page.findById(pageId);
    if (page) {
      if (page.title) syncedTitle = page.title;
      syncedBannerUrl = page.bannerUrl || syncedBannerUrl || "";
      syncedBannerThumbUrl = page.bannerThumbUrl || "";
    }
  }

  const event = await Event.create({
    title: syncedTitle,
    type,
    startDate,
    endDate,
    bannerUrl: syncedBannerUrl,
    bannerThumbUrl: syncedBannerThumbUrl,
    detailLevel,
    groupId,
    pageId,
    linkSync,
    hidden,
    order,
    color,
    startEraId,
    startYear,
    startMonthIndex,
    startDay,
    startHour,
    startMinute,
    endEraId,
    endYear,
    endMonthIndex,
    endDay,
    endHour,
    endMinute,
    icon,
  });
  res.json(event);
});

router.put("/events/:id", requireDM, async (req, res) => {
  const { id } = req.params;
  const update = {};
  // Allowed fields for update
  const fields = [
    "title",
    "type",
    "startDate",
    "endDate",
    "detailLevel",
    "bannerUrl",
    "bannerThumbUrl",
    "startEraId",
    "startYear",
    "startMonthIndex",
    "startDay",
    "startHour",
    "startMinute",
    "endEraId",
    "endYear",
    "endMonthIndex",
    "endDay",
    "endHour",
    "endMinute",
    "groupId",
    "pageId",
    "linkSync",
    "hidden",
    "color",
    "icon",
  ];
  fields.forEach((field) => {
    if (
      req.body[field] !== undefined ||
      field === "bannerUrl" ||
      field === "bannerThumbUrl"
    ) {
      update[field] = req.body[field];
      if (field === "bannerUrl" && !update[field]) {
        update[field] = "";
      }
    }
  });
  console.log("Event updated:", update);
  // If linking with sync enabled, optionally hydrate fields from page
  try {
    const evBefore = await Event.findById(id);
    const pageId =
      update.pageId !== undefined ? update.pageId : evBefore?.pageId;
    const linkSync =
      update.linkSync !== undefined ? update.linkSync : evBefore?.linkSync;
    if (pageId && linkSync) {
      const page = await Page.findById(pageId);
      if (page) {
        // Sync all three fields: title, banner, and world date
        if (page.title) update.title = page.title;
        update.bannerUrl = page.bannerUrl || "";
        update.bannerThumbUrl = page.bannerThumbUrl || "";
        const wd = page.worldDate;
        if (wd) {
          update.startEraId = wd.eraId ?? null;
          update.startYear = typeof wd.year === "number" ? wd.year : null;
          update.startMonthIndex =
            typeof wd.monthIndex === "number" ? wd.monthIndex : null;
          update.startDay = typeof wd.day === "number" ? wd.day : null;
        }
      }
    }
  } catch (e) {
    console.warn("Link/sync hydration failed:", e);
  }

  const event = await Event.findByIdAndUpdate(id, update, { new: true });
  if (!event) return res.status(404).json({ error: "Event not found" });
  res.json(event);
});

// Delete an event. Requires DM role.
router.delete("/events/:id", requireDM, async (req, res) => {
  const { id } = req.params;
  const event = await Event.findByIdAndDelete(id);
  if (!event) return res.status(404).json({ error: "Event not found" });
  res.json({ success: true });
});

export default router;
