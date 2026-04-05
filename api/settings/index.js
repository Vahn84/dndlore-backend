import express from "express";
import { requireDM } from "../../middleware/auth.js";
import { AppSettings } from "../../models.js";

const router = express.Router();

const ALLOWED_FIELDS = ["systemPrompt", "temperature", "maxTokens", "model", "lightragMode", "discordForumChannelId"];

async function getOrCreate() {
  let doc = await AppSettings.findOne();
  if (!doc) doc = await AppSettings.create({});
  return doc;
}

router.get("/settings", async (req, res) => {
  try {
    const doc = await getOrCreate();
    res.json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.put("/settings", requireDM, async (req, res) => {
  try {
    const doc = await getOrCreate();
    for (const field of ALLOWED_FIELDS) {
      if (req.body[field] !== undefined) {
        doc[field] = req.body[field];
      }
    }
    await doc.save();
    res.json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
