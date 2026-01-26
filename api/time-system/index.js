import express from "express";
import { requireDM } from "../../middleware/auth.js";
import { TimeSystem } from "../../models.js";
import { defaultTimeSystem } from "../../utils/time.js";

// -----------------------------------------------------------------------------
// Time system
// -----------------------------------------------------------------------------
const router = express.Router();
// Retrieve the current time system configuration. If none exists, return a
// default minimal configuration so the frontend can still operate. The
// structure matches the TimeSystemConfig interface on the client.
router.get("/time-system", async (req, res) => {
  let ts = await TimeSystem.findOne();
  if (!ts) {
    // Provide a basic fallback if the DB is empty. This ensures that
    // first‑time setups still work without manual seeding.
    ts = defaultTimeSystem;
    await ts.save();
  }
  res.json(ts.config);
});

// Update the time system configuration. Only DM users can perform this
// operation. The client should send the full config object.
router.put("/time-system", requireDM, async (req, res) => {
  const { config } = req.body;
  if (!config) return res.status(400).json({ error: "config is required" });
  let ts = await TimeSystem.findOne();
  if (!ts) {
    ts = await TimeSystem.create({ config });
  } else {
    ts.config = config;
    await ts.save();
  }
  res.json(ts.config);
});

export default router;
