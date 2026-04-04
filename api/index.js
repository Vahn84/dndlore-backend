import express from "express";
import assetFoldersRouter from "./asset-folders/index.js";
import assetsRouter from "./assets/index.js";
import authRouter from "./auth/index.js";
import discordRouter from "./discord/index.js";
import eventsRouter from "./events/index.js";
import externalRouter from "./external/index.js";
import groupsRouter from "./groups/index.js";
import pagesRouter from "./pages/index.js";
import syncRouter from "./sync/index.js";
import timeSystemRouter from "./time-system/index.js";
import lightRagRouter from "./lightrag/index.js";
import settingsRouter from "./settings/index.js";
// Removed circular import of the Express app – this file now only builds and exports a router.

const router = express.Router();
// Mount sub‑routers directly – each router already defines its own path (e.g., "/pages"), so we mount without an extra prefix.
router.use(authRouter);
router.use(assetFoldersRouter);
router.use(discordRouter);
router.use(eventsRouter);
router.use(externalRouter);
router.use(assetsRouter);
router.use(groupsRouter);
router.use(pagesRouter);
router.use(syncRouter);
router.use(timeSystemRouter);
router.use(lightRagRouter);
router.use(settingsRouter);
export default router;
