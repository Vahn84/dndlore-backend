import express from "express";
import { requireDM } from "../../middleware/auth.js";
import { Page } from "../../models.js";
import { sendToLightRag, deleteDocument } from "../../utils/lightRag.js";

const router = express.Router();

// Endpoint to save a page to LightRag
router.post("/pages/:id/lightrag", requireDM, async (req, res) => {
  try {
    const { id } = req.params;

    // Save to LightRag
    const page = await Page.findById(id);
    if (!page) return res.status(404).json({ error: "Page not found" });
    const result = await sendToLightRag(page);
    if (!result) {
      return res.status(400).json({ error: "Page has no content to sync" });
    }
    if (result.status === "error") {
      return res.status(500).json({ error: result.message || "LightRAG upload failed" });
    }
    if (result.status === "success" || result.status === "duplicated") {
      // Update the page with the document name (file_source)
      const update = {};
      update.lightRagDocumentName = result.fileSource;

      const updateOperation = {};
      if (Object.keys(update).length > 0) {
        updateOperation.$set = update;
      }

      const page = await Page.findByIdAndUpdate(id, updateOperation, {
        new: true,
      });
      if (!page) return res.status(404).json({ error: "Page not found" });

      res.json(page);
    } else {
      return res.status(500).json({ error: "Unexpected LightRAG response status: " + result?.status });
    }
  } catch (error) {
    console.error("Error saving document to LightRag:", error);
    res
      .status(500)
      .json({ error: `Failed to save document to LightRag: ${error.message}` });
  }
});

// Endpoint to delete a document from LightRag
router.delete("/pages/:id/lightrag", requireDM, async (req, res) => {
  try {
    const { id } = req.params;

    // Find the page to get its document name
    const page = await Page.findById(id);
    if (!page) {
      return res.status(404).json({ error: "Page not found" });
    }

    // If no document name exists, nothing to delete
    if (!page.lightRagDocumentName) {
      return res.json({
        success: true,
        message: "No LightRag document found to delete",
      });
    }

    // Delete from LightRag
    const deleted = await deleteDocument(page.lightRagDocumentName);

    if (deleted) {
      page.lightRagDocumentName = undefined;
      await page.save();
      res.json({ success: true, message: "Document deleted from LightRAG successfully" });
    } else {
      // Document not found in LightRAG — stale reference, clean it up
      page.lightRagDocumentName = undefined;
      await page.save();
      res.json({ success: true, warning: "Document not found in LightRAG — stale reference removed. You can now re-sync the page." });
    }
  } catch (error) {
    console.error("Error deleting document from LightRag:", error);
    res.status(500).json({ error: "Failed to delete document from LightRag" });
  }
});

// Batch sync all unsynced pages of a given type to LightRag
router.post("/pages/batch-lightrag", requireDM, async (req, res) => {
  const { type } = req.body;
  if (!type) return res.status(400).json({ error: "type is required" });

  try {
    const pages = await Page.find({
      type,
      hidden: { $ne: true },
      lightRagDocumentName: { $in: [null, undefined, ""] },
    });

    const total = pages.length;
    const synced = [];
    const failed = [];

    for (const page of pages) {
      try {
        const result = await sendToLightRag(page);
        if (result && result.status === "success") {
          await Page.findByIdAndUpdate(page._id, {
            $set: { lightRagDocumentName: result.fileSource },
          });
          synced.push({ id: page._id, title: page.title });
        } else {
          failed.push({ id: page._id, title: page.title, reason: result?.message || "Unknown error" });
        }
      } catch (err) {
        failed.push({ id: page._id, title: page.title, reason: err.message });
      }
    }

    res.json({ total, synced: synced.length, failed: failed.length, failedPages: failed });
  } catch (error) {
    console.error("Batch LightRag sync failed:", error);
    res.status(500).json({ error: `Batch sync failed: ${error.message}` });
  }
});

// Proxy LightRAG pipeline status
router.get("/lightrag/pipeline-status", requireDM, async (req, res) => {
  const endpoint = process.env.LIGHTRAG_ENDPOINT;
  const apiKey = process.env.LIGHTRAG_API_KEY;
  if (!endpoint || !apiKey) {
    return res.status(503).json({ error: "LightRAG not configured" });
  }
  try {
    const headers = { "X-API-Key": apiKey };

    const [pipelineRes, countsRes] = await Promise.all([
      fetch(`${endpoint}/documents/pipeline_status`, { headers }),
      fetch(`${endpoint}/documents/status_counts`, { headers }),
    ]);

    if (!pipelineRes.ok) {
      return res.status(pipelineRes.status).json({ error: "LightRAG pipeline status unavailable" });
    }

    const pipeline = await pipelineRes.json();
    const busy = pipeline.busy ?? false;

    let pending = 0, inProgress = 0, done = 0, failed = 0;
    if (countsRes.ok) {
      const countsData = await countsRes.json();
      const counts = countsData.status_counts ?? {};
      pending = counts.pending ?? counts.PENDING ?? 0;
      inProgress = counts.processing ?? counts.PROCESSING ?? 0;
      done = counts.processed ?? counts.PROCESSED ?? 0;
      failed = counts.failed ?? counts.FAILED ?? 0;
    }

    // status_counts only reflects document intake, not KG pipeline work.
    // When the pipeline is busy but counts are all zero, fall back to
    // pipeline_status batch progress for meaningful numbers.
    if (busy && pending === 0 && inProgress === 0 && done === 0) {
      const totalBatches = pipeline.batchs ?? 0;
      const curBatch = pipeline.cur_batch ?? 0;
      done = curBatch;
      pending = Math.max(0, totalBatches - curBatch);
      inProgress = busy && totalBatches > 0 ? 1 : 0;
    }

    return res.json({ busy, request_pending: pending, request_in_progress: inProgress, request_done: done, request_failed: failed });
  } catch (error) {
    res.status(503).json({ error: "Could not reach LightRAG" });
  }
});

// List pages whose LightRAG document failed processing
router.get("/lightrag/failed-documents", requireDM, async (req, res) => {
  const endpoint = process.env.LIGHTRAG_ENDPOINT;
  const apiKey = process.env.LIGHTRAG_API_KEY;
  if (!endpoint || !apiKey) {
    return res.status(503).json({ error: "LightRAG not configured" });
  }
  try {
    const response = await fetch(`${endpoint}/documents`, {
      headers: { "X-API-Key": apiKey },
    });
    if (!response.ok) {
      return res.status(response.status).json({ error: "Could not fetch LightRAG documents" });
    }
    const data = await response.json();

    // Handle different response shapes from LightRAG (keys may be lowercase or uppercase)
    let failedDocs = [];
    const statuses = data?.statuses ?? {};
    const failedBucket = statuses.failed ?? statuses.FAILED;
    if (Array.isArray(failedBucket)) {
      failedDocs = failedBucket;
    } else {
      const all = Array.isArray(data?.documents) ? data.documents
        : Array.isArray(data) ? data : [];
      failedDocs = all.filter((d) => d.status?.toLowerCase() === "failed");
    }

    if (failedDocs.length === 0) return res.json({ failed: [] });

    // Cross-reference with MongoDB pages by lightRagDocumentName ↔ file_path
    const filePaths = failedDocs.map((d) => d.file_path).filter(Boolean);
    const pages = await Page.find(
      { lightRagDocumentName: { $in: filePaths } },
      { _id: 1, title: 1, type: 1, lightRagDocumentName: 1 }
    ).lean();
    const pageMap = new Map(pages.map((p) => [p.lightRagDocumentName, p]));

    const failed = failedDocs.map((doc) => {
      const page = pageMap.get(doc.file_path);
      return {
        filePath: doc.file_path,
        error: doc.error ?? null,
        pageId: page?._id ?? null,
        title: page?.title ?? doc.file_path,
        type: page?.type ?? null,
      };
    });

    res.json({ failed });
  } catch (error) {
    res.status(503).json({ error: "Could not reach LightRAG" });
  }
});

export default router;
