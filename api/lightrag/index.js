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
    if (result && result.status === "success") {
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
      throw new Error("Failed to save document to LightRag database");
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
    const deleted = await deleteDocument(page._id.toString());

    if (deleted) {
      // Clear the document name from the page
      page.lightRagDocumentName = undefined;
      await page.save();

      res.json({
        success: true,
        message: "Document deleted from LightRag successfully",
      });
    } else {
      res
        .status(500)
        .json({ error: "Failed to delete document from LightRag" });
    }
  } catch (error) {
    console.error("Error deleting document from LightRag:", error);
    res.status(500).json({ error: "Failed to delete document from LightRag" });
  }
});

export default router;
