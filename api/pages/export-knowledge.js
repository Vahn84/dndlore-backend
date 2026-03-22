import express from "express";
import { requireDM } from "../../middleware/auth.js";
import { Page } from "../../models.js";
import { TimeSystem } from "../../models.js";
import { generateMarkdownContent, generateFilename } from "../../utils/markdown.js";
import {
  uploadFile,
  addFileToKnowledge,
  getFileIdInKnowledge,
  updateFileInKnowledge,
  deleteFile,
  deleteAllFilesFromKnowledge,
} from "../../utils/owui.js";

const router = express.Router();

router.post("/export-to-knowledge", requireDM, async (req, res) => {
  try {
    const { mode, knowledgeId: overrideKnowledgeId } = req.body;

    if (!mode || !["all", "individual", "delete"].includes(mode)) {
      return res
        .status(400)
        .json({ error: "Invalid mode. Use 'all', 'individual', or 'delete'." });
    }

    const knowledgeId =
      overrideKnowledgeId || process.env.OWUI_KNOWLEDGE_ID;

    if (mode === "delete") {
      if (!knowledgeId) {
        return res.status(400).json({
          error: "OWUI_KNOWLEDGE_ID environment variable not set",
        });
      }

      await deleteAllFilesFromKnowledge(knowledgeId);

      await Page.updateMany({}, { $set: { owuiFileId: null } });

      return res.json({
        success: true,
        mode: "delete",
        message: "All files deleted from knowledge base",
      });
    }

    const ts = await TimeSystem.findOne();
    const tsConfig = ts?.config || null;

    if (mode === "all") {
      const pages = await Page.find({
        draft: false,
        hidden: false,
      });

      const allMarkdown = pages
        .map((page) => generateMarkdownContent(page, tsConfig))
        .join("\n\n---\n\n");

      const filename = `dndlore-knowledge-base-${new Date()
        .toISOString()
        .split("T")[0]}.md`;

      const uploadResult = await uploadFile(allMarkdown, filename);
      const fileId = uploadResult.id || uploadResult._id;

      if (knowledgeId) {
        await addFileToKnowledge(knowledgeId, fileId);
      }

      return res.json({
        success: true,
        mode: "all",
        total: pages.length,
        filename,
        fileId,
        knowledgeId,
      });
    }

    if (mode === "individual") {
      if (!knowledgeId) {
        return res.status(400).json({
          error: "OWUI_KNOWLEDGE_ID environment variable not set",
        });
      }

      const pages = await Page.find({
        draft: false,
        hidden: false,
      });

      const uploaded = [];
      const failed = [];

      for (const page of pages) {
        try {
          const markdown = generateMarkdownContent(page, tsConfig);
          const filename = generateFilename(page, tsConfig);

          let fileId = page.owuiFileId;
          let action = "upload";

          if (fileId) {
            const existingFileId = await getFileIdInKnowledge(
              knowledgeId,
              filename
            );

            if (existingFileId) {
              fileId = existingFileId;
              action = "update";

              const updateResult = await updateFileInKnowledge(
                knowledgeId,
                fileId,
                markdown,
                filename
              );

              fileId = updateResult.fileId;
            } else {
              action = "upload";
              fileId = null;
            }
          }

          if (!fileId) {
            const uploadResult = await uploadFile(markdown, filename);
            fileId = uploadResult.id || uploadResult._id;

            await addFileToKnowledge(knowledgeId, fileId);
          }

          await Page.findByIdAndUpdate(page._id, { owuiFileId: fileId });

          uploaded.push({
            pageId: page._id.toString(),
            fileName: filename,
            fileId,
            title: page.title,
            action,
          });
        } catch (pageError) {
          console.error(`Failed to process page ${page._id}:`, pageError);
          failed.push({
            pageId: page._id.toString(),
            title: page.title,
            error: pageError.message,
          });
        }
      }

      return res.json({
        success: true,
        mode: "individual",
        total: pages.length,
        uploaded: uploaded.length,
        failed: failed.length,
        uploaded,
        failed,
      });
    }

    return res.status(400).json({ error: "Invalid mode specified" });
  } catch (error) {
    console.error("Export to knowledge error:", error);
    return res.status(500).json({
      error: "Failed to export pages to knowledge base",
      details: error.message,
    });
  }
});

// POST /api/pages/:id/sync-to-owui
// Sync single page to OWUI knowledge base
router.post("/pages/:id/sync-to-owui", requireDM, async (req, res) => {
  try {
    const { id } = req.params;
    const { knowledgeId: overrideKnowledgeId } = req.body;

    const page = await Page.findById(id);
    if (!page) {
      return res.status(404).json({ error: "Page not found" });
    }

    const knowledgeId = overrideKnowledgeId || process.env.OWUI_KNOWLEDGE_ID;
    if (!knowledgeId) {
      return res.status(400).json({ error: "OWUI_KNOWLEDGE_ID not set" });
    }

    const ts = await TimeSystem.findOne();
    const tsConfig = ts?.config || null;

    const markdown = generateMarkdownContent(page, tsConfig);
    const filename = generateFilename(page, tsConfig);

    let fileId = page.owuiFileId;
    let action = "upload";

    if (fileId) {
      try {
        action = "update";
        const uploadResult = await uploadFile(markdown, filename);
        fileId = uploadResult.id || uploadResult._id;
        await addFileToKnowledge(knowledgeId, fileId);
      } catch (error) {
        console.error("Error uploading file:", error.message);
        throw error;
      }
    } else {
      const uploadResult = await uploadFile(markdown, filename);
      fileId = uploadResult.id || uploadResult._id;
      await addFileToKnowledge(knowledgeId, fileId);
    }

    const updatedPage = await Page.findByIdAndUpdate(
      id,
      { owuiFileId: fileId },
      { new: true }
    );

    res.json({
      success: true,
      owuiFileId: fileId,
      fileName: filename,
      action,
    });
  } catch (error) {
    console.error("Sync to OWUI error:", error);
    
    let errorMessage = "Failed to sync page to knowledge base";
    let errorDetails = error.message;
    
    if (error.response?.data?.detail) {
      errorDetails = error.response.data.detail;
      
      if (typeof error.response.data.detail === 'string' && 
          error.response.data.detail.includes('Duplicate content')) {
        errorMessage = "Content unchanged in OWUI - no changes detected";
      }
    }
    
    return res.status(error.response?.status || 500).json({
      error: errorMessage,
      details: errorDetails,
    });
  }
});

export default router;
