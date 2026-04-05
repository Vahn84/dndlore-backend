import express from 'express';
import { Asset, Page, Event } from '../../models.js';
import { requireDM } from '../../middleware/auth.js';
import multer from 'multer';
import sharp from 'sharp';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { UPLOADS_PATH } from '../../utils/uploads.js';

const router = express.Router();

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_PATH),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const base = crypto.randomBytes(16).toString('hex');
    cb(null, ext ? `${base}${ext}` : base);
  },
});
const upload = multer({ storage });

// -----------------------------------------------------------------------------
// Asset library (Asset Manager)
// -----------------------------------------------------------------------------
// List assets (no auth required to read; adjust to your needs)
router.get('/assets', async (req, res) => {
  try {
    const assets = await Asset.find().sort({ createdAt: -1 });
    res.json(assets);
  } catch (err) {
    console.error('GET /assets failed', err);
    res.status(500).json({ error: 'Internal error' });
  }
});

// Create an asset. Accepts either a multipart file field named `file` or a JSON body with { url }
router.post('/assets', requireDM, upload.single('file'), async (req, res) => {
  try {
    let url = null;
    let bannerThumbUrl = null;
    const folderId =
      req.body && req.body.folderId ? req.body.folderId || null : null;

    if (req.file) {
      url = `/uploads/${req.file.filename}`;

      // Generate thumbnail for uploaded images
      try {
        const ext = path.extname(req.file.filename).toLowerCase();
        const isImage = ['.jpg', '.jpeg', '.png', '.webp', '.gif', '.bmp', '.tiff'].includes(ext)
          || (req.file.mimetype || '').startsWith('image/');

        if (isImage) {
          const thumbFilename = `thumb-${req.file.filename}`;
          const thumbPath = path.join(UPLOADS_PATH, thumbFilename);

          await sharp(req.file.path)
            .resize(800, null, {
              withoutEnlargement: true,
              fit: 'inside',
            })
            .toFile(thumbPath);

          bannerThumbUrl = `/uploads/${thumbFilename}`;
        }
      } catch (err) {
        console.warn('Thumbnail generation failed:', err);
      }
    } else if (req.body && req.body.url) {
      url = req.body.url;
      // For external URLs, no thumbnail is generated
    }

    if (!url)
      return res.status(400).json({ error: 'file or url is required' });

    const asset = await Asset.create({
      url,
      thumb_url: bannerThumbUrl,
      folderId,
    });
    res.json(asset);
  } catch (err) {
    console.error('POST /assets failed', err);
    res.status(500).json({ error: 'Internal error' });
  }
});

// Delete an asset (and remove underlying file if it is in our uploads folder)
router.delete('/assets/:id', requireDM, async (req, res) => {
  try {
    const { id } = req.params;
    const asset = await Asset.findByIdAndDelete(id);
    if (!asset) return res.status(404).json({ error: 'Asset not found' });

    // Clear references to this asset in Events and Pages
    const assetUrl = asset.url;
    const thumbUrl = asset.thumb_url;

    // Build a list of non-null URLs belonging to this asset
    const assetUrls = [assetUrl, thumbUrl].filter(Boolean);

    if (assetUrls.length > 0) {
      const urlFilter = { $in: assetUrls };

      // Update Events that reference this asset's URL or thumbnail
      await Event.updateMany(
        { $or: [{ bannerUrl: urlFilter }, { bannerThumbUrl: urlFilter }] },
        { $set: { bannerUrl: null, bannerThumbUrl: null } }
      );

      // Update Pages that reference this asset's URL or thumbnail
      await Page.updateMany(
        { $or: [{ bannerUrl: urlFilter }, { bannerThumbUrl: urlFilter }] },
        { $set: { bannerUrl: null, bannerThumbUrl: null } }
      );

      // Clear references in Page blocks (image blocks with url field)
      await Page.updateMany(
        { 'blocks.url': urlFilter },
        { $set: { 'blocks.$[elem].url': null } },
        { arrayFilters: [{ 'elem.url': urlFilter }] }
      );
    }

    // Attempt to unlink local file if served from /uploads
    if (asset.url && asset.url.startsWith('/uploads/')) {
      try {
        const p = path.join(UPLOADS_PATH, path.basename(asset.url));
        fs.unlink(p, () => {});
      } catch (e) {
        // ignore unlink errors
      }
    }

    // Also remove thumbnail file if it exists
    if (asset.thumb_url && asset.thumb_url.startsWith('/uploads/')) {
      try {
        const p = path.join(
          UPLOADS_PATH,
          path.basename(asset.thumb_url)
        );
        fs.unlink(p, () => {});
      } catch (e) {
        // ignore unlink errors
      }
    }

    res.json({ success: true });
  } catch (err) {
    console.error('DELETE /assets/:id failed', err);
    res.status(500).json({ error: 'Internal error' });
  }
});

// Update asset folder location
router.patch('/assets/:id/move', requireDM, async (req, res) => {
  try {
    const { id } = req.params;
    const { folderId } = req.body; // can be null to move to root

    const asset = await Asset.findByIdAndUpdate(
      id,
      { folderId: folderId || null },
      { new: true }
    );

    if (!asset) return res.status(404).json({ error: 'Asset not found' });

    res.json(asset);
  } catch (err) {
    console.error('PATCH /assets/:id/move failed', err);
    res.status(500).json({ error: 'Internal error' });
  }
});
export default router;
