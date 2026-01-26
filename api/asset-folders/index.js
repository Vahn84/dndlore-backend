import express from 'express';
import { requireDM } from '../../middleware/auth.js';
import { AssetFolder, Asset } from '../../models.js';

// -----------------------------------------------------------------------------
// Asset Folders
// -----------------------------------------------------------------------------
const router = express.Router();

// List all asset folders
router.get('/asset-folders', async (req, res) => {
  try {
    const folders = await AssetFolder.find().sort({ createdAt: -1 });
    res.json(folders);
  } catch (err) {
    console.error('GET /asset-folders failed', err);
    res.status(500).json({ error: 'Internal error' });
  }
});

// Create a new asset folder
router.post('/asset-folders', requireDM, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Folder name is required' });
    }

    const folder = await AssetFolder.create({ name: name.trim() });
    res.json(folder);
  } catch (err) {
    console.error('POST /asset-folders failed', err);
    res.status(500).json({ error: 'Internal error' });
  }
});

// Delete an asset folder (only if empty)
router.delete('/asset-folders/:id', requireDM, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if folder contains any assets
    const assetsInFolder = await Asset.countDocuments({ folderId: id });
    if (assetsInFolder > 0) {
      return res.status(400).json({
        error: 'Cannot delete folder with assets. Move or delete assets first.',
      });
    }

    const folder = await AssetFolder.findByIdAndDelete(id);
    if (!folder) return res.status(404).json({ error: 'Folder not found' });

    res.json({ success: true });
  } catch (err) {
    console.error('DELETE /asset-folders/:id failed', err);
    res.status(500).json({ error: 'Internal error' });
  }
});

export default router;
