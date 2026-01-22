import { app, requireExternal } from '../../server.js';

// -----------------------------------------------------------------------------
// External endpoints for automation
// -----------------------------------------------------------------------------
// Optional secret for external automation. Provide EXTERNAL_API_KEY in env to
// allow authorised scripts to create events and pages without a logged‑in DM.
const EXTERNAL_API_KEY = process.env.EXTERNAL_API_KEY;

function requireExternal(req, res, next) {
  if (!EXTERNAL_API_KEY)
    return res.status(403).json({ error: 'External API disabled' });
  const key = req.headers['x-api-key'];
  if (!key || key !== EXTERNAL_API_KEY)
    return res.status(403).json({ error: 'Invalid API key' });
  next();
}

// Create an event via external automation. Expects the same fields as /events.
app.post('/external/events', requireExternal, async (req, res) => {
  const {
    title,
    type = 'other',
    startDate,
    endDate,
    bannerUrl,
    groupId,
    pageId,
    hidden = false,
    color,
  } = req.body;
  if (!title || !startDate || !groupId)
    return res
      .status(400)
      .json({ error: 'title, startDate and groupId are required' });
  const last = await Event.findOne().sort({ order: -1 });
  const order = last ? last.order + 1 : 0;
  const event = await Event.create({
    title,
    type,
    startDate,
    endDate,
    bannerUrl,
    groupId,
    pageId,
    hidden,
    order,
    color,
  });
});

// Create a page via external automation. Expects title, type, bannerUrl, content, hidden, draft.
app.post('/external/pages', requireExternal, async (req, res) => {
  const {
    title,
    type,
    bannerUrl,
    content = [],
    hidden = false,
    draft = false,
  } = req.body;
  if (!title || !type)
    return res.status(400).json({ error: 'title and type are required' });
  const page = await Page.create({
    title,
    type,
    bannerUrl,
    content,
    hidden,
    draft,
  });
  res.json(page);
});