import { app, requireDM } from '../../server.js';
import { Group } from '../../models.js';

// -----------------------------------------------------------------------------
// Gruppi
// -----------------------------------------------------------------------------
app.get('/groups', async (req, res) => {
  let groups = await Group.find().sort({ order: 1 });
  // Ensure at least one defaultSelected group exists for clients that rely on a default
  if (!groups.some((g) => g.defaultSelected)) {
    const first = groups[0];
    if (first) {
      await Group.updateMany({}, { defaultSelected: false });
      await Group.findByIdAndUpdate(first._id, {
        defaultSelected: true,
      });
      groups = await Group.find().sort({ order: 1 });
    }
  }
  res.json(groups);
});

app.put('/groups', requireDM, async (req, res) => {
  const { newOrder } = req.body;
  await Promise.all(
    newOrder.map((id, index) =>
      Group.findByIdAndUpdate(id, { order: index })
    )
  );
  res.json({ success: true });
});

app.post('/groups', requireDM, async (req, res) => {
  const {
    name,
    color,
    exclude = false,
    orderAscending = true,
    defaultSelected = false,
  } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });
  const last = await Group.findOne().sort({ order: -1 });
  const newOrder = last ? last.order + 1 : 0;
  if (defaultSelected) {
    await Group.updateMany({}, { defaultSelected: false });
  }
  const group = await Group.create({
    name,
    order: newOrder,
    color,
    exclude,
    orderAscending,
    defaultSelected,
  });
  res.json(group);
});

app.put('/groups/:id', requireDM, async (req, res) => {
  const { id } = req.params;
  const {
    name,
    color,
    order,
    exclude,
    orderAscending,
    defaultSelected,
  } = req.body;
  console.log('Updating group:', id, name, color, exclude, orderAscending, defaultSelected);
  if (defaultSelected === true) {
    // Ensure only one default
    await Group.updateMany({ _id: { $ne: id } }, { defaultSelected: false });
  }

  const group = await Group.findByIdAndUpdate(
    id,
    {
      ...(name !== undefined ? { name } : {}),
      ...(color !== undefined ? { color } : {}),
      ...(order !== undefined ? { order } : {}),
      ...(exclude !== undefined ? { exclude } : {}),
      ...(orderAscending !== undefined ? { orderAscending } : {}),
      ...(defaultSelected !== undefined ? { defaultSelected } : {}),
    },
    { new: true }
  );
  if (!group) return res.status(404).json({ error: 'Group not found' });
  res.json(group);
});

// Delete a group and cascade delete its events. Requires DM role.
app.delete('/groups/:id', requireDM, async (req, res) => {
  const { id } = req.params;
  const group = await Group.findByIdAndDelete(id);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  // Remove events belonging to this group
  await Event.deleteMany({ groupId: id });
  res.json({ success: true });
});