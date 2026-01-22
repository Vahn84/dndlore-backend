import { app, requireDM } from '../../server.js';
import { TimeSystem } from '../../models.js';

// -----------------------------------------------------------------------------
// Time system
// -----------------------------------------------------------------------------
// Retrieve the current time system configuration. If none exists, return a
// default minimal configuration so the frontend can still operate. The
// structure matches the TimeSystemConfig interface on the client.
app.get('/time-system', async (req, res) => {
  let ts = await TimeSystem.findOne();
  if (!ts) {
    // Provide a basic fallback if the DB is empty. This ensures that
    // first‑time setups still work without manual seeding.
    ts = new TimeSystem({
      config: {
        name: 'Alesar',
        months: [
          { id: '1', name: 'Primos', days: 30 },
          { id: '2', name: 'Secondis', days: 30 },
          { id: '3', name: 'Terzios', days: 30 },
          { id: '4', name: 'Quartis', days: 30 },
          { id: '5', name: 'Quintes', days: 30 },
          { id: '6', name: 'Sixtes', days: 30 },
          { id: '7', name: 'Septis', days: 30 },
          { id: '8', name: 'Octis', days: 30 },
          { id: '9', name: 'Nines', days: 30 },
          { id: '10', name: 'Decis', days: 30 },
        ],
        weekdays: [
          { id: '1', name: 'Lunes' },
          { id: '2', name: 'Martes' },
          { id: '3', name: 'Mercos' },
          { id: '4', name: 'Giovis' },
          { id: '5', name: 'Venis' },
          { id: '6', name: 'Sabes' },
          { id: '7', name: 'Domes' },
        ],
        eras: [
          {
            id: '1',
            abbreviation: 'DE',
            name: 'Divine Era',
            startYear: 10000,
            backward: true,
          },
          {
            id: '2',
            abbreviation: 'IE',
            name: 'Immortals Era',
            startYear: 0,
            backward: false,
          },
        ],
        hoursPerDay: 24,
        minutesPerHour: 60,
        epochWeekday: 0,
        weekdaysResetEachMonth: false,
        erasStartOnZeroYear: false,
        dateFormats: {
          year: 'YYYY, E',
          yearMonth: 'MMMM YYYY, E',
          yearMonthDay: 'D^ MMMM YYYY, E',
          yearMonthDayTime: 'D^ MMMM YYYY, HH:mm, E',
        },
      },
    });
    await ts.save();
  }
  res.json(ts.config);
});

// Update the time system configuration. Only DM users can perform this
// operation. The client should send the full config object.
app.put('/time-system', requireDM, async (req, res) => {
  const { config } = req.body;
  if (!config) return res.status(400).json({ error: 'config is required' });
  let ts = await TimeSystem.findOne();
  if (!ts) {
    ts = await TimeSystem.create({ config });
  } else {
    ts.config = config;
    await ts.save();
  }
  res.json(ts.config);
});