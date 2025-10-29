import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import session from 'express-session';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import mongoose from 'mongoose';
import { User, Group, Page, Event, TimeSystem, Asset } from './models.js';

// Carica variabili d'ambiente con valori di default
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:3000';
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3001;
const SESSION_SECRET = process.env.SESSION_SECRET || 'supersecret';
const JWT_SECRET = process.env.JWT_SECRET || 'jwtsecret';

// Connessione a MongoDB
const MONGO_URI =
	process.env.MONGO_URI ||
	'mongodb+srv://fabiocingolani84_db_user:J4myJn6z59xHGXc@dndlore.njjnky5.mongodb.net/data?appName=DndLore';
mongoose
	.connect(MONGO_URI)
	.then(() => console.log('Connected to MongoDB'))
	.catch((err) => console.error('MongoDB connection error', err));

const app = express();

// Abilita CORS
app.use(
	cors({
		origin: FRONTEND_ORIGIN,
		credentials: true,
	})
);
app.use(bodyParser.json());

// Configurazione sessione (necessaria per Passport)
app.use(
	session({
		secret: SESSION_SECRET,
		resave: false,
		saveUninitialized: false,
		cookie: {
			httpOnly: true,
			secure: process.env.NODE_ENV === 'production',
			maxAge: 24 * 60 * 60 * 1000,
			sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
		},
	})
);

// Inizializza Passport
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
	done(null, user);
});
passport.deserializeUser((user, done) => {
	done(null, user);
});

// Configura strategia Google OAuth2 se credenziali presenti
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_CALLBACK_URL =
	process.env.GOOGLE_CALLBACK_URL ||
	`http://localhost:${PORT}/auth/google/callback`;
console.log('GOOGLE_CLIENT_ID:', GOOGLE_CLIENT_ID);
console.log('GOOGLE_CLIENT_SECRET:', GOOGLE_CLIENT_SECRET);
if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
	passport.use(
		new GoogleStrategy(
			{
				clientID: GOOGLE_CLIENT_ID,
				clientSecret: GOOGLE_CLIENT_SECRET,
				callbackURL: GOOGLE_CALLBACK_URL,
			},
			async (accessToken, refreshToken, profile, done) => {
				console.log(
					'Google OAuth2 callback',
					accessToken,
					refreshToken,
					profile
				);
				try {
					const email =
						profile.emails &&
						profile.emails[0] &&
						profile.emails[0].value;
					let user = await User.findOne({ email });
					if (user) {
						console.log('User found:', user);
						return done(null, user);
					} else {
						return done(err, null);
					}
				} catch (err) {
					return done(err, null);
				}
			}
		)
	);
}

// Gestione uploads
const UPLOADS_PATH = process.env.UPLOADS_PATH || path.resolve('.', 'uploads');
fs.mkdirSync(UPLOADS_PATH, { recursive: true });
app.use('/uploads', express.static(UPLOADS_PATH));

const storage = multer.diskStorage({
	destination: (req, file, cb) => cb(null, UPLOADS_PATH),
	filename: (req, file, cb) => {
		const timestamp = Date.now();
		const sanitized = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
		cb(null, `${timestamp}-${sanitized}`);
	},
});
const upload = multer({ storage });

// Middleware per autenticazione JWT
function requireAuth(req, res, next) {
	const authHeader = req.headers.authorization;
	if (!authHeader)
		return res.status(401).json({ error: 'Missing Authorization header' });
	const token = authHeader.split(' ')[1];
	try {
		const decoded = jwt.verify(token, JWT_SECRET);
		req.user = decoded;
		next();
	} catch (err) {
		return res.status(401).json({ error: 'Invalid or expired token' });
	}
}

// Middleware per richiedere il ruolo DM
function requireDM(req, res, next) {
	requireAuth(req, res, () => {
		if (!req.user || req.user.role !== 'DM') {
			return res
				.status(403)
				.json({ error: 'Forbidden: DM role required' });
		}
		next();
	});
}

// Endpoint login locale
app.post('/login', async (req, res) => {
	const { username, password } = req.body;
	const user = await User.findOne({ username, password });
	if (!user) return res.status(401).json({ error: 'Invalid credentials' });
	const token = jwt.sign(
		{ id: user._id, username: user.username, role: user.role },
		JWT_SECRET,
		{ expiresIn: '1d' }
	);
	res.json({
		token,
		user: { id: user._id, username: user.username, role: user.role },
	});
});

// OAuth2 endpoints
app.get(
	'/auth/google',
	passport.authenticate('google', { scope: ['profile', 'email'] })
);
app.get(
	'/auth/google/callback',
	passport.authenticate('google', { failureRedirect: '/' }),
	(req, res) => {
		const user = req.user;
		const token = jwt.sign(
			{ id: user._id, username: user.username, role: user.role },
			JWT_SECRET,
			{ expiresIn: '1d' }
		);
		res.redirect(`${FRONTEND_ORIGIN}?token=${token}`);
	}
);

// Endpoint per ottenere l'utente corrente
app.get('/auth/user', (req, res) => {
	const authHeader = req.headers.authorization;
	if (!authHeader) return res.json(null);
	const token = authHeader.split(' ')[1];
	try {
		const decoded = jwt.verify(token, JWT_SECRET);
		res.json(decoded);
	} catch (err) {
		res.status(401).json({ error: 'Invalid token' });
	}
});

// Logout
app.post('/auth/logout', (req, res) => {
	req.logout && req.logout();
	res.json({ success: true });
});

// -----------------------------------------------------------------------------
// Gruppi
// -----------------------------------------------------------------------------
app.get('/groups', async (req, res) => {
	const groups = await Group.find().sort({ order: 1 });
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
	const { name } = req.body;
	if (!name) return res.status(400).json({ error: 'name is required' });
	const last = await Group.findOne().sort({ order: -1 });
	const newOrder = last ? last.order + 1 : 0;
	const group = await Group.create({ name, order: newOrder });
	res.json(group);
});

app.put('/groups/:id', requireDM, async (req, res) => {
	const { id } = req.params;
	const { name, color } = req.body;
	console.log('Updating group:', id, name, color);
	const group = await Group.findByIdAndUpdate(
		id,
		{ name, color },
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

// -----------------------------------------------------------------------------
// Eventi
// -----------------------------------------------------------------------------
app.get('/events', async (req, res) => {
	console.log('MONGO URI:', MONGO_URI);
	const events = await Event.find().sort({ order: 1 });
	res.json(events);
});

app.put('/events/order', requireDM, async (req, res) => {
	const { newOrder } = req.body;
	await Promise.all(
		newOrder.map((id, index) =>
			Event.findByIdAndUpdate(id, { order: index })
		)
	);
	res.json({ success: true });
});

app.post('/events', requireDM, async (req, res) => {
	const {
		title,
		type = 'other',
		startDate,
		endDate,
		detailLevel,
		bannerUrl,
		groupId,
		startEraId,
		startYear,
		startMonthIndex,
		startDay,
		endEraId,
		endYear,
		endMonthIndex,
		endDay,
		pageId,
		hidden = false,
		color,
		icon,
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
		detailLevel,
		groupId,
		pageId,
		hidden,
		order,
		color,
		startEraId,
		startYear,
		startMonthIndex,
		startDay,
		endEraId,
		endYear,
		endMonthIndex,
		endDay,
		icon,
	});
	res.json(event);
});

app.put('/events/:id', requireDM, async (req, res) => {
	const { id } = req.params;
	const update = {};
	// Allowed fields for update
	const fields = [
		'title',
		'type',
		'startDate',
		'endDate',
		'detailLevel',
		'bannerUrl',
		'startEraId',
		'startYear',
		'startMonthIndex',
		'startDay',
		'endEraId',
		'endYear',
		'endMonthIndex',
		'endDay',
		'groupId',
		'pageId',
		'order',
		'hidden',
		'color',
		'icon',
	];
	fields.forEach((field) => {
		if (req.body[field] !== undefined || field === 'bannerUrl') {
			update[field] = req.body[field];
			if (field === 'bannerUrl' && !update[field]) {
				update[field] = '';
			}
		}
	});
	console.log('Event updated:', update);
	const event = await Event.findByIdAndUpdate(id, update, { new: true });
	if (!event) return res.status(404).json({ error: 'Event not found' });
	res.json(event);
});

// Delete an event. Requires DM role.
app.delete('/events/:id', requireDM, async (req, res) => {
	const { id } = req.params;
	const event = await Event.findByIdAndDelete(id);
	if (!event) return res.status(404).json({ error: 'Event not found' });
	res.json({ success: true });
});

// -----------------------------------------------------------------------------
// Pagine
// -----------------------------------------------------------------------------
app.get('/pages', async (req, res) => {
	const { type } = req.query;
	const query = {};
	if (type) {
		query.type = type;
	}
	const pages = await Page.find(query);
	res.json(pages);
});

app.get('/pages/:id', async (req, res) => {
	const page = await Page.findById(req.params.id);
	if (!page) return res.status(404).json({ error: 'Page not found' });
	res.json(page);
});

app.post('/pages', requireDM, async (req, res) => {
	const {
		title,
		type,
		bannerUrl,
		content = [],
		hidden = false,
		hiddenSections = [],
		draft = false,
	} = req.body;
	if (!title) return res.status(400).json({ error: 'title is required' });
	if (!type) return res.status(400).json({ error: 'type is required' });
	const page = await Page.create({
		title,
		type,
		bannerUrl,
		content,
		hidden,
		hiddenSections,
		draft,
	});
	res.json(page);
});

app.put('/pages/:id', requireDM, async (req, res) => {
	const { id } = req.params;
	const update = {};
	const fields = [
		'title',
		'type',
		'bannerUrl',
		'content',
		'hidden',
		'hiddenSections',
		'draft',
	];
	fields.forEach((field) => {
		if (req.body[field] !== undefined) update[field] = req.body[field];
	});
	const page = await Page.findByIdAndUpdate(id, update, { new: true });
	if (!page) return res.status(404).json({ error: 'Page not found' });
	res.json(page);
});

// Delete a page. Requires DM role. Also clear pageId on events referencing this page.
app.delete('/pages/:id', requireDM, async (req, res) => {
	const { id } = req.params;
	const page = await Page.findByIdAndDelete(id);
	if (!page) return res.status(404).json({ error: 'Page not found' });
	// Unlink events referencing this page
	await Event.updateMany({ pageId: id }, { $unset: { pageId: '' } });
	res.json({ success: true });
});

// -----------------------------------------------------------------------------
// Upload immagine
// -----------------------------------------------------------------------------
app.post('/upload', requireDM, upload.single('file'), (req, res) => {
	const file = req.file;
	if (!file) return res.status(400).json({ error: 'No file uploaded' });
	const url = `/uploads/${file.filename}`;
	res.json({ url });
});

// Avvio server
app.listen(PORT, () => {
	console.log(`Backend listening on port ${PORT}`);
});

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
					},
					{
						id: '2',
						abbreviation: 'IE',
						name: 'Immortals Era',
						startYear: 0,
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

// -----------------------------------------------------------------------------
// Asset library (Asset Manager)
// -----------------------------------------------------------------------------
// List assets (no auth required to read; adjust to your needs)
app.get('/assets', async (req, res) => {
	try {
		const assets = await Asset.find().sort({ createdAt: -1 });
		res.json(assets);
	} catch (err) {
		console.error('GET /assets failed', err);
		res.status(500).json({ error: 'Internal error' });
	}
});

// Create an asset. Accepts either a multipart file field named `file` or a JSON body with { url }
app.post('/assets', requireDM, upload.single('file'), async (req, res) => {
	try {
		let url = null;
		if (req.file) {
			url = `/uploads/${req.file.filename}`;
		} else if (req.body && req.body.url) {
			url = req.body.url;
		}
		if (!url)
			return res.status(400).json({ error: 'file or url is required' });
		const asset = await Asset.create({ url });
		res.json(asset);
	} catch (err) {
		console.error('POST /assets failed', err);
		res.status(500).json({ error: 'Internal error' });
	}
});

// Delete an asset (and remove underlying file if it is in our uploads folder)
app.delete('/assets/:id', requireDM, async (req, res) => {
	try {
		const { id } = req.params;
		const asset = await Asset.findByIdAndDelete(id);
		if (!asset) return res.status(404).json({ error: 'Asset not found' });
		// Attempt to unlink local file if served from /uploads
		if (asset.url && asset.url.startsWith('/uploads/')) {
			try {
				const p = path.join(UPLOADS_PATH, path.basename(asset.url));
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
	res.json(event);
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
