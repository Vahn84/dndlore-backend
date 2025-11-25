import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import session from 'express-session';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import sharp from 'sharp';
import fs from 'fs';
import path from 'path';
import mongoose from 'mongoose';
import { User, Group, Page, Event, TimeSystem, Asset, AssetFolder } from './models.js';
import discordClient from './discord-client.js';

// Carica variabili d'ambiente con valori di default
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:3000';
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3001;
const SESSION_SECRET = process.env.SESSION_SECRET || 'supersecret';
const JWT_SECRET = process.env.JWT_SECRET || 'jwtsecret';

// Connessione a MongoDB
const MONGO_URI = process.env.MONGO_URI

// MongoDB connection options - allow self-signed certificates on public/free WiFi
const mongoOptions = {
	tls: true,
	tlsAllowInvalidCertificates: process.env.NODE_ENV === 'development' || process.env.ALLOW_INVALID_CERTS === 'true',
	tlsAllowInvalidHostnames: process.env.NODE_ENV === 'development' || process.env.ALLOW_INVALID_CERTS === 'true',
};

mongoose
	.connect(MONGO_URI, mongoOptions)
	.then(() => console.log('Connected to MongoDB'))
	.catch((err) => console.error('MongoDB connection error', err));

const app = express();

// Health check endpoint for Docker
app.get('/health', (req, res) => {
	res.status(200).json({ status: 'ok' });
});

// Abilita CORS
app.use(
	cors({
		origin: FRONTEND_ORIGIN,
		credentials: true,
	})
);
app.use(
	bodyParser.json({
		limit: process.env.REQUEST_LIMIT || '25mb',
	})
);
app.use(
	bodyParser.urlencoded({
		extended: true,
		limit: process.env.REQUEST_LIMIT || '25mb',
	})
);

// Configurazione sessione (necessaria per Passport)
app.use(
	session({
		secret: SESSION_SECRET,
		resave: false,
		saveUninitialized: false,
		cookie: {
			httpOnly: true,
			secure: process.env.NODE_ENV === 'production',
			maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
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
// Avoid logging sensitive secrets in production logs
console.log('Google OAuth configured:', !!(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET));
console.log('OpenAI key configured:', !!process.env.OPENAI_API_KEY);

// Helper function to refresh Google access token using refresh token
async function refreshGoogleToken(refreshToken) {
	try {
		const response = await fetch('https://oauth2.googleapis.com/token', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				client_id: GOOGLE_CLIENT_ID,
				client_secret: GOOGLE_CLIENT_SECRET,
				refresh_token: refreshToken,
				grant_type: 'refresh_token',
			}),
		});

		if (!response.ok) {
			const error = await response.text();
			console.error('Token refresh failed:', error);
			return null;
		}

		const data = await response.json();
		// Google returns: { access_token, expires_in (seconds), scope, token_type }
		return {
			accessToken: data.access_token,
			expiresIn: data.expires_in, // seconds from now
		};
	} catch (err) {
		console.error('Error refreshing Google token:', err);
		return null;
	}
}

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
						// Store tokens with expiry (Google tokens typically expire in 1 hour = 3600 seconds)
						user.googleAccessToken = accessToken;
						user.googleRefreshToken =
							refreshToken || user.googleRefreshToken; // Keep existing if not provided
						user.googleTokenExpiry = new Date(
							Date.now() + 3600 * 1000
						); // 1 hour from now
						await user.save();
						return done(null, user);
					} else {
						// No local user matched this Google account
						return done(null, false);
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
const upload = multer({
	storage,
	limits: {
		fileSize: parseInt(process.env.MAX_UPLOAD_BYTES || `${15 * 1024 * 1024}`, 10),
	},
});

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

// Helper function to format a date using the time system configuration
function formatEventDate(tsConfig, eraId, year, monthIndex, day) {
	console.log('formatEventDate called with:', { eraId, year, monthIndex, day, hasConfig: !!tsConfig });
	if (!tsConfig || year == null) {
		console.log('formatEventDate returning empty: no config or year');
		return '';
	}
	
	const era = tsConfig.eras?.find(e => e.id === eraId) || tsConfig.eras?.[0];
	const eraAbbr = era?.abbreviation || '';
	console.log('Era lookup:', { eraId, foundEra: era?.id, abbreviation: eraAbbr, allEras: tsConfig.eras?.map(e => ({ id: e.id, abbr: e.abbreviation })) });
	console.log('Date formats:', tsConfig.dateFormats);
	
	// If only year is provided
	if (monthIndex == null || monthIndex < 0) {
		const format = tsConfig.dateFormats?.year || 'YYYY [E]';
		let result = format
			.replace(/YYYY/g, String(year))
			.replace(/\[E\]/g, eraAbbr);
		
		// Also replace standalone E (not in brackets) for backwards compatibility
		result = result.replace(/\bE\b/g, eraAbbr).trim();
		
		console.log('formatEventDate (year only) result:', result);
		return result;
	}
	
	const month = tsConfig.months?.[monthIndex];
	const monthName = month?.name || '';
	const monthNumber = monthIndex + 1;
	
	// If year + month
	if (day == null || day <= 0) {
		const format = tsConfig.dateFormats?.yearMonth || 'MMMM YYYY, [E]';
		let result = format
			.replace(/YYYY/g, String(year))
			.replace(/MMMM/g, monthName)
			.replace(/MM/g, String(monthNumber).padStart(2, '0'))
			.replace(/M/g, String(monthNumber))
			.replace(/\[E\]/g, eraAbbr);
		
		// Also replace standalone E (not in brackets) for backwards compatibility
		result = result.replace(/\bE\b/g, eraAbbr).trim();
		
		console.log('formatEventDate (year+month) result:', result);
		return result;
	}
	
	// Year + month + day
	const format = tsConfig.dateFormats?.yearMonthDay || 'D^ MMMM YYYY, [E]';
	console.log('Using format string:', format);
	const ordinal = (n) => {
		const mod100 = n % 100;
		if (mod100 >= 11 && mod100 <= 13) return `${n}th`;
		switch (n % 10) {
			case 1: return `${n}st`;
			case 2: return `${n}nd`;
			case 3: return `${n}rd`;
			default: return `${n}th`;
		}
	};
	
	let result = format
		.replace(/YYYY/g, String(year))
		.replace(/MMMM/g, monthName)
		.replace(/MM/g, String(monthNumber).padStart(2, '0'))
		.replace(/M/g, String(monthNumber))
		.replace(/D\^/g, ordinal(day))
		.replace(/DD/g, String(day).padStart(2, '0'))
		.replace(/D/g, String(day))
		.replace(/\[E\]/g, eraAbbr);
	
	// Also replace standalone E (not in brackets) for backwards compatibility
	result = result.replace(/\bE\b/g, eraAbbr).trim();
	
	console.log('formatEventDate (full date) result:', result);
	return result;
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
	passport.authenticate('google', {
		scope: [
			'profile',
			'email',
			'https://www.googleapis.com/auth/documents.readonly',
			'https://www.googleapis.com/auth/calendar.readonly',
			'https://www.googleapis.com/auth/calendar.events',
		],
		accessType: 'offline',
		prompt: 'consent',
	})
);
app.get(
	'/auth/google/callback',
	passport.authenticate('google', { failureRedirect: '/' }),
	(req, res) => {
		const user = req.user;
		const token = jwt.sign(
			{
				id: user._id,
				email: user.email,
				role: user.role,
				googleAccessToken: user.googleAccessToken,
			},
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

// Check Google token status for the authenticated user
app.get('/auth/google-token-status', requireAuth, async (req, res) => {
	try {
		const user = await User.findById(req.user.id);
		if (!user) return res.status(404).json({ error: 'User not found' });

		const hasRefreshToken = !!user.googleRefreshToken;
		const hasAccessToken = !!user.googleAccessToken;
		const isExpired = user.googleTokenExpiry
			? user.googleTokenExpiry < new Date()
			: true;

		res.json({
			connected: hasRefreshToken && hasAccessToken,
			expired: isExpired,
			tokenExpiry: user.googleTokenExpiry,
			needsReauth: !hasRefreshToken,
		});
	} catch (err) {
		console.error('Error checking Google token status:', err);
		res.status(500).json({ error: 'Failed to check token status' });
	}
});

// Refresh Google access token using stored refresh token
app.post('/auth/refresh-google-token', requireAuth, async (req, res) => {
	try {
		const user = await User.findById(req.user.id);
		if (!user) return res.status(404).json({ error: 'User not found' });

		if (!user.googleRefreshToken) {
			return res.status(400).json({
				error: 'No refresh token available. Please reconnect your Google account.',
				needsReauth: true,
			});
		}

		const refreshed = await refreshGoogleToken(user.googleRefreshToken);
		if (!refreshed) {
			return res.status(500).json({
				error: 'Failed to refresh token. Please reconnect your Google account.',
				needsReauth: true,
			});
		}

		// Update user with new access token and expiry
		user.googleAccessToken = refreshed.accessToken;
		user.googleTokenExpiry = new Date(
			Date.now() + refreshed.expiresIn * 1000
		);
		await user.save();

		// Generate new JWT with updated access token
		const newJwt = jwt.sign(
			{
				id: user._id,
				email: user.email,
				role: user.role,
				googleAccessToken: refreshed.accessToken,
			},
			JWT_SECRET,
			{ expiresIn: '1d' }
		);

		res.json({
			token: newJwt,
			googleAccessToken: refreshed.accessToken,
			tokenExpiry: user.googleTokenExpiry,
		});
	} catch (err) {
		console.error('Error refreshing Google token:', err);
		res.status(500).json({ error: 'Failed to refresh token' });
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
		'bannerThumbUrl',
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
		'linkSync',
		'hidden',
		'color',
		'icon',
	];
	fields.forEach((field) => {
		if (
			req.body[field] !== undefined ||
			field === 'bannerUrl' ||
			field === 'bannerThumbUrl'
		) {
			update[field] = req.body[field];
			if (field === 'bannerUrl' && !update[field]) {
				update[field] = '';
			}
		}
	});
	console.log('Event updated:', update);
	// If linking with sync enabled, optionally hydrate fields from page
	try {
		const evBefore = await Event.findById(id);
		const pageId =
			update.pageId !== undefined ? update.pageId : evBefore?.pageId;
		const linkSync =
			update.linkSync !== undefined
				? update.linkSync
				: evBefore?.linkSync;
		if (pageId && linkSync) {
			const page = await Page.findById(pageId);
			if (page) {
				// Sync all three fields: title, banner, and world date
				if (page.title) update.title = page.title;
				update.bannerUrl = page.bannerUrl || '';
				update.bannerThumbUrl = page.bannerThumbUrl || '';
				const wd = page.worldDate;
				if (wd) {
					update.startEraId = wd.eraId ?? null;
					update.startYear =
						typeof wd.year === 'number' ? wd.year : null;
					update.startMonthIndex =
						typeof wd.monthIndex === 'number'
							? wd.monthIndex
							: null;
					update.startDay =
						typeof wd.day === 'number' ? wd.day : null;
				}
			}
		}
	} catch (e) {
		console.warn('Link/sync hydration failed:', e);
	}

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
	const { type, q, limit } = req.query;
	const query = {};
	if (type) {
		query.type = type;
	}
	if (q && typeof q === 'string' && q.trim()) {
		query.title = { $regex: q.trim(), $options: 'i' };
	}
	const lim = Math.min(100, Math.max(1, Number(limit) || 50));
	// Sort by order field first (ascending), then by updatedAt (descending) as fallback
	const pages = await Page.find(query).limit(lim).sort({ order: 1, updatedAt: -1 });
	console.log('Pages fetched', pages)
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
		placeType,
		coordinates,
		bannerUrl,
		assetId,
		blocks = [],
		sessionDate,
		worldDate,
		hidden = false,
		draft = false,
	} = req.body;
	if (!title) return res.status(400).json({ error: 'title is required' });
	if (!type) return res.status(400).json({ error: 'type is required' });
	const page = await Page.create({
		title,
		subtitle: '',
		type,
		placeType,
		coordinates,
		bannerUrl,
		assetId,
		blocks,
		sessionDate,
		worldDate,
		hidden,
		draft,
	});
	res.json(page);
});

app.put('/pages/:id', requireDM, async (req, res) => {
	const { id } = req.params;
	const update = {};
	const unset = {};
	const fields = [
		'title',
		'subtitle',
		'type',
		'placeType',
		'coordinates',
		'bannerUrl',
		'bannerThumbUrl',
		'assetId',
		'blocks',
		'sessionDate',
		'worldDate',
		'hidden',
		'draft',
	];
	fields.forEach((field) => {
		// Check if field exists in request body (even if undefined/null)
		if (req.body.hasOwnProperty(field)) {
			// If explicitly set to null or undefined, remove the field
			if (req.body[field] === null || req.body[field] === undefined) {
				unset[field] = '';
			} else {
				update[field] = req.body[field];
			}
		}
	});
	
	// Build the MongoDB update operation
	const updateOperation = {};
	if (Object.keys(update).length > 0) {
		updateOperation.$set = update;
	}
	if (Object.keys(unset).length > 0) {
		updateOperation.$unset = unset;
	}
	
	console.log('Page updated:', update, 'Unset:', unset);
	if (update.draft === true) {
		console.log(`Page ${id} is being unpublished (draft=true)`);
	}
	const page = await Page.findByIdAndUpdate(id, updateOperation, { new: true });
	if (!page) return res.status(404).json({ error: 'Page not found' });

	// After updating a page, propagate to linked events that opt into syncing
	try {
		const linkedEvents = await Event.find({ pageId: id });
		console.log(`Found ${linkedEvents.length} linked events for page ${id}`);
		
		// Fetch time system once for formatting dates
		const ts = await TimeSystem.findOne();
		const tsConfig = ts?.config || null;

		for (const ev of linkedEvents) {
			let changed = false;
			
			// If unpublishing (draft=true), hide the event (regardless of linkSync)
			if (update.draft === true && !ev.hidden) {
				ev.hidden = true;
				changed = true;
				console.log(`Hiding event ${ev._id} (${ev.title}) linked to unpublished page ${id}`);
			}
			
			// Only sync other fields if linkSync is enabled
			if (!ev.linkSync) {
				// Still save if we changed hidden status
				if (changed) {
					await ev.save();
					console.log(`Saved hidden status for event ${ev._id}`);
				}
				continue;
			}
			// Sync title
			if (page.title && ev.title !== page.title) {
				ev.title = page.title;
				changed = true;
			}
			// Sync banner
			const pb = page.bannerUrl || '';
			const pbt = page.bannerThumbUrl || '';
			if ((ev.bannerUrl || '') !== pb) {
				ev.bannerUrl = pb;
				changed = true;
			}
			if ((ev.bannerThumbUrl || '') !== pbt) {
				ev.bannerThumbUrl = pbt;
				changed = true;
			}
			// Sync world date
			if (page.worldDate && page.worldDate.eraId) {
				const wd = page.worldDate;
				// Copy structured world date into event start fields
				const nextEra = wd.eraId || null;
				const nextYear = typeof wd.year === 'number' ? wd.year : null;
				const nextMonth =
					typeof wd.monthIndex === 'number' ? wd.monthIndex : null;
				const nextDay = typeof wd.day === 'number' ? wd.day : null;
				if (
					ev.startEraId !== nextEra ||
					ev.startYear !== nextYear ||
					ev.startMonthIndex !== nextMonth ||
					ev.startDay !== nextDay
				) {
					ev.startEraId = nextEra;
					ev.startYear = nextYear;
					ev.startMonthIndex = nextMonth;
					ev.startDay = nextDay;
					// Clear endDate fields for single-day events
					ev.endEraId = null;
					ev.endYear = null;
					ev.endMonthIndex = null;
					ev.endDay = null;
					ev.endDate = '';
					
					// Format startDate string using time system if available
					if (tsConfig) {
						ev.startDate = formatEventDate(tsConfig, nextEra, nextYear, nextMonth, nextDay);
					}
					changed = true;
				}
			} else if (
				page.worldDate === null ||
				(page.worldDate && !page.worldDate.eraId)
			) {
				// Clear world date if page worldDate is null or empty
				if (
					ev.startEraId ||
					ev.startYear ||
					ev.startMonthIndex ||
					ev.startDay
				) {
					ev.startEraId = null;
					ev.startYear = null;
					ev.startMonthIndex = null;
					ev.startDay = null;
					ev.endEraId = null;
					ev.endYear = null;
					ev.endMonthIndex = null;
					ev.endDay = null;
					ev.startDate = '';
					ev.endDate = '';
					changed = true;
				}
			}
			if (changed) {
				await ev.save();
				console.log(`Event ${ev._id} synced. startDate: "${ev.startDate}", startYear: ${ev.startYear}, startMonthIndex: ${ev.startMonthIndex}, startDay: ${ev.startDay}`);
			}
		}
	} catch (propErr) {
		console.warn('Failed to propagate page changes to events:', propErr);
	}
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

// Update page order for a specific type (for drag-and-drop reordering)
app.patch('/pages/reorder/:type', requireDM, async (req, res) => {
	try {
		const { type } = req.params;
		const { pageIds } = req.body; // Array of page IDs in desired order
		
		if (!Array.isArray(pageIds)) {
			return res.status(400).json({ error: 'pageIds must be an array' });
		}

		// Validate page type
		const validTypes = ['place', 'history', 'myth', 'people', 'campaign'];
		if (!validTypes.includes(type)) {
			return res.status(400).json({ error: 'Invalid page type' });
		}

		// Update order field for each page
		const updates = pageIds.map((pageId, index) => ({
			updateOne: {
				filter: { _id: pageId, type },
				update: { $set: { order: index } },
			},
		}));

		await Page.bulkWrite(updates);
		res.json({ success: true, updated: pageIds.length });
	} catch (err) {
		console.error('Error updating page order:', err);
		res.status(500).json({ error: 'Failed to update page order' });
	}
});

// -----------------------------------------------------------------------------
// Upload immagine
// -----------------------------------------------------------------------------
app.post('/upload', requireDM, upload.single('file'), async (req, res) => {
	const file = req.file;
	if (!file) return res.status(400).json({ error: 'No file uploaded' });

	const url = `/uploads/${file.filename}`;
	let bannerThumbUrl = null;

	// Generate thumbnail for images
	try {
		const ext = path.extname(file.filename).toLowerCase();
		const isImage = [
			'.jpg',
			'.jpeg',
			'.png',
			'.webp',
			'.gif',
			'.bmp',
			'.tiff',
		].includes(ext);

		if (isImage) {
			const thumbFilename = `thumb-${file.filename}`;
			const thumbPath = path.join(UPLOADS_PATH, thumbFilename);

			await sharp(file.path)
				.resize(800, null, {
					// 800px width, maintain aspect ratio
					withoutEnlargement: true,
					fit: 'inside',
				})
				.toFile(thumbPath);

			bannerThumbUrl = `/uploads/${thumbFilename}`;
		}
	} catch (err) {
		console.warn('Thumbnail generation failed:', err);
		// Continue without thumbnail - not a critical error
	}

	res.json({ url, bannerThumbUrl });
});

// Avvio server
app.listen(PORT, async () => {
	console.log(`Backend listening on port ${PORT}`);
	
	// Initialize Discord bot (non-blocking)
	try {
		await discordClient.connect();
	} catch (error) {
		console.error('Discord bot initialization failed:', error);
	}
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
// Discord Integration
// -----------------------------------------------------------------------------
/**
 * GET /integrations/google/calendars
 * Fetch user's Google Calendar list
 */
app.get('/integrations/google/calendars', requireAuth, async (req, res) => {
	try {
		// JWT payload stores user id as `id` (see /auth/google/callback), not `userId`
		const user = await User.findById(req.user.id);
		
		if (!user || !user.googleAccessToken) {
			return res.status(401).json({ 
				error: 'Not connected to Google Calendar',
				message: 'Please connect your Google account first.'
			});
		}
		
		// Check if token is expired
		const now = new Date();
		const tokenExpired = user.googleTokenExpiry && user.googleTokenExpiry < now;
		
		let accessToken = user.googleAccessToken;
		
		if (tokenExpired && user.googleRefreshToken) {
			console.log('Google token expired, refreshing...');
			const refreshed = await refreshGoogleToken(user.googleRefreshToken);
			if (refreshed) {
				accessToken = refreshed.accessToken;
				user.googleAccessToken = refreshed.accessToken;
				user.googleTokenExpiry = new Date(Date.now() + refreshed.expiresIn * 1000);
				await user.save();
			} else {
				return res.status(401).json({ error: 'Failed to refresh Google token' });
			}
		}
		
		// Fetch calendar list from Google
		const calResponse = await fetch(
			'https://www.googleapis.com/calendar/v3/users/me/calendarList',
			{
				method: 'GET',
				headers: {
					Authorization: `Bearer ${accessToken}`,
				},
			}
		);
		
		if (!calResponse.ok) {
			const errorText = await calResponse.text();
			console.error('Failed to fetch Google calendars:', errorText);
			return res.status(calResponse.status).json({ error: 'Failed to fetch calendars' });
		}
		
		const data = await calResponse.json();
		
		// Return simplified calendar list
		const calendars = data.items.map(cal => ({
			id: cal.id,
			name: cal.summary,
			primary: cal.primary || false,
			backgroundColor: cal.backgroundColor,
			accessRole: cal.accessRole,
		}));
		
		res.json(calendars);
	} catch (err) {
		console.error('GET /integrations/google/calendars failed', err);
		res.status(500).json({ error: 'Failed to fetch Google calendars', details: err.message });
	}
});

/**
 * GET /integrations/discord/channels
 * Fetch all text channels from the configured Discord guild
 */
app.get('/integrations/discord/channels', requireAuth, async (req, res) => {
	try {
		if (!discordClient.isAvailable()) {
			return res.status(503).json({ 
				error: 'Discord integration not available',
				message: 'Discord bot is not connected. Check DISCORD_BOT_TOKEN and DISCORD_GUILD_ID environment variables.'
			});
		}

		const channels = await discordClient.getTextChannels();
		res.json(channels);
	} catch (err) {
		console.error('GET /integrations/discord/channels failed', err);
		res.status(500).json({ error: 'Failed to fetch Discord channels', details: err.message });
	}
});

/**
 * GET /integrations/discord/voice-channels
 * Fetch all voice channels from the configured Discord guild
 */
app.get('/integrations/discord/voice-channels', requireAuth, async (req, res) => {
	try {
		if (!discordClient.isAvailable()) {
			return res.status(503).json({ 
				error: 'Discord integration not available',
				message: 'Discord bot is not connected. Check DISCORD_BOT_TOKEN and DISCORD_GUILD_ID environment variables.'
			});
		}

		const voiceChannels = await discordClient.getVoiceChannels();
		res.json({
			guildId: process.env.DISCORD_GUILD_ID,
			channels: voiceChannels
		});
	} catch (err) {
		console.error('GET /integrations/discord/voice-channels failed', err);
		res.status(500).json({ error: 'Failed to fetch Discord voice channels', details: err.message });
	}
});

/**
 * POST /integrations/discord/events
 * Create a Discord scheduled event
 * Body: { title, description?, bannerUrl?, dateTimeUtc, channelId, syncToCalendar?, calendarId? }
 */
app.post('/integrations/discord/events', requireAuth, async (req, res) => {
	try {
		if (!discordClient.isAvailable()) {
			return res.status(503).json({ 
				error: 'Discord integration not available',
				message: 'Discord bot is not connected. Check DISCORD_BOT_TOKEN and DISCORD_GUILD_ID environment variables.'
			});
		}

		const { title, description, bannerUrl, dateTimeUtc, channelId, voiceChannelId, syncToCalendar, calendarId } = req.body;

		console.log('Creating Discord event with params:', {
			title,
			description: description?.substring(0, 100),
			bannerUrl,
			dateTimeUtc,
			channelId,
			voiceChannelId,
			syncToCalendar,
			calendarId
		});

		if (!title) {
			return res.status(400).json({ error: 'Event title is required' });
		}

		if (!dateTimeUtc) {
			return res.status(400).json({ error: 'Event date/time is required' });
		}

		const scheduledStartTime = new Date(dateTimeUtc);
		if (isNaN(scheduledStartTime.getTime())) {
			return res.status(400).json({ error: 'Invalid date format' });
		}

		// Create Discord scheduled event
		const discordEvent = await discordClient.createScheduledEvent({
			name: title,
			description: description || `D&D Lore event: ${title}`,
			scheduledStartTime,
			voiceChannelId: voiceChannelId || null,
			image: bannerUrl,
		});

		// Send a message to the selected channel with the event link
		if (discordEvent && discordEvent.url && channelId) {
			try {
				await discordClient.sendMessageToChannel(
					channelId,
					`📅 **New Event Created:** ${title}\n${discordEvent.url}`
				);
			} catch (msgErr) {
				console.error('Failed to send message to channel after event creation:', msgErr);
				// Don't fail the whole request if message send fails
			}
		}

		let calendarEvent = null;

		// Sync to Google Calendar if requested and user has valid token
		if (syncToCalendar) {
			try {
				const user = await User.findById(req.user.id);
				
				if (!user || !user.googleAccessToken) {
					console.warn('User has no Google Calendar token, skipping sync');
				} else {
					// Check if token is expired
					const now = new Date();
					const tokenExpired = user.googleTokenExpiry && user.googleTokenExpiry < now;
					
					let accessToken = user.googleAccessToken;
					
					if (tokenExpired && user.googleRefreshToken) {
						console.log('Google token expired, refreshing...');
						const refreshed = await refreshGoogleToken(user.googleRefreshToken);
						if (refreshed) {
							accessToken = refreshed.accessToken;
							user.googleAccessToken = refreshed.accessToken;
							user.googleTokenExpiry = new Date(Date.now() + refreshed.expiresIn * 1000);
							await user.save();
						}
					}
					
					if (accessToken) {
						// Create event in Google Calendar
						const endTime = new Date(scheduledStartTime.getTime() + 3 * 60 * 60 * 1000); // +3 hours
						
						const calendarEventData = {
							summary: title,
							description: description || `D&D Lore Discord event: ${title}`,
							start: {
								dateTime: scheduledStartTime.toISOString(),
								timeZone: 'UTC',
							},
							end: {
								dateTime: endTime.toISOString(),
								timeZone: 'UTC',
							},
						};
						
						// Use specified calendar or default to primary
						const targetCalendar = calendarId || 'primary';
						
						const calResponse = await fetch(
							`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(targetCalendar)}/events`,
							{
								method: 'POST',
								headers: {
									Authorization: `Bearer ${accessToken}`,
									'Content-Type': 'application/json',
								},
								body: JSON.stringify(calendarEventData),
							}
						);
						
						if (calResponse.ok) {
							calendarEvent = await calResponse.json();
							console.log('Google Calendar event created:', calendarEvent.id);
						} else {
							const errorText = await calResponse.text();
							console.error('Failed to create Google Calendar event:', errorText);
						}
					}
				}
			} catch (calErr) {
				console.error('Google Calendar sync error:', calErr);
				// Don't fail the whole request if calendar sync fails
			}
		}

		res.json({
			success: true,
			discordEvent,
			calendarEvent,
			message: calendarEvent 
				? 'Discord event created and synced to Google Calendar'
				: 'Discord event created successfully',
		});
	} catch (err) {
		console.error('POST /integrations/discord/events failed', err);
		res.status(500).json({ error: 'Failed to create Discord event', details: err.message });
	}
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
		let bannerThumbUrl = null;
		const folderId =
			req.body && req.body.folderId
				? req.body.folderId || null
				: null;

		if (req.file) {
			url = `/uploads/${req.file.filename}`;

			// Generate thumbnail for uploaded images
			try {
				const ext = path.extname(req.file.filename).toLowerCase();
				const isImage = [
					'.jpg',
					'.jpeg',
					'.png',
					'.webp',
					'.gif',
					'.bmp',
					'.tiff',
				].includes(ext);

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
app.delete('/assets/:id', requireDM, async (req, res) => {
	try {
		const { id } = req.params;
		const asset = await Asset.findByIdAndDelete(id);
		if (!asset) return res.status(404).json({ error: 'Asset not found' });

		// Clear references to this asset in Events and Pages
		const assetUrl = asset.url;
		const assetbannerThumbUrl = asset.thumb_url;

		// Update Events that reference this asset's URL or thumbnail
		await Event.updateMany(
			{
				$or: [
					{ bannerUrl: assetUrl },
					{ bannerUrl: assetbannerThumbUrl },
					{ bannerThumbUrl: assetUrl },
					{ bannerThumbUrl: assetbannerThumbUrl },
				],
			},
			{
				$set: {
					bannerUrl: null,
					bannerThumbUrl: null,
				},
			}
		);

		// Update Pages that reference this asset's URL or thumbnail
		await Page.updateMany(
			{
				$or: [
					{ bannerUrl: assetUrl },
					{ bannerUrl: assetbannerThumbUrl },
					{ bannerThumbUrl: assetUrl },
					{ bannerThumbUrl: assetbannerThumbUrl },
				],
			},
			{
				$set: {
					bannerUrl: null,
					bannerThumbUrl: null,
				},
			}
		);

		// Clear references in Page blocks (image blocks with url field)
		await Page.updateMany(
			{ 'blocks.url': { $in: [assetUrl, assetbannerThumbUrl] } },
			{
				$set: {
					'blocks.$[elem].url': null,
				},
			},
			{
				arrayFilters: [
					{
						'elem.url': { $in: [assetUrl, assetbannerThumbUrl] },
					},
				],
			}
		);

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
app.patch('/assets/:id/move', requireDM, async (req, res) => {
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

// -----------------------------------------------------------------------------
// Asset Folders
// -----------------------------------------------------------------------------

// List all asset folders
app.get('/asset-folders', async (req, res) => {
	try {
		const folders = await AssetFolder.find().sort({ createdAt: -1 });
		res.json(folders);
	} catch (err) {
		console.error('GET /asset-folders failed', err);
		res.status(500).json({ error: 'Internal error' });
	}
});

// Create a new asset folder
app.post('/asset-folders', requireDM, async (req, res) => {
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
app.delete('/asset-folders/:id', requireDM, async (req, res) => {
	try {
		const { id } = req.params;
		
		// Check if folder contains any assets
		const assetsInFolder = await Asset.countDocuments({ folderId: id });
		if (assetsInFolder > 0) {
			return res.status(400).json({ 
				error: 'Cannot delete folder with assets. Move or delete assets first.' 
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

// -----------------------------------------------------------------------------
// Sync Step 1: Preview - Fetch and summarize from Google Doc
// -----------------------------------------------------------------------------
app.post('/sync/campaign/preview', requireDM, async (req, res) => {
	try {
		let { docId, url, summarize, googleAccessToken } = req.body || {};

		// Fallback to token embedded in JWT (set by Google login) if not provided in body
		if (!googleAccessToken && req.user && req.user.googleAccessToken) {
			googleAccessToken = req.user.googleAccessToken;
		}

		// Helper to attempt token refresh if we have user context
		const tryRefreshToken = async () => {
			if (!req.user || !req.user.id) return null;
			const user = await User.findById(req.user.id);
			if (!user || !user.googleRefreshToken) return null;

			const refreshed = await refreshGoogleToken(user.googleRefreshToken);
			if (!refreshed) return null;

			// Update database
			user.googleAccessToken = refreshed.access_token;
			user.googleTokenExpiry = new Date(
				Date.now() + (refreshed.expires_in || 3600) * 1000
			);
			await user.save();

			return refreshed.access_token;
		};

		if (!docId && url) {
			const m = url.match(/\/document\/d\/([a-zA-Z0-9_-]+)/);
			docId = m ? m[1] : null;
		}
		if (!docId) {
			return res.status(400).json({ error: 'docId or url required' });
		}

		const doSummarize = summarize !== false;

		// 1) Find the latest existing page by sessionDate to avoid duplicate imports
		const pages = await Page.find({
			type: 'campaign',
			sessionDate: { $exists: true },
		});
		const parseDDMMYYYY = (str) => {
			if (!str) return null;
			const m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec(
				String(str).trim()
			);
			if (!m) return null;
			const [_, dd, mm, yyyy] = m;
			const d = new Date(Number(yyyy), Number(mm) - 1, Number(dd));
			return isNaN(d.getTime()) ? null : d;
		};
		const latestLocal = pages.reduce((acc, p) => {
			const d = parseDDMMYYYY(p.sessionDate);
			return d && (!acc || d > acc) ? d : acc;
		}, null);

		// 2) Fetch Google Doc as plain text
		let txt = null;

		// Try public export first
		const exportUrl = `https://docs.google.com/document/d/${docId}/export?format=txt`;
		const publicResp = await fetch(exportUrl);

		if (publicResp.ok) {
			txt = await publicResp.text();
		} else if (googleAccessToken) {
			// Use user's Google access token to fetch via Docs API
			let docsResp = await fetch(
				`https://docs.googleapis.com/v1/documents/${docId}`,
				{ headers: { Authorization: `Bearer ${googleAccessToken}` } }
			);

			// If 401, attempt token refresh and retry once
			if (docsResp.status === 401) {
				console.log(
					'Google API returned 401, attempting token refresh...'
				);
				const newToken = await tryRefreshToken();
				if (newToken) {
					googleAccessToken = newToken;
					docsResp = await fetch(
						`https://docs.googleapis.com/v1/documents/${docId}`,
						{ headers: { Authorization: `Bearer ${newToken}` } }
					);
				}
			}

			try {
				if (docsResp.ok) {
					const doc = await docsResp.json();
					// Extract plain text from structured document
					if (doc.body && doc.body.content) {
						const textParts = [];
						const extractText = (elements) => {
							for (const el of elements) {
								if (el.paragraph && el.paragraph.elements) {
									for (const elem of el.paragraph.elements) {
										if (
											elem.textRun &&
											elem.textRun.content
										) {
											textParts.push(
												elem.textRun.content
											);
										}
									}
								}
								if (el.table && el.table.tableRows) {
									for (const row of el.table.tableRows) {
										if (row.tableCells) {
											for (const cell of row.tableCells) {
												if (cell.content) {
													extractText(cell.content);
												}
											}
										}
									}
								}
							}
						};
						extractText(doc.body.content);
						txt = textParts.join('');
					}
				}
			} catch (err) {
				console.error('Error parsing Docs API response:', err);
			}
		} // Close else if (googleAccessToken) block

		if (!txt) {
			return res
				.status(400)
				.json({
					error: 'Could not fetch document. Make sure it is publicly accessible or provide a valid Google access token.',
				});
		}

		// 3) Parse out sections by date headers (DD.MM.YYYY format)
		const dateRegex = /^(\d{1,2})\.(\d{1,2})\.(\d{4})$/;
		const sections = [];
		const lines = txt.split(/\r?\n/);
		let currSection = null;

		for (const line of lines) {
			const trimmed = line.trim();
			const match = dateRegex.exec(trimmed);
			if (match) {
				// Found a date header
				if (currSection) sections.push(currSection);
				const [_, dd, mm, yyyy] = match;
				currSection = {
					date: trimmed, // Store as DD.MM.YYYY
					content: [],
				};
			} else if (currSection) {
				currSection.content.push(line);
			}
		}
		if (currSection) sections.push(currSection);
		
		if (sections.length === 0) {
			return res.json({
				message: 'No date section found (looking for DD.MM.YYYY format)',
				availableDates: [],
			});
		}

		// Filter out dates that already exist in the database
		const existingDates = new Set(
			pages
				.filter(p => p.sessionDate)
				.map(p => p.sessionDate.trim())
		);

		const availableSections = sections.filter(section => {
			// Check if this date already exists in DB (as DD.MM.YYYY or DD/MM/YYYY)
			const dateWithDots = section.date; // DD.MM.YYYY
			const dateWithSlashes = section.date.replace(/\./g, '/'); // DD/MM/YYYY
			return !existingDates.has(dateWithDots) && !existingDates.has(dateWithSlashes);
		});

		if (availableSections.length === 0) {
			return res.json({
				message: 'No new dates found (all dates from document already exist in database)',
				availableDates: [],
			});
		}

		// Return all available dates with their content
		const availableDates = availableSections.map(section => ({
			date: section.date, // DD.MM.YYYY format
			content: section.content.join('\n').trim(),
		}));

		// Sort by date (most recent first)
		availableDates.sort((a, b) => {
			const dateA = parseDDMMYYYY(a.date.replace(/\./g, '/'));
			const dateB = parseDDMMYYYY(b.date.replace(/\./g, '/'));
			if (!dateA || !dateB) return 0;
			return dateB.getTime() - dateA.getTime();
		});

		res.json({
			availableDates,
			message: `Found ${availableDates.length} new session(s)`,
		});
	} catch (err) {
		console.error(err);
		res.status(500).json({ error: err.message || 'Server error' });
	}
});

// -----------------------------------------------------------------------------
// Sync Step 1.5: Summarize - Summarize selected date content with OpenAI
// -----------------------------------------------------------------------------
app.post('/sync/campaign/summarize', requireDM, async (req, res) => {
	try {
		const { rawText, sessionDate } = req.body || {};

		if (!rawText) {
			return res.status(400).json({ error: 'rawText is required' });
		}

		const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
		
		if (!OPENAI_API_KEY) {
			return res.status(400).json({ error: 'OpenAI API key not configured' });
		}

		console.log('Summarizing session via OpenAI...');
		let summary = rawText;

		try {
			const targetWords = 520;
			const maxTokens = Math.max(
				800,
				Math.min(6000, Math.ceil(targetWords * 2.5))
			);
			const headers = {
				Authorization: `Bearer ${OPENAI_API_KEY}`,
				'Content-Type': 'application/json',
			};
			if (process.env.OPENAI_ORG_ID)
				headers['OpenAI-Organization'] = process.env.OPENAI_ORG_ID;
			if (process.env.OPENAI_PROJECT_ID)
				headers['OpenAI-Project'] = process.env.OPENAI_PROJECT_ID;

			// Extract explicit dialogue candidates from notes to prevent invention
			const extractDialogues = (src) => {
				const lines = String(src).split(/\r?\n/);
				const map = new Map([
					['O:', 'Owen'],
					['A:', 'Ardi'],
					['F:', 'Farek'],
					['BRUNO>', 'Bruno'],
					['BRUNO:', 'Bruno'],
					['OWEN:', 'Owen'],
					['ARDI:', 'Ardi'],
					['FAREK:', 'Farek'],
					['LYSARA:', 'Lysara'],
					['OBYRON:', 'Obyron'],
					['RAIDAN:', 'Raidan'],
				]);
				const found = [];
				for (const raw of lines) {
					const line = raw.trim();
					if (!line) continue;
					let matched = false;
					for (const [mk, name] of map.entries()) {
						if (line.startsWith(mk)) {
							let content = line.slice(mk.length).trim();
							if (content)
								found.push({
									speaker: name,
									text: content,
								});
							matched = true;
							break;
						}
					}
					if (matched) continue;
					const m = line.match(
						/^(Owen|Ardi|Farek|Bruno|Lysara|Obyron|Raidan)\s*:\s*(.+)$/i
					);
					if (m) {
						found.push({
							speaker:
								m[1][0].toUpperCase() +
								m[1].slice(1).toLowerCase(),
							text: m[2].trim(),
						});
					}
				}
				const uniq = [];
				const seen = new Set();
				for (const d of found) {
					const key = d.speaker + '|' + d.text;
					if (seen.has(key)) continue;
					seen.add(key);
					uniq.push({
						speaker: d.speaker,
						text: d.text.slice(0, 200),
					});
				}
				return uniq.slice(0, 12);
			};
			const allowed = extractDialogues(rawText);
			const allowedList = allowed.length
				? `\n\nUsa SOLO queste battute esplicite se vuoi inserire dialoghi (altrimenti ometti i dialoghi se non bastano):\n` +
				  allowed.map((d) => `- ${d.speaker}: ${d.text}`).join('\n')
				: '';

			const resp = await fetch(
				'https://api.openai.com/v1/chat/completions',
				{
					method: 'POST',
					headers,
					body: JSON.stringify({
						model: 'gpt-4o-mini',
						messages: [
							{
								role: 'system',
								content: `Cronista D&D. Resoconto narrativo in Italiano, 4–7 paragrafi, stile evocativo. NON INVENTARE. Solo fatti/dialoghi dalle note. Battute tra "" con nome (O:→Owen, A:→Ardi, F:→Farek, BRUNO:→Bruno). No preamboli. ~${targetWords} parole.`,
							},
							{
								role: 'user',
								content: `Trasforma note in resoconto. SOLO dialoghi espliciti (O:→Owen, A:→Ardi, F:→Farek, BRUNO:→Bruno). NON INVENTARE.${allowedList}\n\n${rawText}`,
							},
						],
						temperature: 0.7,
						max_completion_tokens: maxTokens,
					}),
				}
			);
			const data = await resp.json();
			const choice = data?.choices?.[0];
			const finishReason = choice?.finish_reason;
			const content =
				choice?.message?.content?.trim() || choice?.text?.trim();

			if (finishReason === 'length') {
				console.warn(
					`OpenAI response was truncated. Consider increasing max_completion_tokens (current: ${maxTokens})`
				);
			}

			if (content) summary = content;
		} catch (e) {
			console.error('OpenAI call failed', e);
			return res.status(500).json({ error: 'OpenAI summarization failed' });
		}

		res.json({
			summary,
			sessionDate,
			suggestedTitle: sessionDate ? `Session ${sessionDate}` : 'Session',
		});
	} catch (err) {
		console.error(err);
		res.status(500).json({ error: err.message || 'Server error' });
	}
});

// -----------------------------------------------------------------------------
// Sync Step 2: Create - Save the page and event with custom fields
// -----------------------------------------------------------------------------
app.post('/sync/campaign/create', requireDM, async (req, res) => {
	try {
		const { summary, sessionDate, title, subtitle, worldDate, bannerUrl } =
			req.body || {};

		if (!summary || !sessionDate) {
			return res
				.status(400)
				.json({ error: 'summary and sessionDate are required' });
		}

		// Split summary into paragraphs for TipTap format
		const paragraphs = String(summary)
			.replace(/\r\n/g, '\n')
			.split(/\n{2,}/)
			.map((p) => p.trim())
			.filter(Boolean);

		const tiptap = {
			type: 'doc',
			content:
				paragraphs.length > 0
					? paragraphs.map((p) => ({
							type: 'paragraph',
							content: [{ type: 'text', text: p }],
					  }))
					: [
							{
								type: 'paragraph',
								content: [{ type: 'text', text: summary }],
							},
					  ],
		};

		const page = await Page.create({
			title: title || 'Untitled Session',
			subtitle: subtitle || '',
			type: 'campaign',
			blocks: [{ type: 'rich', rich: tiptap, plainText: summary }],
			sessionDate,
			worldDate: worldDate || null,
			bannerUrl: bannerUrl || '',
			draft: true,
		});

		// Create a timeline event in the Campaign group
		let campaignGroup = await Group.findOne({
			name: { $regex: /(campaign|session)/i },
		});
		if (!campaignGroup) {
			const count = await Group.countDocuments();
			campaignGroup = await Group.create({
				name: 'Campaign',
				order: count,
			});
		}

		let createdEvent = null;
		try {
			const last = await Event.findOne().sort({ order: -1 });
			const order = last ? last.order + 1 : 0;
			
			// Parse worldDate object into separate fields for Event
			let eventDateFields = {};
			if (worldDate && typeof worldDate === 'object') {
				eventDateFields = {
					startEraId: worldDate.eraId || null,
					startYear: worldDate.year ? Number(worldDate.year) : null,
					startMonthIndex: worldDate.monthIndex ? Number(worldDate.monthIndex) : null,
					startDay: worldDate.day ? Number(worldDate.day) : null,
				};
				
				// Format startDate string using time system if available
				const ts = await TimeSystem.findOne();
				const tsConfig = ts?.config || null;
				if (tsConfig && eventDateFields.startYear != null) {
					eventDateFields.startDate = formatEventDate(
						tsConfig,
						eventDateFields.startEraId,
						eventDateFields.startYear,
						eventDateFields.startMonthIndex,
						eventDateFields.startDay
					);
				}
			}
			
			console.log('Creating event with:', { title: page.title, type: 'campaign', groupId: campaignGroup._id, pageId: page._id, hidden: true, linkSync: true, order, detailLevel: 'Day', ...eventDateFields });
			createdEvent = await Event.create({
				title: page.title,
				type: 'campaign',
				groupId: campaignGroup._id,
				pageId: page._id,
				hidden: true,
				linkSync: true,
				bannerUrl: bannerUrl || '',
				order,
				detailLevel: 'Day',
				...eventDateFields,
			});
			console.log('Event created successfully:', createdEvent._id);
		} catch (evErr) {
			console.error('Failed to create event for synced session:', evErr);
		}

		console.log('Responding with page and event:', { pageId: page._id, eventId: createdEvent?._id });
		res.json({ created: page, event: createdEvent });
	} catch (err) {
		console.error(err);
		res.status(500).json({ error: err.message || 'Server error' });
	}
});

// -----------------------------------------------------------------------------
// Sync (Legacy): import latest session from Google Doc, summarize, create draft campaign page
// -----------------------------------------------------------------------------
app.post('/sync/campaign/from-google', requireDM, async (req, res) => {
	try {
		let {
			docId,
			url,
			summarize,
			title: customTitle,
			googleAccessToken,
			summaryTargetWords,
			keepDialogues,
			worldDate,
		} = req.body || {};

		// Fallback to token embedded in JWT (set by Google login) if not provided in body
		if (!googleAccessToken && req.user && req.user.googleAccessToken) {
			googleAccessToken = req.user.googleAccessToken;
		}

		// Helper to attempt token refresh if we have user context
		const tryRefreshToken = async () => {
			if (!req.user || !req.user.id) return null;
			const user = await User.findById(req.user.id);
			if (!user || !user.googleRefreshToken) return null;

			const refreshed = await refreshGoogleToken(user.googleRefreshToken);
			if (!refreshed) return null;

			// Update database
			user.googleAccessToken = refreshed.accessToken;
			user.googleTokenExpiry = new Date(
				Date.now() + refreshed.expiresIn * 1000
			);
			await user.save();

			return refreshed.accessToken;
		};

		if (!docId && url) {
			const m = String(url).match(/\/document\/d\/([a-zA-Z0-9_-]+)/);
			if (m) docId = m[1];
		}
		if (!docId) return res.status(400).json({ error: 'docId is required' });
		const doSummarize = summarize !== false; // default true

		// 1) Fetch existing campaign pages and determine latest sessionDate
		const pages = await Page.find({ type: 'campaign' });
		const parseDDMMYYYY = (s) => {
			if (!s || typeof s !== 'string') return null;
			const m = s.match(/^(\d{2})[./-](\d{2})[./-](\d{4})$/);
			if (!m) return null;
			const [_, dd, mm, yyyy] = m;
			const d = new Date(Number(yyyy), Number(mm) - 1, Number(dd));
			return isNaN(d.getTime()) ? null : d;
		};
		const latestLocal = pages.reduce((acc, p) => {
			const d = parseDDMMYYYY(p.sessionDate);
			return d && (!acc || d > acc) ? d : acc;
		}, null);

		// 2) Fetch Google Doc as plain text
		let txt = null;

		// Try public export first
		const exportUrl = `https://docs.google.com/document/d/${docId}/export?format=txt`;
		const publicResp = await fetch(exportUrl);

		if (publicResp.ok) {
			txt = await publicResp.text();
		} else if (googleAccessToken) {
			// Use user's Google access token to fetch via Docs API
			let docsResp = await fetch(
				`https://docs.googleapis.com/v1/documents/${docId}`,
				{ headers: { Authorization: `Bearer ${googleAccessToken}` } }
			);

			// If 401, attempt token refresh and retry once
			if (docsResp.status === 401) {
				console.log(
					'Google API returned 401, attempting token refresh...'
				);
				const newToken = await tryRefreshToken();
				if (newToken) {
					googleAccessToken = newToken;
					docsResp = await fetch(
						`https://docs.googleapis.com/v1/documents/${docId}`,
						{ headers: { Authorization: `Bearer ${newToken}` } }
					);
				}
			}

			try {
				if (docsResp.ok) {
					const doc = await docsResp.json();
					// Extract plain text from structured document
					if (doc.body && doc.body.content) {
						const textParts = [];
						const extractText = (elements) => {
							for (const el of elements) {
								if (el.paragraph && el.paragraph.elements) {
									for (const elem of el.paragraph.elements) {
										if (
											elem.textRun &&
											elem.textRun.content
										) {
											textParts.push(
												elem.textRun.content
											);
										}
									}
								}
							}
						};
						extractText(doc.body.content);
						txt = textParts.join('');
					}
				} else {
					// Log diagnostic to help user understand why it failed
					const errTxt = await docsResp.text().catch(() => '');
					console.warn(
						'Docs API request failed',
						docsResp.status,
						docsResp.statusText,
						errTxt
					);
				}
			} catch (oauthErr) {
				console.error('OAuth with user token failed:', oauthErr);
			}
		}

		if (!txt) {
			return res.status(400).json({
				error: 'Failed to fetch Google Doc. Ensure it is public OR shared with the Google account you used to log in. Also verify Docs API is enabled and consent granted.',
			});
		}

		// 3) Parse headings as dates (DD/MM/YYYY). Take last section newer than local latest
		const lines = txt.split(/\r?\n/);
		const dateLineRE = /^(\d{2})[./-](\d{2})[./-](\d{4})$/;
		const sections = [];
		let current = null;
		for (const line of lines) {
			const m = line.trim().match(dateLineRE);
			if (m) {
				if (current) sections.push(current);
				const ddmmyyyy = `${m[1]}/${m[2]}/${m[3]}`; // normalize to slashes
				current = { date: ddmmyyyy, content: [] };
			} else if (current) {
				current.content.push(line);
			}
		}
		if (current) sections.push(current);
		if (sections.length === 0)
			return res
				.status(400)
				.json({
					error: 'No date headings found. Use DD/MM/YYYY, DD.MM.YYYY, or DD-MM-YYYY on its own line.',
				});

		// Find the newest section newer than latestLocal
		let chosen = null;
		for (let i = sections.length - 1; i >= 0; i--) {
			const s = sections[i];
			const d = parseDDMMYYYY(s.date);
			if (!d) continue;
			if (!latestLocal || d > latestLocal) {
				chosen = s;
				break;
			}
		}
		if (!chosen) {
			return res.json({
				message: 'No newer section found',
				created: null,
			});
		}

		const rawText = chosen.content.join('\n').trim();
		const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
		let summary = rawText;
		if (OPENAI_API_KEY && doSummarize) {
			console.log('Summarizing session via OpenAI...');
			try {
				// Determine desired length (default to a rich narrative recap)
				const targetWords = Math.max(
					300,
					Math.min(900, Number(summaryTargetWords) || 520)
				);
				// Increase token multiplier significantly for Italian (longer words), formatting, and narrative style
				const maxTokens = Math.max(
					800,
					Math.min(6000, Math.ceil(targetWords * 2.5))
				);
				const headers = {
					Authorization: `Bearer ${OPENAI_API_KEY}`,
					'Content-Type': 'application/json',
				};
				if (process.env.OPENAI_ORG_ID)
					headers['OpenAI-Organization'] = process.env.OPENAI_ORG_ID;
				if (process.env.OPENAI_PROJECT_ID)
					headers['OpenAI-Project'] = process.env.OPENAI_PROJECT_ID;

				// Extract explicit dialogue candidates from notes to prevent invention
				const extractDialogues = (src) => {
					const lines = String(src).split(/\r?\n/);
					const map = new Map([
						['O:', 'Owen'],
						['A:', 'Ardi'],
						['F:', 'Farek'],
						['BRUNO>', 'Bruno'],
						['BRUNO:', 'Bruno'],
						['OWEN:', 'Owen'],
						['ARDI:', 'Ardi'],
						['FAREK:', 'Farek'],
						['LYSARA:', 'Lysara'],
						['OBYRON:', 'Obyron'],
						['RAIDAN:', 'Raidan'],
					]);
					const found = [];
					for (const raw of lines) {
						const line = raw.trim();
						if (!line) continue;
						let matched = false;
						for (const [mk, name] of map.entries()) {
							if (line.startsWith(mk)) {
								let content = line.slice(mk.length).trim();
								if (content)
									found.push({
										speaker: name,
										text: content,
									});
								matched = true;
								break;
							}
						}
						if (matched) continue;
						const m = line.match(
							/^(Owen|Ardi|Farek|Bruno|Lysara|Obyron|Raidan)\s*:\s*(.+)$/i
						);
						if (m) {
							found.push({
								speaker:
									m[1][0].toUpperCase() +
									m[1].slice(1).toLowerCase(),
								text: m[2].trim(),
							});
						}
					}
					// Deduplicate and clip
					const uniq = [];
					const seen = new Set();
					for (const d of found) {
						const key = d.speaker + '|' + d.text;
						if (seen.has(key)) continue;
						seen.add(key);
						uniq.push({
							speaker: d.speaker,
							text: d.text.slice(0, 200),
						});
					}
					return uniq.slice(0, 12);
				};
				const allowed = extractDialogues(rawText);
				const allowedList = allowed.length
					? `\n\nUsa SOLO queste battute esplicite se vuoi inserire dialoghi (altrimenti ometti i dialoghi se non bastano):\n` +
					  allowed.map((d) => `- ${d.speaker}: ${d.text}`).join('\n')
					: '';

				const resp = await fetch(
					'https://api.openai.com/v1/chat/completions',
					{
						method: 'POST',
						headers,
						body: JSON.stringify({
							model: 'gpt-4o-mini',
							messages: [
								{
									role: 'system',
									content: `Sei un cronista di sessioni D&D. Scrivi un resoconto narrativo in Italiano in 4–7 paragrafi, con una prosa evocativa, in stile Patrick Rothfuss, ma leggibile. NON INVENTARE NULLA: nessun fatto, nessun dialogo. Riporta SOLO ciò che è presente nelle note. Se compaiono battute dirette (righe con marcatori come O:, A:, F:, BRUNO>), riportale tra virgolette “”, con attribuzione esplicita mappando i marcatori a nomi (Owen, Ardi, Farek, Bruno, Lysara, Obyron, Raidan). Se le battute dirette sono meno di tre, includi solo quelle esistenti; se non ce ne sono, non aggiungere dialoghi. Non parafrasare testo non dialogico come se fosse dialogo. Mantieni i nomi e i dettagli chiave (luoghi, magie, ferite, mosse). Evita preamboli e conclusioni meta; entra subito nell’azione. Preferisci frasi non troppo lunghe. Lunghezza desiderata: ~${targetWords} parole.`,
								},
								{
									role: 'user',
									content: `Trasforma le seguenti note in un resoconto narrativo coerente. Riporta SOLO dialoghi che appaiono esplicitamente nelle note, fedeli o con minime correzioni di punteggiatura, con il nome del parlante (es. Owen: “…”). Se nelle note compaiono marcatori come O:, A:, F:, BRUNO>, mappali a Owen, Ardi, Farek, Bruno. Se non ci sono battute dirette, non inserirne. NON INVENTARE fatti o battute. Mantieni l’atmosfera e i nomi.${allowedList}\n\n${rawText}`,
								},
							],
							temperature: 0.7,
							max_completion_tokens: maxTokens,
						}),
					}
				);
				const data = await resp.json();
				const choice = data?.choices?.[0];
				const finishReason = choice?.finish_reason;
				const content =
					choice?.message?.content?.trim() || choice?.text?.trim();

				// Log if the response was truncated
				if (finishReason === 'length') {
					console.warn(
						`OpenAI response was truncated. Consider increasing max_completion_tokens (current: ${maxTokens})`
					);
				}

				if (content) summary = content;
			} catch (e) {
				console.error('OpenAI call failed', e);
			}
		}

		// 4) Create a draft campaign page with one rich block from summary
		// Split summary into paragraphs for better formatting in the editor
		const paragraphs = String(summary)
			.replace(/\r\n/g, '\n')
			.split(/\n{2,}/)
			.map((p) => p.trim())
			.filter(Boolean);

		console.log(
			`Summary length: ${summary.length} chars, ${paragraphs.length} paragraphs`
		);

		const tiptap = {
			type: 'doc',
			content:
				paragraphs.length > 0
					? paragraphs.map((p) => ({
							type: 'paragraph',
							content: [{ type: 'text', text: p }],
					  }))
					: [
							{
								type: 'paragraph',
								content: [{ type: 'text', text: summary }],
							},
					  ],
		};
		const pageTitle = customTitle?.trim() || `Session ${chosen.date}`;
		const page = await Page.create({
			title: pageTitle,
			type: 'campaign',
			subtitle: '',
			blocks: [{ type: 'rich', rich: tiptap, plainText: summary }],
			sessionDate: chosen.date,
			worldDate: worldDate || null,
			draft: true,
		});

		console.log(
			`Created page with ${page.blocks[0].plainText.length} chars in plainText`
		);

		// 5) Also create a timeline event in the Campaign group
		let campaignGroup = await Group.findOne({
			name: { $regex: /(campaign|session)/i },
		});
		if (!campaignGroup) {
			// If no groups exist yet, create the Campaign group automatically
			const count = await Group.countDocuments();
			campaignGroup = await Group.create({
				name: 'Campaign',
				order: count,
			});
		}
		let createdEvent = null;
		try {
			createdEvent = await Event.create({
				title: pageTitle,
				type: 'campaign',
				startDate: chosen.date,
				groupId: campaignGroup?._id,
				pageId: page._id,
				detailLevel: 'Day',
				linkSync: true,
				hidden: true,
			});
		} catch (e) {
			console.warn(
				'Failed to auto-create campaign event:',
				e?.message || e
			);
		}

		res.json({ created: page, event: createdEvent });
	} catch (e) {
		console.error('/sync/campaign/from-google failed', e);
		res.status(500).json({ error: 'Internal error' });
	}
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

// -----------------------------------------------------------------------------
// Test endpoint: OpenAI summarization sandbox for DMs
// -----------------------------------------------------------------------------
app.post('/test/openai/summarize', async (req, res) => {
	try {
		const {
			text,
			model,
			language = 'it',
			bulletPoints = false,
			targetWords = 520,
			temperature = 0.3,
			style = 'narrative', // 'neutral' | 'executive' | 'narrative'
			returnPrompt = true,
		} = req.body || {};

		if (!text || typeof text !== 'string' || !text.trim()) {
			return res.status(400).json({ error: 'text is required' });
		}
		const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
		if (!OPENAI_API_KEY) {
			return res
				.status(400)
				.json({ error: 'OPENAI_API_KEY missing on server' });
		}

		// Default to a reliable, inexpensive model that supports temperature
		const modelToUse = model || 'gpt-4o-mini';

		// Build a clear, testable prompt with explicit constraints
		const langHint = language === 'it' ? 'Italiano' : 'English';
		const lengthRule = `Keep it under ~${targetWords} words.`;
		const styleRule =
			style === 'executive'
				? 'Use crisp, non-poetic language suitable for an executive summary.'
				: style === 'narrative'
				? 'Use a light narrative tone, but stay concise and avoid flowery prose.'
				: 'Use neutral, concise language.';
		const formatRule = bulletPoints
			? 'Return 5–8 bullet points, each on its own line. No preamble.'
			: 'Return a single concise paragraph. No preamble.';

		// Extract explicit dialogue candidates from input text to prevent invention
		const extractDialogues = (src) => {
			const lines = String(src).split(/\r?\n/);
			const map = new Map([
				['O:', 'Owen'],
				['A:', 'Ardi'],
				['F:', 'Farek'],
				['BRUNO>', 'Bruno'],
				['BRUNO:', 'Bruno'],
				['OWEN:', 'Owen'],
				['ARDI:', 'Ardi'],
				['FAREK:', 'Farek'],
				['LYSARA:', 'Lysara'],
				['OBYRON:', 'Obyron'],
				['RAIDAN:', 'Raidan'],
			]);
			const found = [];
			for (const raw of lines) {
				const line = raw.trim();
				if (!line) continue;
				let matched = false;
				for (const [mk, name] of map.entries()) {
					if (line.startsWith(mk)) {
						let content = line.slice(mk.length).trim();
						if (content)
							found.push({ speaker: name, text: content });
						matched = true;
						break;
					}
				}
				if (matched) continue;
				const m = line.match(
					/^(Owen|Ardi|Farek|Bruno|Lysara|Obyron|Raidan)\s*:\s*(.+)$/i
				);
				if (m) {
					found.push({
						speaker:
							m[1][0].toUpperCase() + m[1].slice(1).toLowerCase(),
						text: m[2].trim(),
					});
				}
			}
			const uniq = [];
			const seen = new Set();
			for (const d of found) {
				const key = d.speaker + '|' + d.text;
				if (seen.has(key)) continue;
				seen.add(key);
				uniq.push({ speaker: d.speaker, text: d.text.slice(0, 200) });
			}
			return uniq.slice(0, 12);
		};
		const allowed = extractDialogues(text);
		const allowedList = allowed.length
			? `\n\nUse ONLY these explicit lines if you include dialogue (otherwise omit dialogue if none match):\n` +
			  allowed.map((d) => `- ${d.speaker}: ${d.text}`).join('\n')
			: '';

		const systemPrompt = `You are a narrative chronicler for D&D sessions. Always:
${lengthRule}
${styleRule}
Write in ${langHint}.
Return 4–7 short paragraphs separated by blank lines.
DO NOT INVENT ANYTHING: no facts, no dialogues. Include ONLY direct quotes that explicitly appear in the notes (verbatim or with minimal punctuation cleanup), with speaker attribution (e.g., Ardi: “…”). If the notes contain markers like O:, A:, F:, BRUNO>, map them to names (Owen, Ardi, Farek, Bruno, Lysara, Obyron, Raidan). If fewer than 3 quotes exist, include only those; if none exist, include zero dialogues. Do not paraphrase non-dialogue text as dialogue. Preserve names, places, spells, wounds.
Avoid meta prefaces—start in medias res.`;
		const userPrompt = `Trasforma le note in un resoconto narrativo coerente. Riporta SOLO dialoghi che compaiono esplicitamente nelle note (con eventuali minime correzioni di punteggiatura), con attribuzione del parlante (es. Owen: “…”). Se nelle note compaiono marcatori come O:, A:, F:, BRUNO>, mappali a Owen, Ardi, Farek, Bruno, Lysara, Obyron, Raidan. Se i dialoghi espliciti sono meno di tre, includi solo quelli; se non ci sono, non inserirne. NON INVENTARE fatti o battute. Mantieni atmosfera ed eventi.${allowedList}\n\n${text}`;

		// Approximate token cap from target words (roughly 1.5 tokens per word)
		const maxTokens = Math.max(
			64,
			Math.min(2048, Math.ceil((targetWords || 120) * 1.5))
		);

		const headers = {
			Authorization: `Bearer ${OPENAI_API_KEY}`,
			'Content-Type': 'application/json',
		};
		// Optional org/project headers if provided via env (helps route billing correctly)
		if (process.env.OPENAI_ORG_ID)
			headers['OpenAI-Organization'] = process.env.OPENAI_ORG_ID;
		if (process.env.OPENAI_PROJECT_ID)
			headers['OpenAI-Project'] = process.env.OPENAI_PROJECT_ID;

		// Build request body and include temperature only for models that support it
		const body = {
			model: modelToUse,
			max_completion_tokens: maxTokens,
			messages: [
				{ role: 'system', content: systemPrompt },
				{ role: 'user', content: userPrompt },
			],
		};
		const supportsTemperature =
			/4o|gpt-4|mini|turbo/i.test(modelToUse) &&
			!/gpt-5/i.test(modelToUse);
		if (supportsTemperature) {
			body.temperature =
				typeof temperature === 'number' ? temperature : 0.7;
		}

		const resp = await fetch('https://api.openai.com/v1/chat/completions', {
			method: 'POST',
			headers,
			body: JSON.stringify(body),
		});
		const data = await resp.json();
		if (!resp.ok) {
			return res.status(resp.status).json({
				error: 'OpenAI request failed',
				status: resp.status,
				details: data,
			});
		}

		// Extract output - handle standard and alternative formats
		const choice = data?.choices?.[0];
		let output = '';
		if (choice?.message?.content) {
			output = String(choice.message.content).trim();
		} else if (choice?.text) {
			output = String(choice.text).trim();
		}

		if (!output && choice) {
			console.log(
				'Empty output detected. Full choice:',
				JSON.stringify(choice, null, 2)
			);
		}

		return res.json({
			ok: true,
			usedOpenAI: true,
			model: modelToUse,
			output,
			usage: data?.usage || null,
			rawChoice: !output ? choice : undefined,
			prompt: returnPrompt
				? { system: systemPrompt, user: userPrompt }
				: undefined,
			params: { language, bulletPoints, targetWords, temperature, style },
		});
	} catch (err) {
		console.error('TEST /test/openai/summarize failed', err);
		return res.status(500).json({ error: 'Internal error' });
	}
});
