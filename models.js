import mongoose from 'mongoose';

// Schema e modelli Mongoose per utenti, gruppi, pagine ed eventi

const userSchema = new mongoose.Schema({
	email: { type: String },
	role: { type: String, enum: ['DM', 'PLAYER'], default: 'PLAYER' },
	googleAccessToken: { type: String },
	googleRefreshToken: { type: String },
	googleTokenExpiry: { type: Date },
});

// Groups represent eras or categories of events on the timeline
const groupSchema = new mongoose.Schema({
	// Human‑readable name of the group/era
	name: { type: String, required: true },
	// Manual ordering for display
	order: { type: Number, default: 0 },
	color: { type: String },
	// Exclusive groups hide all others when selected
	exclude: { type: Boolean, default: false },
	// Sort direction for exclusive groups
	orderAscending: { type: Boolean, default: true },
	// Default selection when no filter is provided
	defaultSelected: { type: Boolean, default: false },
});

// I blocchi della pagina possono contenere testo o immagine e un flag hidden opzionale
const pageBlockSchema = new mongoose.Schema(
	{
		id: { type: String }, // optional client-side id
		type: { type: String, enum: ['rich', 'image'], required: true },
		hidden: { type: Boolean, default: false },

		// Rich block payload (TipTap JSON)
		rich: { type: mongoose.Schema.Types.Mixed },
		plainText: { type: String, default: '' },

		// Image block payload
		url: { type: String },
	},
	{ _id: false, strict: true }
);

const pageSchema = new mongoose.Schema(
	{
		// Title of the lore page
		title: { type: String, required: true },
		subtitle: { type: String, default: '' },
		// Type of lore page: place, history, myth, people, campaign
		type: {
			type: String,
			enum: ['place', 'history', 'myth', 'people', 'campaign'],
			required: true,
		},
		// For place pages: specify if it's a region or city
		placeType: {
			type: String,
			enum: ['region', 'city'],
		},
		// Map coordinates for place pages
		coordinates: {
			type: {
				type: String,
				enum: ['point', 'polygon'],
			},
			data: {
				// For points (cities)
				x: { type: Number }, // normalized 0-1
				y: { type: Number }, // normalized 0-1
				// For polygons (regions)
				points: [
					{
						x: { type: Number },
						y: { type: Number },
						_id: false,
					},
				],
			},
			// Reference to parent region (for cities)
			parentRegionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Page' },
			// Styling for regions
			borderColor: { type: String },
			fillColor: { type: String },
		},
		// Optional banner image URL
		bannerUrl: { type: String },
		// Optional banner thumbnail URL (generated from bannerUrl if it's an uploaded image)
		bannerThumbUrl: { type: String },
		// Optional asset ID for city icon on map
		assetId: { type: String },
		// Array of content blocks
		blocks: { type: [pageBlockSchema], default: [] },
		// Real-world session date for campaign pages (DD/MM/YYYY)
		sessionDate: { type: String },
		// In-world date for campaign pages (custom calendar)
	worldDate: {
		eraId: { type: String },
		year: { type: Number },
		monthIndex: { type: Number },
		day: { type: Number },
		hour: { type: Number },
		minute: { type: Number },
	},
		// If true, the entire page is hidden from public view
		hidden: { type: Boolean, default: false },
		// Draft flag: if true, the page is not published
		draft: { type: Boolean, default: false },
		// Manual ordering for display within the same type (lower numbers appear first)
		order: { type: Number, default: 0 },
	},
	{ timestamps: true }
);

const eventSchema = new mongoose.Schema(
	{
		// Title of the event
		title: { type: String, required: true },
		// Category/type of event: history or campaign (others can be extended)
		type: {
			type: String,
			enum: ['history', 'campaign', 'other'],
			default: 'history',
		},
		startDate: { type: String },
		endDate: { type: String },
		startEraId: { type: String },
		startYear: { type: Number },
		startMonthIndex: { type: Number },
		startDay: { type: Number },
		startHour: { type: Number },
		startMinute: { type: Number },
		endEraId: { type: String },
		endYear: { type: Number },
		endMonthIndex: { type: Number },
		endDay: { type: Number },
		endHour: { type: Number },
		endMinute: { type: Number },
		bannerUrl: { type: String },
		// Banner thumbnail URL (for timeline/list display)
		bannerThumbUrl: { type: String },
		// Reference to the group/era this event belongs to
		groupId: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' },
		// Reference to the linked lore page (optional)
		pageId: { type: mongoose.Schema.Types.ObjectId, ref: 'Page' },
		// Manual order for drag‑and‑drop sorting
		order: { type: Number, default: 0 },
		// If true, this event is hidden from public
		hidden: { type: Boolean, default: false },
		// Colour used for the event card
		color: { type: String },
		icon: { type: String },
		// Sync flag: when true and pageId is set, keep title, banner, and worldDate synced from the linked page
		linkSync: { type: Boolean, default: false },
		// How detailed to display the date for this event in the UI
		detailLevel: {
			type: String,
			enum: ['Year', 'Month', 'Day'],
			default: 'Year',
		},
	},
	{ timestamps: true }
);

const AssetSchema = new mongoose.Schema(
	{
		url: { type: String, required: true },
		thumb_url: { type: String },
		folderId: { type: mongoose.Schema.Types.ObjectId, ref: 'AssetFolder', default: null },
		createdAt: { type: Date, default: Date.now },
	},
	{ collection: 'assets' }
);

const AssetFolderSchema = new mongoose.Schema(
	{
		name: { type: String, required: true },
		createdAt: { type: Date, default: Date.now },
	},
	{ collection: 'assetfolders' }
);

export const User = mongoose.model('User', userSchema);
export const Group = mongoose.model('Group', groupSchema);
export const Page = mongoose.model('Page', pageSchema);
export const Event = mongoose.model('Event', eventSchema);
export const Asset = mongoose.model('Asset', AssetSchema);
export const AssetFolder = mongoose.model('AssetFolder', AssetFolderSchema);

// Time system configuration stored as a single document. The config field
// contains the full TimeSystemConfig object used by the frontend. If no
// document exists, the server should return a sensible default in
// `/time-system` route.
const timeSystemSchema = new mongoose.Schema(
	{
		config: { type: mongoose.Schema.Types.Mixed, required: true },
	},
	{ timestamps: true }
);

export const TimeSystem = mongoose.model('TimeSystem', timeSystemSchema);
