import mongoose from 'mongoose';

// Schema e modelli Mongoose per utenti, gruppi, pagine ed eventi

const userSchema = new mongoose.Schema({
	email: { type: String },
	role: { type: String, enum: ['DM', 'PLAYER'], default: 'PLAYER' },
});

// Groups represent eras or categories of events on the timeline
const groupSchema = new mongoose.Schema({
	// Human‑readable name of the group/era
	name: { type: String, required: true },
	// Manual ordering for display
	order: { type: Number, default: 0 },
	color: { type: String },
});

// I blocchi della pagina possono contenere testo o immagine e un flag hidden opzionale
const pageBlockSchema = new mongoose.Schema(
	{
		type: { type: String, enum: ['text', 'image'], required: true },
		text: { type: String },
		url: { type: String },
		hidden: { type: Boolean, default: false },
	},
	{ _id: false }
);

const pageSchema = new mongoose.Schema(
	{
		// Title of the lore page
		title: { type: String, required: true },
		// Type of lore page: place, history, myth, people, campaign
		type: {
			type: String,
			enum: ['place', 'history', 'myth', 'people', 'campaign'],
			required: true,
		},
		// Optional banner image URL
		bannerUrl: { type: String },
		// Array of content blocks
		content: { type: [pageBlockSchema], default: [] },
		// If true, the entire page is hidden from public view
		hidden: { type: Boolean, default: false },
		// Store indexes of blocks that should be hidden from public
		hiddenSections: { type: [Number], default: [] },
		// Draft flag: if true, the page is not published
		draft: { type: Boolean, default: false },
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
		endEraId: { type: String },
		endYear: { type: Number },
		endMonthIndex: { type: Number },
		endDay: { type: Number },
		bannerUrl: { type: String },
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
		createdAt: { type: Date, default: Date.now },
	},
	{ collection: 'assets' }
);

export const User = mongoose.model('User', userSchema);
export const Group = mongoose.model('Group', groupSchema);
export const Page = mongoose.model('Page', pageSchema);
export const Event = mongoose.model('Event', eventSchema);
export const Asset = mongoose.model('Asset', AssetSchema);

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
