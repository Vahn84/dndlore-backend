import 'dotenv/config';
import mongoose from 'mongoose';
import { User, Group, Page, Event, TimeSystem } from './models.js';

async function seed() {
	const MONGO_URI =
		process.env.MONGO_URI ||
		'mongodb+srv://fabiocingolani84_db_user:J4myJn6z59xHGXc@dndlore.njjnky5.mongodb.net/?appName=DndLore';
	await mongoose.connect(MONGO_URI, {dbName: 'data'});
	console.log('Connected to MongoDB');
	// Cancella dati esistenti
	await User.deleteMany({});
	await Group.deleteMany({});
	await Page.deleteMany({});
	await Event.deleteMany({});
	await TimeSystem.deleteMany({});
	// Crea utenti
	const dm = await User.create({
		email: 'fabiocingolani84@gmail.com',
		role: 'DM',
	});
	// Crea gruppi
	const group1 = await Group.create({ name: 'Divine Era', order: 0 });
	const group2 = await Group.create({ name: 'Immortals Era', order: 1 });
	// Crea pagina di esempio
	const page1 = await Page.create({
		title: "Andrann'Ea - Il ciclo della creazione",
		type: 'history',
		bannerUrl: '',
		content: [
			{
				type: 'text',
				text: 'Kiriel, in perenne riflessione...',
				hidden: false,
			},
			{ type: 'text', text: 'Altro testo di esempio.', hidden: false },
		],
		hidden: false,
		hiddenSections: [],
		draft: false,
	});
	// Crea evento di esempio
	await Event.create({
		title: "Andrann'Ea - Il ciclo della creazione",
		type: 'history',
		startDate: '10000, DE',
		endDate: '9000, DE',
		bannerUrl: '',
		groupId: group1._id,
		pageId: page1._id,
		order: 0,
		hidden: false,
		color: '#63a4ff',
	});

	// Crea time system di esempio se non esiste
	await TimeSystem.create({
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
			erasStartOnZeroYear: true,
			dateFormats: {
				year: 'YYYY, E',
				yearMonth: 'MMMM YYYY, E',
				yearMonthDay: 'D^ MMMM YYYY, E',
				yearMonthDayTime: 'D^ MMMM YYYY, HH:mm, E',
			},
		},
	});
	console.log('Seed completed');
	process.exit(0);
}

seed().catch((err) => {
	console.error(err);
	process.exit(1);
});
