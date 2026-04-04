/**
 * cleanup-lightrag.js
 *
 * Checks every page that has a lightRagDocumentName and verifies whether
 * the document actually exists in LightRAG. Pages with stale/dirty data
 * (document not found in LightRAG) get their lightRagDocumentName cleared.
 *
 * Usage:
 *   node scripts/cleanup-lightrag.js          # dry run — shows what would be cleared
 *   node scripts/cleanup-lightrag.js --fix    # actually clears dirty data
 */

import "dotenv/config";
import mongoose from "mongoose";

const LIGHTRAG_ENDPOINT = process.env.LIGHTRAG_ENDPOINT;
const LIGHTRAG_API_KEY  = process.env.LIGHTRAG_API_KEY;
const MONGO_URI         = process.env.MONGO_URI;
const DRY_RUN           = !process.argv.includes("--fix");

// ---------------------------------------------------------------------------
// Minimal Page model (only what we need)
// ---------------------------------------------------------------------------
const pageSchema = new mongoose.Schema({ lightRagDocumentName: { type: String } }, {
	strict: false,
	timestamps: true,
});
const Page = mongoose.model("Page", pageSchema);

// ---------------------------------------------------------------------------
// LightRAG helpers
// ---------------------------------------------------------------------------
async function fetchAllDocuments() {
	const res = await fetch(`${LIGHTRAG_ENDPOINT}/documents`, {
		headers: { "X-API-Key": LIGHTRAG_API_KEY },
	});
	if (!res.ok) throw new Error(`LightRAG /documents returned ${res.status}`);
	const data = await res.json();

	// Handle different response shapes
	if (Array.isArray(data?.documents))       return data.documents;
	if (data?.statuses)                        return Object.values(data.statuses).flat();
	if (Array.isArray(data))                   return data;
	return [];
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
	console.log(`\n🔍 LightRAG cleanup script — ${DRY_RUN ? "DRY RUN (pass --fix to apply)" : "LIVE FIX"}\n`);

	await mongoose.connect(MONGO_URI);
	console.log("✓ Connected to MongoDB");

	// Fetch pages that have a lightRagDocumentName set
	const pages = await Page.find(
		{ lightRagDocumentName: { $exists: true, $ne: null, $ne: "" } },
		{ _id: 1, lightRagDocumentName: 1, title: 1 }
	).lean();

	console.log(`✓ Found ${pages.length} pages with lightRagDocumentName set\n`);

	if (pages.length === 0) {
		console.log("Nothing to check. Exiting.");
		await mongoose.disconnect();
		return;
	}

	// Fetch all documents from LightRAG once (cheaper than one call per page)
	console.log("⟳ Fetching documents from LightRAG...");
	let lightragDocs = [];
	try {
		lightragDocs = await fetchAllDocuments();
		console.log(`✓ LightRAG has ${lightragDocs.length} documents\n`);
	} catch (err) {
		console.error(`✗ Could not reach LightRAG: ${err.message}`);
		await mongoose.disconnect();
		process.exit(1);
	}

	// Build a set of known file_paths for fast lookup
	const knownPaths = new Set(lightragDocs.map((d) => d.file_path).filter(Boolean));

	// ---------------------------------------------------------------------------
	// Check each page
	// ---------------------------------------------------------------------------
	let clean  = 0;
	let dirty  = 0;
	let fixed  = 0;

	for (const page of pages) {
		const docName = page.lightRagDocumentName;
		const exists  = knownPaths.has(docName);
		const label   = page.title ?? page._id;

		if (exists) {
			console.log(`  ✓ CLEAN    "${label}"  →  "${docName}"`);
			clean++;
		} else {
			console.log(`  ✗ DIRTY    "${label}"  →  "${docName}"  (not found in LightRAG)`);
			dirty++;

			if (!DRY_RUN) {
				await Page.updateOne(
					{ _id: page._id },
					{ $unset: { lightRagDocumentName: "" } }
				);
				fixed++;
			}
		}
	}

	// ---------------------------------------------------------------------------
	// Summary
	// ---------------------------------------------------------------------------
	console.log("\n─────────────────────────────────────────");
	console.log(`  Clean  : ${clean}`);
	console.log(`  Dirty  : ${dirty}`);
	if (DRY_RUN) {
		console.log(`  Fixed  : 0  (dry run — run with --fix to apply)`);
	} else {
		console.log(`  Fixed  : ${fixed}`);
	}
	console.log("─────────────────────────────────────────\n");

	await mongoose.disconnect();
}

main().catch((err) => {
	console.error("Fatal error:", err);
	process.exit(1);
});
