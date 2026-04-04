import { TimeSystem } from "../models.js";
import { formatEventDate } from "../utils/time.js";

const LIGHTRAG_ENDPOINT =
	process.env.NODE_ENV === "development"
		? process.env.LIGHTRAG_ENDPOINT
		: `${process.env.FRONTEND_ORIGIN}/lightrag`;
const LIGHTRAG_API_KEY = process.env.LIGHTRAG_API_KEY;

export const sendToLightRag = async (page) => {
	try {
		const lightRagBaseUrl = LIGHTRAG_ENDPOINT;
		const apiKey = process.env.LIGHTRAG_API_KEY;

		if (!lightRagBaseUrl || !apiKey) {
			console.warn(
				"LIGHTRAG_ENDPOINT or LIGHTRAG_API_KEY not set. Skipping LightRag upload.",
			);
			return;
		}

		// Check if page already has a lightRagDocumentName and delete it first
		if (page.lightRagDocumentName) {
			console.log(
				`Deleting existing LightRag document: ${page.lightRagDocumentName}`,
			);
			const deleted = await deleteDocument(page.lightRagDocumentName);
			if (!deleted) {
				console.warn(
					`Failed to delete existing LightRag document: ${page.lightRagDocumentName}`,
				);
			}
		}

		let contentText = "";
		if (page.blocks && page.blocks.length > 0) {
			contentText = page.blocks
				.map((block) => block.plainText || "")
				.join("\n");
		} else {
			return null;
		}

		// Use the endpoint as-is from .env without cleaning
		const url = `${lightRagBaseUrl}/documents/text`;
		let fileSource = page.title;

		const ts = await TimeSystem.findOne();
		const tsConfig = ts?.config || null;
		if (tsConfig && page.worldDate != null) {
			let worldDate = formatEventDate(
				tsConfig,
				page.worldDate.eraId,
				page.worldDate.year,
				page.worldDate.monthIndex,
				page.worldDate.day,
			);

			if (page.worldDate.hour != null) {
				let minutes =
					!page.worldDate.minute || page.worldDate.minute === 0
						? "00"
						: page.worldDate.minute;
				worldDate += ` ore ${page.worldDate.hour}:${minutes}`;
			}

			if (worldDate) {
				fileSource = `${page.type} - ${fileSource} - (${worldDate})`;
				contentText = `${worldDate} - ${contentText}`;
			}
		}

		const payload = {
			text: contentText,
			file_source: fileSource,
		};
		console.log(process.env.NODE_ENV);
		console.log("LightRag URL: " + url);
		const response = await fetch(url, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-API-Key": apiKey,
			},
			body: JSON.stringify(payload),
		});

		console.log(`LIGHTRAG: ${response.status} - ${response.statusText}`);
		if (response.ok) {
			const data = await response.json();
			console.log("Saved to LightRag:", data);
			if (
				data.status &&
				(data.status === "success" || data.status === "duplicated")
			) {
				data.fileSource = fileSource;
				console.log(`LIGHTRAG: ${data.status} - ${data.message}`);
				return data;
			} else {
				console.warn(`LIGHTRAG: ${data.status} - ${data.message}`);
				throw new Error(data.message);
			}
		} else {
			throw new Error(response.statusText);
		}
	} catch (err) {
		console.warn("Error saving to LightRag server:", err);
		return { status: "error", message: err.message };
	}
};

const findDocumentByFilePath = async ({
	lightRagBaseUrl,
	apiKey,
	filePath,
}) => {
	const url = `${lightRagBaseUrl}/documents`;

	const response = await fetch(url, {
		method: "GET",
		headers: {
			"X-API-Key": apiKey,
		},
	});

	if (!response.ok) {
		return null;
	}

	const data = await response.json();
	const documents = Array.isArray(data?.documents)
		? data.documents
		: data?.statuses
			? Object.values(data.statuses).flat()
			: Array.isArray(data)
				? data
				: [];

	return documents.find((doc) => doc.file_path === filePath) ?? null;
};

export const checkDocumentExists = async (id) => {
	try {
		const lightRagBaseUrl = LIGHTRAG_ENDPOINT;
		const apiKey = process.env.LIGHTRAG_API_KEY;

		if (!lightRagBaseUrl || !apiKey) {
			console.warn(
				"LIGHTRAG_ENDPOINT or LIGHTRAG_API_KEY not set. Skipping check.",
			);
			return false;
		}

		// Use the endpoint as-is from .env without cleaning
		const document = await findDocumentByFilePath({
			lightRagBaseUrl,
			apiKey,
			filePath: id,
		});

		return Boolean(document);
	} catch (err) {
		console.error("Error checking document existence:", err);
		return false;
	}
};

export const deleteDocument = async (id) => {
	try {
		const lightRagBaseUrl = process.env.LIGHTRAG_ENDPOINT;
		const apiKey = process.env.LIGHTRAG_API_KEY;

		if (!lightRagBaseUrl || !apiKey) {
			console.warn(
				"LIGHTRAG_ENDPOINT or LIGHTRAG_API_KEY not set. Skipping delete.",
			);
			return false;
		}

		// Use the endpoint as-is from .env without cleaning
		const document = await findDocumentByFilePath({
			lightRagBaseUrl,
			apiKey,
			filePath: id,
		});

		if (!document?.id) {
			return false;
		}

		const deleteUrl = `${lightRagBaseUrl}/documents/delete_document`;

		const response = await fetch(deleteUrl, {
			method: "DELETE",
			headers: {
				"Content-Type": "application/json",
				"X-API-Key": apiKey,
			},
			body: JSON.stringify({
				doc_ids: [document.id],
				delete_file: false,
				delete_llm_cache: false,
			}),
		});

		return response.ok;
	} catch (err) {
		console.error("Error deleting document:", err);
		return false;
	}
};
