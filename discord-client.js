import { Client, GatewayIntentBits, GuildScheduledEventPrivacyLevel, GuildScheduledEventEntityType } from 'discord.js';
import https from 'https';
import http from 'http';
import fs from 'fs';
import path from 'path';

// Bypass TLS certificate validation for public/free WiFi networks
// Must be set before any HTTPS/WSS connections are made
if (process.env.NODE_ENV === 'development' || process.env.ALLOW_INVALID_CERTS === 'true' || !process.env.NODE_ENV) {
	process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
	console.log('TLS certificate validation disabled for Discord (development mode)');
}

/**
 * Discord Bot Client Singleton
 * Manages connection to Discord and provides methods for:
 * - Fetching text channels
 * - Creating scheduled events
 */
class DiscordClient {
	constructor() {
		this.client = null;
		this.ready = false;
		this.guildId = process.env.DISCORD_GUILD_ID;
		this.token = process.env.DISCORD_BOT_TOKEN;
	}

	/**
	 * Initialize and login the Discord bot
	 */
	async connect() {
		if (this.ready) {
			console.log('Discord bot already connected');
			return;
		}

		if (!this.token) {
			console.warn('DISCORD_BOT_TOKEN not set. Discord integration disabled.');
			return;
		}

		if (!this.guildId) {
			console.warn('DISCORD_GUILD_ID not set. Discord integration disabled.');
			return;
		}

		try {
			this.client = new Client({
				intents: [
					GatewayIntentBits.Guilds,
					GatewayIntentBits.GuildScheduledEvents,
				],
			});

			this.client.once('clientReady', () => {
				console.log(`Discord bot logged in as ${this.client.user.tag}`);
				this.ready = true;
			});

			this.client.on('error', (error) => {
				console.error('Discord client error:', error);
			});

			await this.client.login(this.token);
		} catch (error) {
			console.error('Failed to connect Discord bot:', error.message || error);
			
			// Check if this is a network/captive portal issue (HTML response instead of JSON)
			if (error.rawError && error.status === 403) {
				console.warn('Discord connection blocked - likely by public WiFi captive portal or firewall.');
				console.warn('Discord integration will be disabled. Please connect to a different network or use a VPN.');
			}
			
			this.ready = false;
			this.client = null;
		}
	}

	/**
	 * Get the guild object
	 */
	async getGuild() {
		if (!this.ready || !this.client) {
			throw new Error('Discord bot not ready');
		}

		const guild = await this.client.guilds.fetch(this.guildId);
		if (!guild) {
			throw new Error(`Guild ${this.guildId} not found`);
		}

		return guild;
	}

	/**
	 * Fetch all text channels in the configured guild
	 * @returns {Promise<Array<{id: string, name: string}>>}
	 */
	async getTextChannels() {
		try {
			const guild = await this.getGuild();
			const channels = await guild.channels.fetch();

			// Filter to text channels only (type 0 = GUILD_TEXT)
			const textChannels = channels
				.filter((channel) => channel.type === 0)
				.map((channel) => ({
					id: channel.id,
					name: channel.name,
				}))
				.sort((a, b) => a.name.localeCompare(b.name));

			return textChannels;
		} catch (error) {
			console.error('Failed to fetch Discord channels:', error);
			throw error;
		}
	}

	/**
	 * Fetch all voice channels in the configured guild
	 * @returns {Promise<Array<{id: string, name: string}>>}
	 */
	async getVoiceChannels() {
		try {
			const guild = await this.getGuild();
			const channels = await guild.channels.fetch();

			// Filter to voice channels only (type 2 = GUILD_VOICE)
			const voiceChannels = channels
				.filter((channel) => channel.type === 2)
				.map((channel) => ({
					id: channel.id,
					name: channel.name,
				}))
				.sort((a, b) => a.name.localeCompare(b.name));

			return voiceChannels;
		} catch (error) {
			console.error('Failed to fetch Discord voice channels:', error);
			throw error;
		}
	}

	/**
	 * Create a scheduled event in Discord
	 * @param {Object} options
	 * @param {string} options.name - Event name
	 * @param {string} options.description - Event description
	 * @param {Date} options.scheduledStartTime - When the event starts
	 * @param {Date} [options.scheduledEndTime] - When the event ends (optional, defaults to +2 hours)
	 * @param {string} [options.voiceChannelId] - Voice/Stage channel ID for the event location
	 * @param {string} [options.image] - Event cover image URL (optional)
	 * @returns {Promise<Object>} Created event object
	 */
	async createScheduledEvent(options) {
		try {
			const guild = await this.getGuild();

			const {
				name,
				description = '',
				scheduledStartTime,
				scheduledEndTime = new Date(scheduledStartTime.getTime() + 3 * 60 * 60 * 1000), // +3 hours default
				voiceChannelId,
				image,
			} = options;

			// Validate required fields
			if (!name) {
				throw new Error('Event name is required');
			}
			if (!scheduledStartTime || !(scheduledStartTime instanceof Date)) {
				throw new Error('Valid scheduledStartTime (Date) is required');
			}

			const eventOptions = {
				name,
				description,
				scheduledStartTime,
				scheduledEndTime,
				privacyLevel: GuildScheduledEventPrivacyLevel.GuildOnly,
			};

			// If voice channel is provided, set it as voice event, otherwise external
			if (voiceChannelId) {
				eventOptions.entityType = GuildScheduledEventEntityType.Voice;
				eventOptions.channel = voiceChannelId;
			} else {
				eventOptions.entityType = GuildScheduledEventEntityType.External;
				eventOptions.entityMetadata = {
					location: 'External',
				};
			}

			// Add image if provided - convert to base64 data URI
			if (image) {
				try {
					let imageBuffer;
					let imageUrl = image;
					
					// If it's a relative /uploads/ path, read from file system directly
					if (image.startsWith('/uploads/')) {
						console.log('Reading event image from local file system:', image);
						const filePath = path.join(process.cwd(), image);
						imageBuffer = fs.readFileSync(filePath);
					} else {
						// Otherwise fetch from URL
						imageUrl = image.startsWith('http') ? image : `${process.env.FRONTEND_URL || 'http://localhost:3000'}${image}`;
						console.log('Fetching event image from URL:', imageUrl);
						
						// Use https or http based on URL
						const protocol = imageUrl.startsWith('https') ? https : http;
						
						imageBuffer = await new Promise((resolve, reject) => {
							protocol.get(imageUrl, (response) => {
								if (response.statusCode !== 200) {
									reject(new Error(`Failed to fetch image: ${response.statusCode}`));
									return;
								}
								
								const chunks = [];
								response.on('data', (chunk) => chunks.push(chunk));
								response.on('end', () => resolve(Buffer.concat(chunks)));
								response.on('error', reject);
							}).on('error', reject);
						});
					}
					
					// Detect image type from URL/path extension
					let mimeType = 'image/png';
					if (image.match(/\.(jpg|jpeg)$/i)) {
						mimeType = 'image/jpeg';
					} else if (image.match(/\.webp$/i)) {
						mimeType = 'image/webp';
					} else if (image.match(/\.gif$/i)) {
						mimeType = 'image/gif';
					}
					
					// Convert buffer to base64 data URI
					const base64Image = imageBuffer.toString('base64');
					const dataUri = `data:${mimeType};base64,${base64Image}`;
					eventOptions.image = dataUri;
					
					console.log(`Event image converted to base64 (${mimeType}), size:`, imageBuffer.length, 'bytes');
				} catch (imgErr) {
					console.error('Error processing event image:', imgErr.message);
				}
			}

			const event = await guild.scheduledEvents.create(eventOptions);

			console.log(`Discord event created: ${event.name} (${event.id})`);

			return {
				id: event.id,
				name: event.name,
				description: event.description,
				scheduledStartTime: event.scheduledStartTimestamp,
				scheduledEndTime: event.scheduledEndTimestamp,
				url: event.url,
			};
		} catch (error) {
			console.error('Failed to create Discord scheduled event:', error);
			throw error;
		}
	}

	/**
	 * Send a plain text message to a guild text channel
	 * @param {string} channelId
	 * @param {string} content
	 */
	async sendMessageToChannel(channelId, content) {
		try {
			if (!this.ready || !this.client) {
				throw new Error('Discord bot not ready');
			}
			const ch = await this.client.channels.fetch(channelId);
			if (!ch || typeof ch.send !== 'function') {
				throw new Error('Channel not found or not a text channel');
			}
			await ch.send({ content });
			return true;
		} catch (err) {
			console.error('Failed to send message to Discord channel:', err);
			throw err;
		}
	}

	/**
	 * Check if Discord integration is available
	 */
	isAvailable() {
		return this.ready && !!this.client;
	}
}

// Export singleton instance
const discordClient = new DiscordClient();
export default discordClient;
