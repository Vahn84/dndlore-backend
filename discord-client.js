import { Client, GatewayIntentBits, GuildScheduledEventPrivacyLevel, GuildScheduledEventEntityType } from 'discord.js';

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
	 * Create a scheduled event in Discord
	 * @param {Object} options
	 * @param {string} options.name - Event name
	 * @param {string} options.description - Event description
	 * @param {Date} options.scheduledStartTime - When the event starts
	 * @param {Date} [options.scheduledEndTime] - When the event ends (optional, defaults to +2 hours)
	 * @param {string} options.channelId - Voice/Stage channel ID (or null for external)
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
				scheduledEndTime = new Date(scheduledStartTime.getTime() + 2 * 60 * 60 * 1000), // +2 hours default
				channelId,
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
				entityType: GuildScheduledEventEntityType.External, // External event (no voice channel required)
				entityMetadata: {
					location: channelId ? `#${channelId}` : 'TBD', // Optional location text
				},
			};

			// Add image if provided (must be base64 or buffer)
			if (image) {
				// If image is a URL, we'd need to fetch and convert to buffer
				// For now, we'll skip it - Discord API requires base64/buffer format
				console.log('Event image provided but not yet implemented:', image);
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
	 * Check if Discord integration is available
	 */
	isAvailable() {
		return this.ready && !!this.client;
	}
}

// Export singleton instance
const discordClient = new DiscordClient();
export default discordClient;
