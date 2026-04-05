import {
  Client,
  GatewayIntentBits,
  GuildScheduledEventPrivacyLevel,
  GuildScheduledEventEntityType,
} from "discord.js";
import https from "https";
import http from "http";
import fs from "fs";
import path from "path";

// Bypass TLS certificate validation for public/free WiFi networks
// Must be set before any HTTPS/WSS connections are made
if (
  process.env.NODE_ENV === "development" ||
  process.env.ALLOW_INVALID_CERTS === "true" ||
  !process.env.NODE_ENV
) {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  console.log(
    "TLS certificate validation disabled for Discord (development mode)",
  );
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
      console.log("Discord bot already connected");
      return;
    }

    if (!this.token) {
      console.warn("DISCORD_BOT_TOKEN not set. Discord integration disabled.");
      return;
    }

    if (!this.guildId) {
      console.warn("DISCORD_GUILD_ID not set. Discord integration disabled.");
      return;
    }

    try {
      this.client = new Client({
        intents: [
          GatewayIntentBits.Guilds,
          GatewayIntentBits.GuildScheduledEvents,
          GatewayIntentBits.GuildMessages,
          GatewayIntentBits.MessageContent,
        ],
      });

      this.client.once("clientReady", () => {
        console.log(`Discord bot logged in as ${this.client.user.tag}`);
        this.ready = true;
      });

      this.client.on("error", (error) => {
        console.error("Discord client error:", error);
      });

      await this.client.login(this.token);
    } catch (error) {
      console.error("Failed to connect Discord bot:", error.message || error);

      // Check if this is a network/captive portal issue (HTML response instead of JSON)
      if (error.rawError && error.status === 403) {
        console.warn(
          "Discord connection blocked - likely by public WiFi captive portal or firewall.",
        );
        console.warn(
          "Discord integration will be disabled. Please connect to a different network or use a VPN.",
        );
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
      throw new Error("Discord bot not ready");
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
      console.error("Failed to fetch Discord channels:", error);
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
      console.error("Failed to fetch Discord voice channels:", error);
      throw error;
    }
  }

  /**
   * Fetch all forum channels in the configured guild
   * @returns {Promise<Array<{id: string, name: string}>>}
   */
  async getForumChannels() {
    try {
      const guild = await this.getGuild();
      const channels = await guild.channels.fetch();
      console.log(channels);
      // Filter to forum channels only (type 15 = GUILD_FORUM)
      const forumChannels = channels
        .filter((channel) => channel.type === 15)
        .map((channel) => ({
          id: channel.id,
          name: channel.name,
        }))
        .sort((a, b) => a.name.localeCompare(b.name));

      return forumChannels;
    } catch (error) {
      console.error("Failed to fetch Discord forum channels:", error);
      throw error;
    }
  }

  /**
   * Fetch all topics (posts) in a forum channel
   * @param {string} channelId - The ID of the forum channel
   * @returns {Promise<Array<{id: string, title: string, author: {id: string, username: string}, content: string, createdAt: Date, updatedAt: Date}>>}
   */
  async getForumTopics(channelId) {
    try {
      const guild = await this.getGuild();
      const channel = await guild.channels.fetch(channelId);

      if (!channel || channel.type !== 15) {
        throw new Error("Channel not found or not a forum channel");
      }
      console.log(channel.name);
      // Get all threads in the forum
      const threads = await channel.threads.fetch();
      console.log(threads);

      if (!threads || !threads.first) {
        return []; // Return empty array if no threads
      }

      // Convert Collection to array and map
      return threads.map((thread) => ({
        id: thread.id,
        title: thread.name,
        author: {
          id: thread.ownerId,
          username: "Unknown User", // Will be populated in the API endpoint
        },
        content: thread.starterMessage?.content || "",
        createdAt: thread.createdAt,
        updatedAt: thread.lastMessageTimestamp || thread.createdAt,
      }));
    } catch (error) {
      console.error("Failed to fetch forum topics:", error);
      throw error;
    }
  }

  /**
   * Fetch detailed information about a specific forum topic including all posts
   * @param {string} threadId - The ID of the thread/topic
   * @returns {Promise<{id: string, title: string, author: {id: string, username: string}, content: string, createdAt: Date, updatedAt: Date, posts: Array<{id: string, author: {id: string, username: string}, content: string, createdAt: Date}>}>}
   */
  async getForumTopicDetails(threadId) {
    try {
      const thread = await this.client.channels.fetch(threadId);

      if (!thread || !thread.isThread()) {
        throw new Error("Thread not found or not a valid thread");
      }

      // Get the first message (starter message)
      const starterMessage = await thread.messages.fetch(thread.id);

      // Get all messages in the thread
      const allMessages = await thread.messages.fetch();

      // Map messages to posts (excluding the starter message which is already handled)
      const posts = allMessages
        .filter((msg) => msg.id !== thread.id)
        .map((msg) => ({
          id: msg.id,
          author: {
            id: msg.author.id,
            username: msg.author.username,
          },
          content: msg.content,
          createdAt: msg.createdAt,
        }));

      return {
        id: thread.id,
        title: thread.name,
        author: {
          id: thread.ownerId,
          username: "Unknown User", // Will be populated in the API endpoint
        },
        content: starterMessage?.content || "",
        createdAt: thread.createdAt,
        updatedAt: thread.lastMessageTimestamp || thread.createdAt,
        posts: posts,
      };
    } catch (error) {
      console.error("Failed to fetch forum topic details:", error);
      throw error;
    }
  }

  /**
   * Fetch all posts in a specific forum topic
   * @param {string} threadId - The ID of the thread/topic
   * @returns {Promise<Array<{id: string, author: {id: string, username: string}, content: string, createdAt: Date}>>}
   */
  async getForumTopicPosts(threadId) {
    try {
      const thread = await this.client.channels.fetch(threadId);

      if (!thread || !thread.isThread()) {
        throw new Error("Thread not found or not a valid thread");
      }

      // Get all messages in the thread
      const messages = await thread.messages.fetch();

      return messages.map((msg) => ({
        id: msg.id,
        author: {
          id: msg.author.id,
          username: msg.author.username,
        },
        content: msg.content,
        createdAt: msg.createdAt,
      }));
    } catch (error) {
      console.error("Failed to fetch forum topic posts:", error);
      throw error;
    }
  }

  /**
   * Publish a page as a new forum post (thread) in a forum channel.
   * Handles the 2000-char Discord message limit by splitting into multiple messages.
   * Sends the banner image as an embed in the first message if provided.
   * @param {string} channelId - ID of the GUILD_FORUM channel
   * @param {{ title: string, content: string, bannerUrl?: string }} opts
   * @returns {Promise<{ id: string, url: string }>}
   */
  async createForumPost(channelId, { title, content, bannerUrl }) {
    const LIMIT = 2000;

    try {
      const channel = await this.client.channels.fetch(channelId);
      if (!channel || channel.type !== 15) {
        throw new Error("Channel not found or not a forum channel");
      }

      // Split content into ≤2000-char chunks on paragraph boundaries
      const chunks = splitIntoChunks(content, LIMIT);
      const firstChunk = chunks[0] || title;

      const firstMessage = { content: firstChunk };
      if (bannerUrl) {
        firstMessage.embeds = [{ image: { url: bannerUrl } }];
      }

      const thread = await channel.threads.create({
        name: title,
        message: firstMessage,
      });

      // Post remaining chunks as follow-up messages in the thread
      for (let i = 1; i < chunks.length; i++) {
        await thread.send(chunks[i]);
      }

      return { id: thread.id, url: thread.url };
    } catch (error) {
      console.error("Failed to create forum post:", error);
      if (error?.code === 50001) {
        throw new Error("Bot is missing permissions on the forum channel. Required: CREATE_PUBLIC_THREADS and SEND_MESSAGES_IN_THREADS.");
      }
      throw error;
    }
  }

  /**
   * Fetch user information by ID
   * @param {string} userId - The ID of the user
   * @returns {Promise<{id: string, username: string, discriminator: string, avatar?: string}>}
   */
  async getUserInfo(userId) {
    try {
      const user = await this.client.users.fetch(userId);
      return {
        id: user.id,
        username: user.username,
        discriminator: user.discriminator,
        avatar: user.avatar ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png` : null,
      };
    } catch (error) {
      console.error("Failed to fetch user info:", error);
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
        description = "",
        scheduledStartTime,
        scheduledEndTime = new Date(
          scheduledStartTime.getTime() + 3 * 60 * 60 * 1000,
        ), // +3 hours default
        voiceChannelId,
        image,
      } = options;

      // Validate required fields
      if (!name) {
        throw new Error("Event name is required");
      }
      if (!scheduledStartTime || !(scheduledStartTime instanceof Date)) {
        throw new Error("Valid scheduledStartTime (Date) is required");
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
          location: "External",
        };
      }

      // Add image if provided - convert to base64 data URI
      if (image) {
        try {
          let imageBuffer;
          let imageUrl = image;

          // If it's a relative /uploads/ path, read from file system directly
          if (image.startsWith("/uploads/")) {
            console.log("Reading event image from local file system:", image);
            const filePath = path.join(process.cwd(), image);
            imageBuffer = fs.readFileSync(filePath);
          } else {
            // Otherwise fetch from URL
            imageUrl = image.startsWith("http")
              ? image
              : `${process.env.FRONTEND_URL || "http://localhost:3000"}${image}`;
            console.log("Fetching event image from URL:", imageUrl);

            // Use https or http based on URL
            const protocol = imageUrl.startsWith("https") ? https : http;

            imageBuffer = await new Promise((resolve, reject) => {
              protocol
                .get(imageUrl, (response) => {
                  if (response.statusCode !== 200) {
                    reject(
                      new Error(
                        `Failed to fetch image: ${response.statusCode}`,
                      ),
                    );
                    return;
                  }

                  const chunks = [];
                  response.on("data", (chunk) => chunks.push(chunk));
                  response.on("end", () => resolve(Buffer.concat(chunks)));
                  response.on("error", reject);
                })
                .on("error", reject);
            });
          }

          // Detect image type from URL/path extension
          let mimeType = "image/png";
          if (image.match(/\.(jpg|jpeg)$/i)) {
            mimeType = "image/jpeg";
          } else if (image.match(/\.webp$/i)) {
            mimeType = "image/webp";
          } else if (image.match(/\.gif$/i)) {
            mimeType = "image/gif";
          }

          // Convert buffer to base64 data URI
          const base64Image = imageBuffer.toString("base64");
          const dataUri = `data:${mimeType};base64,${base64Image}`;
          eventOptions.image = dataUri;

          console.log(
            `Event image converted to base64 (${mimeType}), size:`,
            imageBuffer.length,
            "bytes",
          );
        } catch (imgErr) {
          console.error("Error processing event image:", imgErr.message);
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
      console.error("Failed to create Discord scheduled event:", error);
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
        throw new Error("Discord bot not ready");
      }
      const ch = await this.client.channels.fetch(channelId);
      if (!ch || typeof ch.send !== "function") {
        throw new Error("Channel not found or not a text channel");
      }
      await ch.send({ content });
      return true;
    } catch (err) {
      console.error("Failed to send message to Discord channel:", err);
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

/**
 * Split text into chunks of at most `limit` chars, preferring paragraph breaks.
 */
function splitIntoChunks(text, limit) {
  if (text.length <= limit) return [text];

  const chunks = [];
  let remaining = text;

  while (remaining.length > 0) {
    if (remaining.length <= limit) {
      chunks.push(remaining);
      break;
    }

    // Try to split on a double newline (paragraph boundary) within the limit
    const window = remaining.slice(0, limit);
    const lastPara = window.lastIndexOf("\n\n");
    const lastNewline = window.lastIndexOf("\n");
    const splitAt = lastPara > 0 ? lastPara + 2
      : lastNewline > 0 ? lastNewline + 1
      : limit;

    chunks.push(remaining.slice(0, splitAt).trimEnd());
    remaining = remaining.slice(splitAt).trimStart();
  }

  return chunks.filter(Boolean);
}

// Export singleton instance
const discordClient = new DiscordClient();

export default discordClient;

export async function initializeDiscordClient() {
  try {
    await discordClient.connect();
  } catch (error) {
    console.error("Discord bot initialization failed:", error);
  }
}
