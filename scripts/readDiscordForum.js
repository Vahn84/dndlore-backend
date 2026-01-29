import discordClient, { initializeDiscordClient } from "../discord-client.js";
import fs from "fs";
import path from "path";

/**
 * Script to read all topics and their posts from a Discord forum channel
 * 
 * USAGE:
 *   node scripts/readDiscordForum.js [FORUM_CHANNEL_ID] [--output FILE.json]
 * 
 * ARGUMENTS:
 *   FORUM_CHANNEL_ID (optional): The ID of the forum channel to read.
 *                                 If not provided, the script will list all available forum channels.
 *   --output FILE.json (optional): Export the data to a JSON file instead of printing to console.
 *                                  If not provided, data will be printed to the console.
 * 
 * EXAMPLES:
 *   # List all available forum channels
 *   node scripts/readDiscordForum.js
 * 
 *   # Read a specific forum channel and print to console
 *   node scripts/readDiscordForum.js 123456789012345678
 * 
 *   # Read a specific forum channel and export to JSON
 *   node scripts/readDiscordForum.js 123456789012345678 --output forum-data.json
 * 
 * OUTPUT:
 *   - Console output: Displays thread details and messages in a readable format
 *   - JSON output: Structured data including:
 *     * Guild information
 *     * Channel information
 *     * Thread details (name, author, timestamps, etc.)
 *     * Message details (content, attachments, embeds, reactions, etc.)
 * 
 * REQUIREMENTS:
 *   - DISCORD_BOT_TOKEN environment variable must be set
 *   - DISCORD_GUILD_ID environment variable must be set
 *   - Discord bot must have permission to read forum channels
 */

const FORUM_CHANNEL_ID = process.argv.find((arg) => !arg.startsWith("--")) || null;
const OUTPUT_FILE = process.argv.find((arg) => arg.startsWith("--output="))?.split("=")[1] || null;

async function main() {
  try {
    console.log("Initializing Discord client...");
    await initializeDiscordClient();
    
    if (!discordClient.isAvailable()) {
      console.error("Discord bot is not connected. Please check DISCORD_BOT_TOKEN and DISCORD_GUILD_ID environment variables.");
      process.exit(1);
    }

    const guild = await discordClient.getGuild();
    console.log(`Connected to guild: ${guild.name} (${guild.id})`);

    // Fetch all channels
    const channels = await guild.channels.fetch();
    
    // Filter to forum channels only (type 15 = GUILD_FORUM)
    const forumChannels = channels
      .filter((channel) => channel.type === 15)
      .map((channel) => ({
        id: channel.id,
        name: channel.name,
        topic: channel.topic,
        position: channel.position,
      }))
      .sort((a, b) => a.position - b.position);

    if (forumChannels.length === 0) {
      console.log("No forum channels found in this guild.");
      process.exit(0);
    }

    if (!FORUM_CHANNEL_ID) {
      console.log("\nAvailable forum channels:");
      forumChannels.forEach((channel, index) => {
        console.log(`  ${index + 1}. ${channel.name} (${channel.id})`);
        if (channel.topic) {
          console.log(`     Topic: ${channel.topic}`);
        }
      });
      console.log("\nUsage: node scripts/readDiscordForum.js [FORUM_CHANNEL_ID] [--output FILE.json]");
      process.exit(0);
    }

    // Find the specified forum channel
    const forumChannel = forumChannels.find((c) => c.id === FORUM_CHANNEL_ID);
    
    if (!forumChannel) {
      console.error(`Forum channel "${FORUM_CHANNEL_ID}" not found.`);
      console.log("\nAvailable forum channels:");
      forumChannels.forEach((channel, index) => {
        console.log(`  ${index + 1}. ${channel.name} (${channel.id})`);
      });
      process.exit(1);
    }

    console.log(`\nReading forum channel: ${forumChannel.name} (${forumChannel.id})`);
    if (forumChannel.topic) {
      console.log(`Topic: ${forumChannel.topic}`);
    }

    // Fetch all threads in the forum
    console.log("\nFetching threads...");
    const threads = await forumChannel.threads.fetch();
    
    if (threads.size === 0) {
      console.log("No threads found in this forum.");
      process.exit(0);
    }

    console.log(`Found ${threads.size} thread(s):\n`);

    // Process each thread
    const forumData = {
      guild: {
        id: guild.id,
        name: guild.name,
      },
      channel: {
        id: forumChannel.id,
        name: forumChannel.name,
        topic: forumChannel.topic,
      },
      threads: [],
    };

    for (const [threadId, thread] of threads) {
      console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
      console.log(`Thread: ${thread.name} (${threadId})`);
      console.log(`Created: ${new Date(thread.createdTimestamp).toLocaleString()}`);
      console.log(`Author: ${thread.author?.tag || 'Unknown'}`);
      console.log(`Message Count: ${thread.messageCount}`);
      console.log(`Reply Count: ${thread.replyCount}`);
      console.log(`Pinned: ${thread.pinned ? 'Yes' : 'No'}`);
      console.log(`Locked: ${thread.locked ? 'Yes' : 'No'}`);
      console.log(`Archived: ${thread.archived ? 'Yes' : 'No'}`);
      console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);

      // Fetch all messages in the thread
      console.log(`Fetching messages for thread "${thread.name}"...`);
      const messages = await thread.messages.fetch();
      
      console.log(`Found ${messages.size} message(s):\n`);

      // Display messages
      const threadMessages = messages.map((message, index) => {
        const timestamp = new Date(message.createdTimestamp).toISOString();
        const author = message.author?.tag || 'Unknown';
        const authorId = message.author?.id || null;
        const content = message.content || '[No content]';
        
        // Build attachments array
        const attachments = message.attachments
          ? message.attachments.map((attachment) => ({
              id: attachment.id,
              name: attachment.name,
              url: attachment.url,
              size: attachment.size,
              contentType: attachment.contentType,
            }))
          : [];
        
        // Build embeds array
        const embeds = message.embeds
          ? message.embeds.map((embed) => ({
              title: embed.title,
              description: embed.description,
              url: embed.url,
              color: embed.color,
              author: embed.author
                ? {
                    name: embed.author.name,
                    url: embed.author.url,
                    iconUrl: embed.author.iconUrl,
                  }
                : null,
              fields: embed.fields
                ? embed.fields.map((field) => ({
                    name: field.name,
                    value: field.value,
                    inline: field.inline,
                  }))
                : [],
              image: embed.image
                ? {
                    url: embed.image.url,
                    proxyUrl: embed.image.proxyUrl,
                  }
                : null,
              thumbnail: embed.thumbnail
                ? {
                    url: embed.thumbnail.url,
                    proxyUrl: embed.thumbnail.proxyUrl,
                  }
                : null,
            }))
          : [];
        
        // Check if message is a reply
        const replyTo = message.reference?.messageId
          ? {
              messageId: message.reference.messageId,
              channelId: message.reference.channelId,
              guildId: message.reference.guildId,
            }
          : null;

        return {
          index: index + 1,
          id: message.id,
          timestamp,
          author: {
            id: authorId,
            tag: author,
            username: message.author?.username || null,
            discriminator: message.author?.discriminator || null,
            avatarUrl: message.author?.displayAvatarURL() || null,
          },
          content,
          attachments,
          embeds,
          replyTo,
          reactions: message.reactions
            ? {
                count: message.reactions.count,
                emoji: message.reactions.emoji
                  ? {
                      name: message.reactions.emoji.name,
                      id: message.reactions.emoji.id,
                      animated: message.reactions.emoji.animated,
                    }
                  : null,
              }
            : null,
        };
      });

      // Display messages
      threadMessages.forEach((msg) => {
        const timestamp = new Date(msg.timestamp).toLocaleString();
        console.log(`${msg.index}. [${timestamp}] ${msg.author.tag}`);
        console.log(`   ${msg.content}`);
        
        // Show attachments if any
        if (msg.attachments && msg.attachments.length > 0) {
          console.log(`   Attachments: ${msg.attachments.length}`);
          msg.attachments.forEach((attachment) => {
            console.log(`     - ${attachment.name} (${attachment.size} bytes)`);
          });
        }
        
        // Show embeds if any
        if (msg.embeds && msg.embeds.length > 0) {
          console.log(`   Embeds: ${msg.embeds.length}`);
          msg.embeds.forEach((embed) => {
            console.log(`     - Title: ${embed.title || 'No title'}`);
            console.log(`     - Description: ${embed.description?.substring(0, 100) || 'No description'}`);
          });
        }
        
        console.log('');
      });

      console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);

      // Add thread to forum data
      forumData.threads.push({
        id: threadId,
        name: thread.name,
        created: new Date(thread.createdTimestamp).toISOString(),
        author: {
          id: thread.author?.id || null,
          tag: thread.author?.tag || 'Unknown',
        },
        messageCount: thread.messageCount,
        replyCount: thread.replyCount,
        pinned: thread.pinned,
        locked: thread.locked,
        archived: thread.archived,
        messages: threadMessages,
      });
    }

    console.log("✅ Successfully read all forum topics and their posts!");

    // Export to JSON if output file is specified
    if (OUTPUT_FILE) {
      const outputPath = path.resolve(process.cwd(), OUTPUT_FILE);
      const jsonOutput = JSON.stringify(forumData, null, 2);
      
      fs.writeFileSync(outputPath, jsonOutput, "utf-8");
      console.log(`\n✅ Data exported to: ${outputPath}`);
      console.log(`   Total threads: ${forumData.threads.length}`);
      console.log(`   Total messages: ${forumData.threads.reduce((sum, t) => sum + t.messages.length, 0)}`);
    }

  } catch (error) {
    console.error("\n❌ Error reading Discord forum:");
    console.error(error);
    process.exit(1);
  }
}

// Run the script
main();