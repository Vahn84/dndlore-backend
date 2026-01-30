import express from "express";
import { requireAuth } from "../../middleware/auth.js";
import { User } from "../../models.js";
import discordClient, {
  initializeDiscordClient,
} from "../../discord-client.js";
import { refreshGoogleToken } from "../auth/index.js";

// -----------------------------------------------------------------------------
// Discord Integration
// -----------------------------------------------------------------------------
const router = express.Router();
/**
 * GET /integrations/google/calendars
 * Fetch user's Google Calendar list
 */
router.get("/integrations/google/calendars", requireDM, async (req, res) => {
  try {
    // JWT payload stores user id as `id` (see /auth/google/callback), not `userId`
    const user = await User.findById(req.user.id);

    if (!user || !user.googleAccessToken) {
      return res.status(401).json({
        error: "Not connected to Google Calendar",
        message: "Please connect your Google account first.",
      });
    }

    // Check if token is expired
    const now = new Date();
    const tokenExpired = user.googleTokenExpiry && user.googleTokenExpiry < now;

    let accessToken = user.googleAccessToken;

    if (tokenExpired && user.googleRefreshToken) {
      console.log("Google token expired, refreshing...");
      const refreshed = await refreshGoogleToken(user.googleRefreshToken);
      if (refreshed) {
        accessToken = refreshed.accessToken;
        user.googleAccessToken = refreshed.accessToken;
        user.googleTokenExpiry = new Date(
          Date.now() + refreshed.expiresIn * 1000,
        );
        await user.save();
      } else {
        return res
          .status(401)
          .json({ error: "Failed to refresh Google token" });
      }
    }

    // Fetch calendar list from Google
    const calResponse = await fetch(
      "https://www.googleapis.com/calendar/v3/users/me/calendarList",
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      },
    );

    if (!calResponse.ok) {
      const errorText = await calResponse.text();
      console.error("Failed to fetch Google calendars:", errorText);
      return res
        .status(calResponse.status)
        .json({ error: "Failed to fetch calendars" });
    }

    const data = await calResponse.json();

    // Return simplified calendar list
    const calendars = data.items.map((cal) => ({
      id: cal.id,
      name: cal.summary,
      primary: cal.primary || false,
      backgroundColor: cal.backgroundColor,
      accessRole: cal.accessRole,
    }));

    res.json(calendars);
  } catch (err) {
    console.error("GET /integrations/google/calendars failed", err);
    res.status(500).json({
      error: "Failed to fetch Google calendars",
      details: err.message,
    });
  }
});

/**
 * GET /integrations/discord/channels
 * Fetch all text channels from the configured Discord guild
 */
router.get("/integrations/discord/channels", requireDM, checkDiscordClient(), async (req, res) => {
  try {
    const channels = await discordClient.getTextChannels();
    res.json(channels);
  } catch (err) {
    console.error("GET /integrations/discord/channels failed", err);
    res.status(500).json({
      error: "Failed to fetch Discord channels",
      details: err.message,
    });
  }
});

/**
 * GET /integrations/discord/voice-channels
 * Fetch all voice channels from the configured Discord guild
 */
router.get(
  "/integrations/discord/voice-channels",
  requireDM,
  checkDiscordClient(),
  async (req, res) => {
    try {
      const voiceChannels = await discordClient.getVoiceChannels();
      res.json({
        guildId: process.env.DISCORD_GUILD_ID,
        channels: voiceChannels,
      });
    } catch (err) {
      console.error("GET /integrations/discord/voice-channels failed", err);
      res.status(500).json({
        error: "Failed to fetch Discord voice channels",
        details: err.message,
      });
    }
  },
);

/**
 * GET /integrations/discord/forum-channels
 * Fetch all forum channels from the configured Discord guild
 */
router.get(
  "/integrations/discord/forum-channels",
  requireDM,
  checkDiscordClient(),
  async (req, res) => {
    try {
      const forumChannels = await discordClient.getForumChannels();
      res.json({
        guildId: process.env.DISCORD_GUILD_ID,
        channels: forumChannels,
      });
    } catch (err) {
      console.error("GET /integrations/discord/forum-channels failed", err);
      res.status(500).json({
        error: "Failed to fetch Discord forum channels",
        details: err.message,
      });
    }
  },
);

/**
 * GET /integrations/discord/forum/:channelId/topics
 * Fetch all topics in a specific forum channel
 */
router.get(
  "/integrations/discord/forum/:channelId/topics",
  requireDM,
  checkDiscordClient(),
  async (req, res) => {
    try {
      const { channelId } = req.params;

      if (!channelId) {
        return res.status(400).json({
          error: "Channel ID is required",
          message: "Please provide a channel ID in the URL path.",
        });
      }

      const topics = await discordClient.getForumTopics(channelId);

      // Enrich with user information
      const enrichedTopics = await Promise.all(
        topics.map(async (topic) => {
          try {
            const authorInfo = await discordClient.getUserInfo(topic.author.id);
            return {
              ...topic,
              author: authorInfo,
            };
          } catch (userErr) {
            console.warn(`Could not fetch user info for ${topic.author.id}:`, userErr.message);
            return {
              ...topic,
              author: topic.author, // Keep original info if fetch fails
            };
          }
        })
      );

      res.json({
        channelId,
        topics: enrichedTopics,
        totalTopics: enrichedTopics.length,
      });
    } catch (err) {
      console.error("GET /integrations/discord/forum/:channelId/topics failed", err);
      res.status(500).json({
        error: "Failed to fetch forum topics",
        details: err.message,
      });
    }
  },
);

/**
 * GET /integrations/discord/forum/topic/:threadId
 * Fetch detailed information about a specific forum topic including all posts
 */
router.get(
  "/integrations/discord/forum/topic/:threadId",
  requireDM,
  checkDiscordClient(),
  async (req, res) => {
    try {
      const { threadId } = req.params;

      if (!threadId) {
        return res.status(400).json({
          error: "Thread ID is required",
          message: "Please provide a thread ID in the URL path.",
        });
      }

      const topicDetails = await discordClient.getForumTopicDetails(threadId);

      // Enrich with user information for author and post authors
      const enrichedTopic = {
        ...topicDetails,
        author: await discordClient.getUserInfo(topicDetails.author.id).catch(err => {
          console.warn(`Could not fetch user info for author ${topicDetails.author.id}:`, err.message);
          return topicDetails.author;
        }),
        posts: await Promise.all(
          topicDetails.posts.map(async (post) => ({
            ...post,
            author: await discordClient.getUserInfo(post.author.id).catch(err => {
              console.warn(`Could not fetch user info for post author ${post.author.id}:`, err.message);
              return post.author;
            }),
          }))
        ),
      };

      res.json(enrichedTopic);
    } catch (err) {
      console.error("GET /integrations/discord/forum/topic/:threadId failed", err);
      res.status(500).json({
        error: "Failed to fetch forum topic details",
        details: err.message,
      });
    }
  },
);

/**
 * GET /integrations/discord/forum/topic/:threadId/posts
 * Fetch all posts in a specific forum topic
 */
router.get(
  "/integrations/discord/forum/topic/:threadId/posts",
  requireDM,
  checkDiscordClient(),
  async (req, res) => {
    try {
      const { threadId } = req.params;

      if (!threadId) {
        return res.status(400).json({
          error: "Thread ID is required",
          message: "Please provide a thread ID in the URL path.",
        });
      }

      const posts = await discordClient.getForumTopicPosts(threadId);

      // Enrich with user information
      const enrichedPosts = await Promise.all(
        posts.map(async (post) => ({
          ...post,
          author: await discordClient.getUserInfo(post.author.id).catch(err => {
            console.warn(`Could not fetch user info for post author ${post.author.id}:`, err.message);
            return post.author;
          }),
        }))
      );

      res.json({
        threadId,
        posts: enrichedPosts,
        totalPosts: enrichedPosts.length,
      });
    } catch (err) {
      console.error("GET /integrations/discord/forum/topic/:threadId/posts failed", err);
      res.status(500).json({
        error: "Failed to fetch forum topic posts",
        details: err.message,
      });
    }
  },
);

/**
 * POST /integrations/discord/events
 * Create a Discord scheduled event
 * Body: { title, description?, bannerUrl?, dateTimeUtc, channelId, syncToCalendar?, calendarId? }
 */
router.post("/integrations/discord/events", requireAuth, checkDiscordClient(), async (req, res) => {
  try {
    const {
      title,
      description,
      bannerUrl,
      dateTimeUtc,
      channelId,
      voiceChannelId,
      syncToCalendar,
      calendarId,
    } = req.body;

    console.log("Creating Discord event with params:", {
      title,
      description: description?.substring(0, 100),
      bannerUrl,
      dateTimeUtc,
      channelId,
      voiceChannelId,
      syncToCalendar,
      calendarId,
    });

    if (!title) {
      return res.status(400).json({ error: "Event title is required" });
    }

    if (!dateTimeUtc) {
      return res.status(400).json({ error: "Event date/time is required" });
    }

    const scheduledStartTime = new Date(dateTimeUtc);
    if (isNaN(scheduledStartTime.getTime())) {
      return res.status(400).json({ error: "Invalid date format" });
    }

    // Create Discord scheduled event
    const discordEvent = await discordClient.createScheduledEvent({
      name: title,
      description: description || `Aetherium event: ${title}`,
      scheduledStartTime,
      voiceChannelId: voiceChannelId || null,
      image: bannerUrl,
    });

    // Send a message to the selected channel with the event link
    if (discordEvent && discordEvent.url && channelId) {
      try {
        await discordClient.sendMessageToChannel(
          channelId,
          `📅 **New Event Created:** ${title}\n${discordEvent.url}`,
        );
      } catch (msgErr) {
        console.error(
          "Failed to send message to channel after event creation:",
          msgErr,
        );
        // Don't fail the whole request if message send fails
      }
    }

    let calendarEvent = null;

    // Sync to Google Calendar if requested and user has valid token
    if (syncToCalendar) {
      try {
        const user = await User.findById(req.user.id);

        if (!user || !user.googleAccessToken) {
          console.warn("User has no Google Calendar token, skipping sync");
        } else {
          // Check if token is expired
          const now = new Date();
          const tokenExpired =
            user.googleTokenExpiry && user.googleTokenExpiry < now;

          let accessToken = user.googleAccessToken;

          if (tokenExpired && user.googleRefreshToken) {
            console.log("Google token expired, refreshing...");
            const refreshed = await refreshGoogleToken(user.googleRefreshToken);
            if (refreshed) {
              accessToken = refreshed.accessToken;
              user.googleAccessToken = refreshed.accessToken;
              user.googleTokenExpiry = new Date(
                Date.now() + refreshed.expiresIn * 1000,
              );
              await user.save();
            }
          }

          if (accessToken) {
            // Create event in Google Calendar
            const endTime = new Date(
              scheduledStartTime.getTime() + 3 * 60 * 60 * 1000,
            ); // +3 hours

            const calendarEventData = {
              summary: title,
              description: description || `Aetherium event: ${title}`,
              start: {
                dateTime: scheduledStartTime.toISOString(),
                timeZone: "UTC",
              },
              end: {
                dateTime: endTime.toISOString(),
                timeZone: "UTC",
              },
            };

            // Use specified calendar or default to primary
            const targetCalendar = calendarId || "primary";

            const calResponse = await fetch(
              `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(
                targetCalendar,
              )}/events`,
              {
                method: "POST",
                headers: {
                  Authorization: `Bearer ${accessToken}`,
                  "Content-Type": "application/json",
                },
                body: JSON.stringify(calendarEventData),
              },
            );

            if (calResponse.ok) {
              calendarEvent = await calResponse.json();
              console.log("Google Calendar event created:", calendarEvent.id);
            } else {
              const errorText = await calResponse.text();
              console.error(
                "Failed to create Google Calendar event:",
                errorText,
              );
            }
          }
        }
      } catch (calErr) {
        console.error("Google Calendar sync error:", calErr);
        // Don't fail the whole request if calendar sync fails
      }
    }

    res.json({
      success: true,
      discordEvent,
      calendarEvent,
      message: calendarEvent
        ? "Discord event created and synced to Google Calendar"
        : "Discord event created successfully",
    });
  } catch (err) {
    console.error("POST /integrations/discord/events failed", err);
    res.status(500).json({
      error: "Failed to create Discord event",
      details: err.message,
    });
  }
});

function checkDiscordClient() {
  return async (req, res, next) => {
    try {
      await initializeDiscordClient();
      if (!discordClient.isAvailable()) {
        return res.status(503).json({
          error: "Discord integration not available",
          message:
            "Discord bot is not connected. Check DISCORD_BOT_TOKEN and DISCORD_GUILD_ID environment variables.",
        });
      }
      next();
    } catch (error) {
      return res.status(503).json({
        error: "Discord integration not available",
        message:
          "Failed to initialize Discord client. Check DISCORD_BOT_TOKEN and DISCORD_GUILD_ID environment variables.",
        details: error.message,
      });
    }
  };
}

export default router;
