# Discord Forum API Documentation

This document describes the new API endpoints for interacting with Discord forum channels.

## Overview

The Discord Forum API allows you to:
- List all available forum channels in your server
- Fetch topics from a specific forum channel
- Get detailed information about individual forum topics including all posts
- Retrieve all posts from a specific forum topic

## Authentication

All endpoints require authentication via JWT token. Include the token in the `Authorization` header:
```
Authorization: Bearer <your-jwt-token>
```

## Endpoints

### 1. Get Forum Channels

**Endpoint:** `GET /api/integrations/discord/forum-channels`

**Description:** Fetches all forum channels from the configured Discord guild.

**Response:**
```json
{
  "guildId": "your-guild-id",
  "channels": [
    {
      "id": "channel-id-1",
      "name": "forum-channel-name"
    }
  ]
}
```

### 2. Get Forum Topics

**Endpoint:** `GET /api/integrations/discord/forum/:channelId/topics`

**Description:** Fetches all topics (posts) in a specific forum channel.

**Parameters:**
- `channelId` (path parameter): The ID of the forum channel

**Response:**
```json
{
  "channelId": "channel-id",
  "topics": [
    {
      "id": "thread-id-1",
      "title": "Topic Title",
      "author": {
        "id": "user-id-1",
        "username": "Username"
      },
      "content": "Content of the first post...",
      "createdAt": "2023-01-01T12:00:00.000Z",
      "updatedAt": "2023-01-01T12:30:00.000Z"
    }
  ],
  "totalTopics": 1
}
```

### 3. Get Forum Topic Details

**Endpoint:** `GET /api/integrations/discord/forum/topic/:threadId`

**Description:** Fetches detailed information about a specific forum topic including all posts.

**Parameters:**
- `threadId` (path parameter): The ID of the thread/topic

**Response:**
```json
{
  "id": "thread-id-1",
  "title": "Topic Title",
  "author": {
    "id": "user-id-1",
    "username": "Username"
  },
  "content": "Content of the first post...",
  "createdAt": "2023-01-01T12:00:00.000Z",
  "updatedAt": "2023-01-01T12:30:00.000Z",
  "posts": [
    {
      "id": "message-id-1",
      "author": {
        "id": "user-id-2",
        "username": "AnotherUser"
      },
      "content": "Reply content...",
      "createdAt": "2023-01-01T12:15:00.000Z"
    }
  ]
}
```

### 4. Get Forum Topic Posts

**Endpoint:** `GET /api/integrations/discord/forum/topic/:threadId/posts`

**Description:** Fetches all posts in a specific forum topic.

**Parameters:**
- `threadId` (path parameter): The ID of the thread/topic

**Response:**
```json
{
  "threadId": "thread-id-1",
  "posts": [
    {
      "id": "message-id-1",
      "author": {
        "id": "user-id-1",
        "username": "Username"
      },
      "content": "Content of the post...",
      "createdAt": "2023-01-01T12:00:00.000Z"
    }
  ],
  "totalPosts": 1
}
```

## Error Responses

All endpoints return appropriate HTTP status codes and error messages:

- `400 Bad Request`: Missing required parameters
- `401 Unauthorized`: Invalid or missing authentication token
- `500 Internal Server Error`: Discord API error or server issue
- `503 Service Unavailable`: Discord bot not connected

## Example Usage

### Using curl:

```bash
# Get forum channels
curl -H "Authorization: Bearer <your-token>" \
     http://localhost:3000/api/integrations/discord/forum-channels

# Get topics from a specific channel
curl -H "Authorization: Bearer <your-token>" \
     http://localhost:3000/api/integrations/discord/forum/123456789/topics

# Get details of a specific topic
curl -H "Authorization: Bearer <your-token>" \
     http://localhost:3000/api/integrations/discord/forum/topic/987654321

# Get all posts from a specific topic
curl -H "Authorization: Bearer <your-token>" \
     http://localhost:3000/api/integrations/discord/forum/topic/987654321/posts
```

### Using JavaScript (fetch):

```javascript
// Get forum channels
const response = await fetch('/api/integrations/discord/forum-channels', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
const data = await response.json();

// Get topics from a specific channel
const channelId = '123456789';
const topicsResponse = await fetch(`/api/integrations/discord/forum/${channelId}/topics`, {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
const topicsData = await topicsResponse.json();
```

## Notes

1. The Discord bot must have the necessary permissions to access forum channels and threads
2. User information is enriched with usernames when possible, but may fall back to basic user data if Discord API calls fail
3. All timestamps are returned in ISO 8601 format (UTC)
4. The forum channel must be of type `GUILD_FORUM` (Discord channel type 15)