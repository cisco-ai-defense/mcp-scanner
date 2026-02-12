# Discord Tools (25 tools) for MCP Server

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Discord Tools")

@mcp.tool()
def discord_get_guild_info(guild_id: str, api_token: str = None) -> dict:
    """Get detailed information about a Discord guild/server."""
    return {
        "id": guild_id,
        "name": f"Guild {guild_id}",
        "description": f"Description for guild {guild_id}",
        "owner_id": "owner123",
        "member_count": 1250
    }

@mcp.tool()
def discord_list_guilds(api_token: str = None) -> list:
    """List all Discord guilds the bot is in."""
    return [
        {"id": "guild1", "name": "Gaming Community", "owner": True},
        {"id": "guild2", "name": "Development Server", "owner": False}
    ]

@mcp.tool()
def discord_create_guild(name: str, region: str = "us-west", api_token: str = None) -> dict:
    """Create a new Discord guild/server."""
    return {
        "id": "new_guild_123",
        "name": name,
        "region": region,
        "owner_id": "current_user"
    }

@mcp.tool()
def discord_update_guild(guild_id: str, name: str = None, description: str = None, api_token: str = None) -> dict:
    """Update a Discord guild/server."""
    return {
        "id": guild_id,
        "name": name or f"Updated Guild {guild_id}",
        "description": description or "Updated description"
    }

@mcp.tool()
def discord_delete_guild(guild_id: str, api_token: str = None) -> dict:
    """Delete a Discord guild/server."""
    return {"message": f"Guild {guild_id} deleted successfully"}

@mcp.tool()
def discord_get_guild_channels(guild_id: str, api_token: str = None) -> list:
    """Get all channels in a Discord guild."""
    return [
        {"id": "channel1", "name": "general", "type": 0, "topic": "General discussion"},
        {"id": "channel2", "name": "announcements", "type": 0, "topic": "Server announcements"}
    ]

@mcp.tool()
def discord_create_channel(guild_id: str, name: str, channel_type: int = 0, topic: str = None, api_token: str = None) -> dict:
    """Create a new channel in a Discord guild."""
    return {
        "id": "new_channel_456",
        "name": name,
        "type": channel_type,
        "guild_id": guild_id,
        "topic": topic or f"Channel: {name}"
    }

@mcp.tool()
def discord_update_channel(channel_id: str, name: str = None, topic: str = None, api_token: str = None) -> dict:
    """Update a Discord channel."""
    return {
        "id": channel_id,
        "name": name or f"updated-channel-{channel_id}",
        "topic": topic or "Updated topic"
    }

@mcp.tool()
def discord_delete_channel(channel_id: str, api_token: str = None) -> dict:
    """Delete a Discord channel."""
    return {"message": f"Channel {channel_id} deleted successfully"}

@mcp.tool()
def discord_get_channel_messages(channel_id: str, limit: int = 50, api_token: str = None) -> list:
    """Get messages from a Discord channel."""
    return [
        {"id": "msg1", "content": "Hello everyone!", "author": {"id": "user1", "username": "john_doe"}},
        {"id": "msg2", "content": "How's everyone doing?", "author": {"id": "user2", "username": "jane_smith"}}
    ]

@mcp.tool()
def discord_send_message(channel_id: str, content: str, embed: dict = None, api_token: str = None) -> dict:
    """Send a message to a Discord channel."""
    return {
        "id": "new_msg_789",
        "content": content,
        "channel_id": channel_id,
        "author": {"id": "bot_user", "username": "Bot"}
    }

@mcp.tool()
def discord_edit_message(channel_id: str, message_id: str, content: str, api_token: str = None) -> dict:
    """Edit a Discord message."""
    return {
        "id": message_id,
        "content": content,
        "channel_id": channel_id
    }

@mcp.tool()
def discord_delete_message(channel_id: str, message_id: str, api_token: str = None) -> dict:
    """Delete a Discord message."""
    return {"message": f"Message {message_id} deleted successfully"}

@mcp.tool()
def discord_add_reaction(channel_id: str, message_id: str, emoji: str, api_token: str = None) -> dict:
    """Add a reaction to a Discord message."""
    return {
        "message": message_id,
        "emoji": emoji,
        "added": True
    }

@mcp.tool()
def discord_remove_reaction(channel_id: str, message_id: str, emoji: str, user_id: str = None, api_token: str = None) -> dict:
    """Remove a reaction from a Discord message."""
    return {
        "message": message_id,
        "emoji": emoji,
        "user": user_id or "current_user",
        "removed": True
    }

@mcp.tool()
def discord_get_guild_members(guild_id: str, limit: int = 1000, api_token: str = None) -> list:
    """Get members of a Discord guild."""
    return [
        {"user": {"id": "user1", "username": "john_doe"}, "nick": "John", "roles": ["role1"]},
        {"user": {"id": "user2", "username": "jane_smith"}, "nick": "Jane", "roles": ["role2"]}
    ]

@mcp.tool()
def discord_get_guild_member(guild_id: str, user_id: str, api_token: str = None) -> dict:
    """Get a specific member of a Discord guild."""
    return {
        "user": {"id": user_id, "username": f"user_{user_id}"},
        "nick": f"Nickname {user_id}",
        "roles": ["role1", "role2"]
    }

@mcp.tool()
def discord_add_guild_member_role(guild_id: str, user_id: str, role_id: str, api_token: str = None) -> dict:
    """Add a role to a Discord guild member."""
    return {
        "guild": guild_id,
        "user": user_id,
        "role": role_id,
        "added": True
    }

@mcp.tool()
def discord_remove_guild_member_role(guild_id: str, user_id: str, role_id: str, api_token: str = None) -> dict:
    """Remove a role from a Discord guild member."""
    return {
        "guild": guild_id,
        "user": user_id,
        "role": role_id,
        "removed": True
    }

@mcp.tool()
def discord_kick_guild_member(guild_id: str, user_id: str, reason: str = None, api_token: str = None) -> dict:
    """Kick a member from a Discord guild."""
    return {
        "guild": guild_id,
        "user": user_id,
        "reason": reason or "No reason provided",
        "kicked": True
    }

@mcp.tool()
def discord_ban_guild_member(guild_id: str, user_id: str, reason: str = None, api_token: str = None) -> dict:
    """Ban a member from a Discord guild."""
    return {
        "guild": guild_id,
        "user": user_id,
        "reason": reason or "No reason provided",
        "banned": True
    }

@mcp.tool()
def discord_get_guild_roles(guild_id: str, api_token: str = None) -> list:
    """Get all roles in a Discord guild."""
    return [
        {"id": "role1", "name": "@everyone", "color": 0, "position": 0},
        {"id": "role2", "name": "Moderator", "color": 3447003, "position": 2},
        {"id": "role3", "name": "Member", "color": 10181046, "position": 1}
    ]

@mcp.tool()
def discord_create_guild_role(guild_id: str, name: str, permissions: int = 0, color: int = 0, api_token: str = None) -> dict:
    """Create a new role in a Discord guild."""
    return {
        "id": "new_role_abc",
        "name": name,
        "color": color,
        "permissions": permissions
    }

@mcp.tool()
def discord_get_guild_invites(guild_id: str, api_token: str = None) -> list:
    """Get all invites for a Discord guild."""
    return [
        {"code": "abc123", "guild": {"id": guild_id}, "uses": 5, "max_uses": 10},
        {"code": "def456", "guild": {"id": guild_id}, "uses": 2, "max_uses": 0}
    ]

@mcp.tool()
def discord_create_guild_invite(guild_id: str, channel_id: str, max_age: int = 86400, max_uses: int = 0, api_token: str = None) -> dict:
    """Create an invite for a Discord guild."""
    return {
        "code": "new_invite_jkl",
        "guild": {"id": guild_id},
        "channel": {"id": channel_id},
        "uses": 0,
        "max_uses": max_uses,
        "max_age": max_age
    }

app = mcp.sse_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9002)