# Sleepyteepee Plugin

A REST API plugin for the Tremulous Master Server that provides HTTP endpoints for managing server listings, blacklist entries, MOTD, and more.

## Overview

Sleepyteepee exposes a REST API for the Tremulous Master Server, allowing external applications to query and manage server listings via HTTP instead of the traditional UDP protocol. The plugin uses a two-phase initialization pattern and integrates with the master server's plugin system.

## Features

- **REST API Endpoints**: Full CRUD operations for blacklist, featured servers, MOTD, and server statistics
- **API Key Authentication**: Secure endpoints using X-API-Key header
- **Framework Agnostic**: Works with multiple HTTP transport implementations (Flask, FastAPI, stdlib)
- **In-Memory Logging**: Recent log entries accessible via `/api/logs`
- **JSON Heartbeats**: Game servers can send heartbeats via JSON

## Installation

The Sleepyteepee plugin is installed as part of the Tremulous Master Server plugin system. Ensure the plugin is registered in `pyproject.toml`:

```toml
[project.entry-points."tremulous.master.plugins"]
sleepyteepee = "plugins.sleepyteepee:SleepyteepeePlugin"
```

## Configuration

### Command-Line Options

- `--api-host`: Host to bind the REST API server (default: `127.0.0.1`)
- `--api-port`: Port for the REST API server (default: `8067`)
- `--api-keys`: Comma-separated list of API keys

### Environment Variables

- `SLEEPYTEEPEE_API_KEYS`: Comma-separated list of API keys (alternative to `--api-keys`)

### Example

```bash
# Start master server with Sleepyteepee plugin
export SLEEPYTEEPEE_API_KEYS="my-secret-key-1,my-secret-key-2"
python3 master.py --api-host 0.0.0.0 --api-port 8067
```

## API Endpoints

### Unauthenticated Endpoints

#### POST `/heartbeat`

JSON heartbeat from tremded servers.

**Request Body:**
```json
{
  "address": "127.0.0.1:30720",
  "protocol": "71",
  "dead": false
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Heartbeat received, challenge sent",
  "challenge": "abc123def456"
}
```

### Authenticated Endpoints

All authenticated endpoints require a valid API key in the `X-API-Key` header.

#### GET `/api/blacklist`

Get all blacklist entries.

**Response:**
```json
{
  "entries": [
    {"id": 1, "entry": "192.168.1.0/24"},
    {"id": 2, "entry": "10.0.0.0/8"}
  ],
  "count": 2
}
```

#### POST `/api/blacklist`

Add a blacklist entry.

**Request Body:**
```json
{
  "entry": "192.168.1.0/24"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Blacklist entry added",
  "entry": "192.168.1.0/24"
}
```

#### DELETE `/api/blacklist/{id}`

Remove a blacklist entry by ID.

**Response:**
```json
{
  "status": "success",
  "message": "Blacklist entry removed",
  "entry": "192.168.1.0/24"
}
```

#### GET `/api/featured`

Get featured server groups.

**Response:**
```json
{
  "featured_servers": {
    "official": ["127.0.0.1:30720", "127.0.0.1:30721"],
    "community": ["127.0.0.1:30730"]
  }
}
```

#### PUT `/api/featured`

Add or modify featured servers.

**Request Body:**
```json
{
  "label": "official",
  "servers": ["127.0.0.1:30720", "127.0.0.1:30721"]
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Featured servers updated for label: official",
  "label": "official",
  "servers": ["127.0.0.1:30720", "127.0.0.1:30721"]
}
```

#### GET `/api/motd`

Get current MOTD.

**Response:**
```json
{
  "motd": "Welcome to Tremulous!"
}
```

#### PUT `/api/motd`

Update MOTD.

**Request Body:**
```json
{
  "motd": "Welcome to Tremulous! Have fun!"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "MOTD updated"
}
```

#### GET `/api/logs`

Get recent log entries.

**Query Parameters:**
- `limit`: Number of entries to return (default: 100, max: 1000)
- `level`: Filter by log level (ERROR, PRINT, VERBOSE, DEBUG)

**Response:**
```json
{
  "entries": [
    {
      "timestamp": 1705900000,
      "level": "PRINT",
      "message": "Server started"
    }
  ],
  "count": 1
}
```

#### POST `/api/admin/shutdown`

Emergency shutdown of the master server.

**Response:**
```json
{
  "status": "success",
  "message": "Shutdown initiated"
}
```

#### POST `/api/admin/reload-config`

Reload configuration files.

**Response:**
```json
{
  "status": "success",
  "message": "Configuration reloaded"
}
```

#### GET `/api/stats`

Get server statistics.

**Response:**
```json
{
  "total_servers": 10,
  "verified_servers": 8,
  "by_label": {
    "default": {"total": 5, "verified": 4},
    "official": {"total": 5, "verified": 4}
  },
  "by_connection_type": {
    "udp": 8,
    "websocket": 2
  },
  "by_address_family": {
    "ipv4": 10,
    "ipv6": 0
  },
  "featured_groups": 1
}
```

#### GET `/api/servers/rss`

RSS feed of server additions.

**Response:** XML (application/rss+xml)

## Error Responses

All endpoints return standard error responses:

```json
{
  "error": "Error Type",
  "message": "Human-readable error message"
}
```

Common HTTP status codes:
- `200 OK`: Request succeeded
- `201 Created`: Resource created
- `400 Bad Request`: Invalid input
- `401 Unauthorized`: Missing or invalid API key
- `403 Forbidden`: Operation not allowed
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server error

## Security

### API Key Authentication

All authenticated endpoints require a valid API key. Configure API keys via:

1. Environment variable: `SLEEPYTEEPEE_API_KEYS`
2. Command-line argument: `--api-keys`

API keys are comma-separated and never logged for security.

### Best Practices

1. **Use HTTPS**: In production, use TLS/SSL to encrypt API traffic
2. **Rotate Keys**: Regularly rotate API keys
3. **Limit Access**: Only expose the API on trusted networks
4. **Monitor Logs**: Review `/api/logs` for suspicious activity

## Development

### Project Structure

```
plugins/sleepyteepee/
├── __init__.py          # Plugin package initialization
├── auth.py              # API key authentication module
├── handlers.py           # REST API endpoint handlers
├── plugin.py             # Main plugin class
└── README.md             # This file
```

### Handler Functions

Handler functions in `handlers.py` follow a consistent signature:

```python
def handle_endpoint(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext
) -> HandlerResponse:
    """Handle endpoint request."""
    # Implementation
    return HandlerResponse(200, {"status": "success"})
```

### HandlerContext

The `HandlerContext` class provides access to:
- `config`: Master server configuration
- `servers`: Server registry
- `outSocks`: Output sockets
- `auth`: Authentication helper
- `plugin_instance`: Plugin instance

## HTTP Transport Implementations

Sleepyteepee supports multiple HTTP transport backends:

- **stdlib**: Python's built-in `http.server`
- **Flask**: Flask web framework
- **FastAPI**: FastAPI web framework

Transport implementations are in `plugins/transports/` and are automatically selected based on availability.

## License

This plugin is part of the Tremulous Master Server project and is licensed under the GNU General Public License v2.0.

## Contributing

Contributions to the Sleepyteepee plugin are welcome. Please follow the project's coding standards and submit pull requests.

## Support

For issues or questions about the Sleepyteepee plugin, please refer to the main Tremulous Master Server project documentation and issue tracker.
