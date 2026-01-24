# Tremulous Master Server

A Python implementation of the Tremulous Master Server, designed to track game servers and provide server lists to clients.

## Overview

The Tremulous Master Server is a network-based server that maintains a list of active Tremulous game servers. It handles server heartbeats, verifies servers through challenge-response authentication, and provides server lists to clients upon request. The server supports both IPv4 and IPv6, includes logging capabilities, offers various security features, and now includes WebSocket support for web-based clients.

## Features

### Core Functionality

- **Server Tracking**: Maintains a list of active game servers through heartbeat messages
- **Challenge-Response Verification**: Servers are verified before being added to the server list
- **Server List Distribution**: Responds to client requests for server lists
- **Server Caching**: Persists server list to disk (`serverlist.txt`) for quick recovery
- **Timeout Management**: Automatically removes inactive servers
- **Connection Type Tracking**: Tracks whether servers connect via UDP or WebSocket
- **Client Type Filtering**: WebSocket clients only see WebSocket servers, UDP clients only see UDP servers

### Network Support

- **Dual-Stack Operation**: Supports both IPv4 and IPv6 simultaneously
- **Multiple Listening Ports**: Can listen on multiple ports for incoming requests
- **Separate Challenge Port**: Uses a dedicated port for outgoing challenges to avoid NAT issues
- **Address Filtering**: Supports IP blacklisting via CIDR notation
- **WebSocket Support**: Enables web-based clients to connect via WebSocket protocol

### WebSocket Support

The master server now includes WebSocket support, allowing web-based clients to connect and communicate with the server. This feature enables:

- **Web-Based Clients**: Browser-based game clients can connect without requiring native UDP support
- **Protocol Compatibility**: WebSocket connections follow the same protocol as UDP connections
- **Multiple WebSocket Ports**: Can listen on multiple WebSocket ports simultaneously
- **Automatic Handshake**: Handles WebSocket handshake and connection management automatically
- **Message Framing**: Properly frames and unframes messages according to WebSocket protocol
- **Ping/Pong Support**: Responds to WebSocket ping frames with pong frames for keep-alive
- **Graceful Connection Handling**: Properly handles connection closure and errors

**WebSocket Implementation Details:**

- Uses the `wsproto` library for WebSocket protocol handling
- Supports binary message transmission for game protocol data
- Handles WebSocket connection lifecycle (accept, receive, close)
- Integrates seamlessly with existing UDP protocol handlers
- Logs WebSocket connection events for debugging

### Plugin System

The master server includes a comprehensive plugin system using [stevedore](https://docs.openstack.org/stevedore/latest/) for dynamic plugin loading. This feature enables:

- **Extensible Architecture**: Add new functionality without modifying core code
- **Pre-Initialization**: Plugins can fetch data before socket binding (e.g., puppet plugin)
- **Plugin Hooks**: Intercept heartbeat and getservers events
- **Connection Type Tracking**: Servers track UDP vs WebSocket connection type
- **Client Type Filtering**: WebSocket clients only see WebSocket servers, UDP clients only see UDP servers

**Plugin System Features:**

- Uses stevedore for plugin discovery and loading
- Plugins registered via setuptools entry points under namespace `tremulous.master.plugins`
- Two-phase initialization: pre-initialize (before socket binding) and initialize (after)
- Hook system allows plugins to intercept and modify server behavior
- Graceful cleanup on shutdown

**Available Plugins:**

See [`plugins/README.md`](plugins/README.md) for available plugins and their configuration.

### Protocol Support

The master server implements the following protocol messages:

| Protocol | Description |
|----------|-------------|
| `heartbeat <game>\n` | Server registration request |
| `getservers <protocol> [empty] [full]` | Standard server list request |
| `getserversExt Tremulous <protocol> [ipv4\|ipv6] [empty] [full]` | Extended server list request |
| `getmotd` | Message of the day request |
| `gamestat` | Game statistics logging |
| `infoResponse` | Server challenge response |

### Featured Servers

- **Labeled Server Groups**: Featured servers can be organized into labeled groups
- **Special Display**: Featured servers are sent in separate response packets with labels
- **Configuration File**: Featured servers defined in `featured.txt`

### Security Features

- **IP Blacklisting**: Block specific IP addresses or CIDR ranges via `ignore.txt`
- **Challenge-Response Authentication**: Servers must respond to a challenge before being listed
- **Chroot Support**: Can run in a chroot jail for enhanced security
- **Privilege Dropping**: Supports switching to a non-root user after initialization
- **Packet Filtering**: Rejects invalid packets and blacklisted sources

### Logging and Statistics

- **Multiple Verbosity Levels**: Configurable logging (ERROR, PRINT, VERBOSE, DEBUG)
- **WebSocket Logging**: Comprehensive WebSocket connection and event logging with `[WS]` prefix
- **Database Backends**: Supports SQLite, TDB, or no database
- **Client Statistics**: Logs client version and renderer information
- **Game Statistics**: Records game statistics from servers
- **Timestamped Logging**: All log entries include timestamps

### Configuration

- **Command-Line Options**: Extensive command-line interface for configuration
- **Configuration Files**: Uses text files for featured servers, blacklist, and MOTD
- **Configurable Timeouts**: Adjust challenge and server timeouts
- **Max Server Limit**: Optional limit on the number of tracked servers
- **WebSocket Configuration**: Enable/disable WebSocket support and configure ports

## Requirements

### Python Version

- Python 3.x only

### Standard Library Dependencies

The following Python standard library modules are required:

- `socket` - Network socket operations
- `select` - I/O multiplexing
- `signal` - Signal handling
- `time` - Time functions
- `os` - Operating system interface
- `sys` - System-specific parameters
- `itertools` - Iterator functions
- `random` - Random number generation
- `errno` - Standard errno system symbols
- `hashlib` - Secure hash and message digest algorithms
- `functools` - Higher-order functions and operations

### WebSocket Dependencies

- `wsproto` - WebSocket protocol implementation (install via pip)

### Plugin System Dependencies

- `stevedore` - Plugin management and discovery (install via pip)

### Optional Dependencies

- `sqlite3` - For SQLite database backend (standard library in Python 3.x)
- `tdb-py` - For TDB (Trivial Database) backend (install via pip)
- `pwd` - For user switching (Unix only)
- `grp` - For group switching (Unix only)

## Installation

1. Clone or download the repository
2. Ensure Python 3.x is installed
3. Install the WebSocket dependency:
   ```bash
   pip install wsproto
   ```
4. Install the plugin system dependency:
   ```bash
   pip install stevedore
   ```
5. (Optional) Install the `tdb-py` module if you want to use the TDB database backend:
   ```bash
   pip install tdb-py
   ```
6. (Optional) Create configuration files (see Configuration section)

## Usage

### Basic Usage

Run the master server with default settings:

```bash
python master.py
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Display help and exit |
| `-4, --ipv4` | Only use IPv4 |
| `-6, --ipv6` | Only use IPv6 |
| `-d, --db <none\|tdb\|sqlite\|auto>` | Database backend (default: auto) |
| `-j, --jail <DIR>` | Path to chroot into at startup |
| `-l, --listen-addr <ADDR>` | IPv4 address to listen to |
| `-L, --listen6-addr <ADDR>` | IPv6 address to listen to |
| `-n, --max-servers <NUM>` | Maximum number of servers to track |
| `-p, --port <NUM>` | Port for incoming requests (can be specified multiple times) |
| `-P, --challengeport <NUM>` | Port for outgoing challenges |
| `-q` | Decrease verbose level (can be used multiple times) |
| `-u, --user <USER>` | User to switch to at startup |
| `-v` | Increase verbose level (can be used multiple times) |
| `--verbose <LEVEL>` | Set verbose level directly (0-4) |
| `-V, --version` | Show version information |
| `-w, --use_ws` | Enable IPv4 WebSockets (default: enabled) |
| `-W, --ws_ports <NUM>` | WebSocket ports for incoming requests (can be specified multiple times) |

### Examples

Run with IPv4 only on port 30710:

```bash
python master.py -4 -p 30710
```

Run with verbose logging and SQLite database:

```bash
python master.py -v -d sqlite
```

Run with chroot and privilege dropping:

```bash
sudo python master.py -j /var/chroot/tremulous-master -u tremulous
```

Run with WebSocket support on port 8080:

```bash
python master.py -W 8080
```

Run with multiple WebSocket ports:

```bash
python master.py -W 8080 -W 8081 -W 8082
```

Run with both UDP and WebSocket support:

```bash
python master.py -p 30710 -W 8080
```

## Configuration Files

### featured.txt

Defines featured server groups with labels. Format:

```
Label Name
server1.example.com:30720
server2.example.com:30720

Another Label
server3.example.com:30720
```

- Lines starting with a label (no leading whitespace) define a new group
- Indented lines define server addresses for that group
- Blank lines and comments (lines starting with `#`) are ignored

### ignore.txt

Defines IP addresses and CIDR ranges to blacklist. Format:

```
# Comments start with #
192.168.1.100
10.0.0.0/8
2001:db8::/32
```

### motd.txt

Contains the message of the day sent to clients. Simple text file with one message.

### serverlist.txt

Automatically generated file that caches the server list. Created and managed by the master server.

## Database Setup

### SQLite

To create a new SQLite database:

```bash
python logsqlite.py stats.db
```

This creates two tables:
- `clients` - Stores client statistics (addr, version, renderer)
- `gamestats` - Stores game statistics (addr, time, data)

### TDB

The TDB backend automatically creates database files (`clientStats.tdb` and `gameStats.tdb`) when needed.

### No Database

To run without database logging:

```bash
python master.py -d none
```

## Protocol Details

### Heartbeat

Servers send heartbeat messages to register:

```
heartbeat Tremulous\n
```

The master responds with a challenge packet to verify the server.

### getservers

Clients request server lists:

```
getservers 71 empty full
```

- `71` - Protocol version
- `empty` - Include empty servers
- `full` - Include full servers

### getserversExt

Extended server list request:

```
getserversExt Tremulous 71 ipv4 ipv6 empty full
```

Supports IPv4/IPv6 filtering and returns multiple packets if needed.

### getmotd

Clients request the message of the day:

```
\xff\xff\xff\xffgetmotd\challenge\version\renderer\...
```

### infoResponse

Servers respond to challenges:

```
\xff\xff\xff\xffinfoResponse\challenge\...\hostname\...\protocol\...\clients\...\sv_maxclients\...
```

## WebSocket Protocol

WebSocket clients can connect to the master server and send the same protocol messages as UDP clients. The WebSocket implementation handles:

1. **Connection Handshake**: Automatically processes WebSocket upgrade requests
2. **Message Framing**: Wraps and unwraps binary messages according to WebSocket protocol
3. **Ping/Pong**: Responds to ping frames to maintain connection health
4. **Connection Management**: Tracks active WebSocket connections and handles disconnections
5. **Error Handling**: Gracefully handles connection errors and logs them

### WebSocket Client Example

A simple WebSocket client can connect and request servers:

```javascript
const ws = new WebSocket('ws://localhost:8080');

ws.onopen = () => {
    // Request server list
    const message = '\xff\xff\xff\xffgetservers 71 empty full';
    ws.send(message);
};

ws.onmessage = (event) => {
    console.log('Received:', event.data);
};
```

## Logging Levels

The master server supports five logging levels:

| Level | Value | Description |
|-------|-------|-------------|
| ALWAYS | 0 | Always displayed |
| ERROR | 1 | Error messages only |
| PRINT | 2 | Default level |
| VERBOSE | 3 | Detailed operational information |
| DEBUG | 4 | Full debugging output |

Use `-v` to increase verbosity or `-q` to decrease it. Use `--verbose <LEVEL>` to set directly.

### WebSocket Logging

WebSocket events are logged with a `[WS]` prefix for easy filtering. The following WebSocket events are logged:

| Event Type | Log Level | Description |
|------------|------------|-------------|
| Server Startup | PRINT/DEBUG | WebSocket server listening on specific ports |
| Connection Attempt | VERBOSE | New WebSocket connection attempts with client IP |
| Handshake Request | VERBOSE/DEBUG | WebSocket handshake details and subprotocols |
| Handshake Complete | VERBOSE/DEBUG | Connection established and state transitions |
| Message Received | VERBOSE/DEBUG | Incoming messages with content preview (truncated) |
| Message Sent | VERBOSE/DEBUG | Outgoing messages with content preview (truncated) |
| Ping/Pong | DEBUG | WebSocket keep-alive events |
| Disconnection | VERBOSE/DEBUG | Connection close events with reason codes |
| Connection Error | ERROR | Full error details with stack traces |
| State Changes | DEBUG | Protocol state transitions (connecting → connected → closed) |

**Message Preview**: Large messages are truncated to 100 bytes in logs for readability.

**Verbosity Control**:
- **No -v**: Only WebSocket errors and startup messages shown
- **Single -v**: Connection events, handshakes, and message previews shown
- **Double -v**: Full debugging output including state transitions and stack traces

**Example**: To filter only WebSocket logs:
```bash
grep '\[WS\]' master_output.log
```

## Default Values

| Setting | Default Value |
|---------|---------------|
| Listen Port | 30710 |
| Challenge Port | 30711 (or next available) |
| WebSocket Ports | None (must be specified with `-W`) |
| Challenge Length | 12 characters |
| Challenge Timeout | 5 seconds |
| Server Timeout | 660 seconds (11 minutes) |
| Max Servers per Packet | 256 |
| Database Backend | auto (tries SQLite, then TDB) |
| WebSocket Support | Enabled |

## File Structure

```
tremulous-master-web/
├── master.py          # Main server implementation
├── config.py          # Configuration management
├── db.py              # Database connection abstraction
├── logsqlite.py       # SQLite logging backend
├── logtdb.py          # TDB logging backend
├── utils.py           # Utility functions
├── plugins/           # Plugin system directory
│   ├── __init__.py    # Plugin initialization
│   ├── puppet.py      # Puppet plugin for cloning servers from remote masters
│   └── README.md      # Plugin documentation
├── .gitignore         # Git ignore patterns
├── featured.txt       # Featured servers configuration (optional)
├── ignore.txt         # IP blacklist (optional)
├── motd.txt           # Message of the day (optional)
├── serverlist.txt     # Server cache (auto-generated)
├── stats.db           # SQLite database (auto-generated, if using SQLite)
└── README.md          # This file
```

## License

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

The 'stevedore' plugin system is licensed under the Apache-2.0 License

## Credits

- Original C implementation: Mathieu Olivier
- Python implementation: Ben Millwood (2009-2011)
- Updates: Jeff Kent (2015), Darren Salt (2012)
- WebSocket support: AurigaSyno https://github.com/AurigaSyno (2026)
- Plugin support, HTTP transport, Puppet and SleepyTeePee API plugin: redrumrobot 
   https://github.com/redrumrobot (2026)

## Troubleshooting

### Port Already in Use

If you get a "port already in use" error, either:
- Stop the existing process using the port
- Use a different port with `-p <PORT>` or `-W <PORT>`

### Database Import Errors

If you see "database not available" warnings:
- Install the required database module (`sqlite3` is included in Python 2.5+)
- Use `-d none` to run without database logging

### Permission Denied

If you get permission errors:
- Ensure you have permission to bind to the specified ports (ports < 1024 require root)
- Check file permissions for configuration files and databases

### IPv6 Not Working

If IPv6 doesn't work:
- Ensure your system supports IPv6
- Check that the IPv6 address is valid and not already in use
- Use `-4` to run with IPv4 only

### WebSocket Connection Issues

If WebSocket connections fail:
- Ensure the `wsproto` library is installed: `pip install wsproto`
- Check that WebSocket ports are specified with `-W` option
- Verify firewall rules allow WebSocket connections
- Check logs for connection errors and verify client handshake

**Debugging WebSocket Connections**:
- Run with `-v -v` for full WebSocket event logging
- Filter logs with `grep '\[WS\]'` to see only WebSocket events
- Look for handshake errors in the logs (e.g., invalid subprotocols)
- Check for state transitions to understand connection flow
- Review stack traces for detailed error information

### WebSocket Port Conflicts

If WebSocket ports conflict with UDP ports:
- Ensure WebSocket ports are different from UDP ports
- Use distinct port ranges for each protocol
- Check logs for port binding errors

### WebSocket Messages Not Received

If WebSocket clients don't receive responses:
- Verify the message format matches the UDP protocol (including `\xff\xff\xff\xff` header)
- Check that the client properly handles binary WebSocket messages
- Review server logs for processing errors
- Ensure the WebSocket connection is still open (check for close events)
