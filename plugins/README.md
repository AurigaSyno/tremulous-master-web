# Tremulous Master Server Plugin System

This directory contains plugins for the Tremulous Master Server. The plugin system uses [stevedore](https://docs.openstack.org/stevedore/latest/) to dynamically load plugins at runtime.

## Plugin Architecture

Plugins are Python modules that extend the master server functionality. They are loaded via setuptools entry points under the namespace `tremulous.master.plugins`.

**Plugin System Features:**

- **Two-Phase Initialization**: Plugins support both `pre_initialize()` (called before socket binding) and `initialize()` (called after socket binding). This allows plugins to fetch data from external sources before the master server starts listening.
- **Connection Type Tracking**: The master server tracks whether servers connect via UDP or WebSocket. This information is available to plugins via the `Server` class.
- **Client Type Filtering**: The master server filters servers based on client type - WebSocket clients only see WebSocket servers, and UDP clients only see UDP servers.
- **Graceful Cleanup**: Plugins receive a `cleanup()` call during server shutdown for proper resource cleanup.
- **Hook System**: Plugins can intercept and modify server behavior through various hooks.

## Creating a Plugin

1. **Create a plugin class** that inherits from `MasterPluginBase`:

```python
from plugins.base import MasterPluginBase

class MyPlugin(MasterPluginBase):
    def get_name(self) -> str:
        return 'my_plugin'

    def initialize(self) -> bool:
        # Perform initialization here
        return True  # Return False to disable the plugin
```

2. **Register the plugin** in `pyproject.toml`:

```toml
[project.entry-points."tremulous.master.plugins"]
my_plugin = "plugins.myplugin:MyPlugin"
```

3. **Install the package** in development mode:

```bash
pip install -e .
```

## Plugin Hooks

Plugins can hook into various events in the master server:

- `pre_initialize()` - Called before socket binding (optional). Use this to fetch data from external sources.
- `initialize()` - Called after socket binding. Perform plugin initialization here.
- `on_heartbeat(addr, data)` - Called when a heartbeat is received
- `on_getservers(sock, addr, data)` - Called when a getservers request is received
- `on_server_timeout(server)` - Called when a server times out
- `cleanup()` - Called during shutdown

**Hook Return Values:**

- `on_heartbeat()` can return a modified heartbeat tuple to change the data
- `on_getservers()` can return a custom response tuple to override the default response
- Other hooks are called for their side effects and return values are ignored

## Available Plugins

### Puppet Plugin

The `puppet` plugin clones servers from a remote master server.

**Safeguards:**

To prevent infinite loops when multiple master servers use the puppet plugin:
1. Servers already cloned from another master (in 'puppet' label) are skipped
2. Servers that are already in the 'puppet' label are not re-cloned
3. Servers from the remote master's own address are skipped

**Supported Master Server Types:**

The puppet plugin supports both standard Python master servers and JavaScript-based master servers:

1. **Standard Python Master Servers** (e.g., master.tremulous.net, master.ioquake3.org)
   - Uses standard `getserversResponse` format with binary IP addresses
   - Default UDP port: 30710
   - Supports both UDP and WebSocket connections

2. **JavaScript Master Servers** (e.g., master.tremulous.online)
   - Uses `getserverswebResponse` format with hostnames
   - Default WebSocket port: 30700
   - Default UDP port: 40700
   - Supports both UDP and WebSocket connections

**Configuration Options:**

- `--puppet-master ADDR` - Remote master server address
- `--puppet-port PORT` - Remote master server port (default: 30710)
- `--puppet-protocol PROTOCOL` - Protocol version for puppet plugin (default: 71). Common values: 70 (Tremulous 1.1), 71 (Tremulous 1.2+), 68 (Quake3/ioquake3)
- `--puppet-use-websocket` - Use WebSocket instead of UDP for puppet plugin connections
- `--puppet-interval SECONDS` - Sync interval in seconds (default: 300)
- `--puppet-disable` - Disable the puppet plugin

**Examples:**

```bash
# Connect to standard Python master server (UDP)
python3 master.py --puppet-master master.tremulous.net --puppet-port 30710

# Connect to standard Python master server (WebSocket)
python3 master.py --puppet-master master.tremulous.net --puppet-port 30710 --puppet-use-websocket

# Connect to JavaScript master server (WebSocket)
python3 master.py --puppet-master master.tremulous.online --puppet-port 30700 --puppet-use-websocket

# Connect to JavaScript master server (UDP)
python3 master.py --puppet-master master.tremulous.online --puppet-port 40700
```

## Plugin Base Class

The `MasterPluginBase` class (defined in `plugins/__init__.py`) provides the following methods:

- `__init__(config, servers, outSocks)` - Initialize with server configuration
  - `config`: Dictionary of command-line arguments and configuration
  - `servers`: Dictionary of active servers (keyed by server address)
  - `outSocks`: List of output sockets for sending responses
- `get_name()` - Return the plugin name (abstract)
- `pre_initialize()` - Called before socket binding (optional, returns bool)
- `initialize()` - Initialize the plugin (abstract, returns bool)
- `on_heartbeat(addr, data)` - Hook for heartbeat events
  - `addr`: Tuple of (ip, port) for the server
  - `data`: The heartbeat data string
  - Returns: Modified heartbeat tuple or None to use default
- `on_getservers(sock, addr, data)` - Hook for getservers events
  - `sock`: The socket that received the request
  - `addr`: Tuple of (ip, port) for the client
  - `data`: The getservers request data
  - Returns: Custom response tuple (response, addr) or None to use default
- `on_server_timeout(server)` - Hook for server timeout events
  - `server`: The Server object that timed out
- `cleanup()` - Cleanup resources during shutdown
- `get_info()` - Return plugin metadata (returns dict)

## Server Class

The `Server` class represents a game server in the master server's list. Plugins can access server information through the `servers` dictionary passed during initialization.

**Server Attributes:**

- `addr`: Tuple of (ip, port) for the server
- `challenge`: The challenge string sent to the server
- `last_seen`: Timestamp of last heartbeat
- `connection_type`: Either 'udp' or 'websocket' - indicates how the server connects
- `game`: The game name (e.g., 'Tremulous')
- `hostname`: Server hostname (if available)
- `protocol`: Protocol version
- `clients`: Current number of clients
- `max_clients`: Maximum number of clients
- `mapname`: Current map name (if available)
- `label`: Optional label for server grouping (e.g., 'puppet' for puppet plugin servers)

**Connection Type Tracking:**

The master server automatically determines the connection type of each server:
- UDP heartbeats are marked with `connection_type='udp'`
- WebSocket connections are marked with `connection_type='websocket'`

Plugins can use this information to filter or modify server behavior based on connection type.
