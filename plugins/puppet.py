"""
Puppet Plugin - Clones servers from remote master servers.

This plugin connects to one or more remote Tremulous master servers and
mirrors their server lists into the local master server.

Important: To prevent infinite loops, this plugin will NOT clone servers
that are already in the 'puppet' label (i.e., servers that were
themselves cloned from another master). This prevents two master servers
with puppet enabled from endlessly cloning each other's servers.

The plugin supports both UDP and WebSocket connections to remote masters.
When auto-detect is enabled (no explicit --puppet-use-websocket flag),
the plugin tries both UDP and WebSocket in parallel and uses whichever
responds first.

Multiple remote masters can be configured. If not specified, defaults to:
- master.tremulous.net:30710
- master.tremulous.online:30710
- master.tremulo.us:30710

Each master can optionally specify which protocol to use:
- 'udp' - Use UDP connection
- 'websocket' - Use WebSocket connection
- 'auto' - Auto-detect (try both, use whichever responds first)

If not specified, uses auto-detect or the global --puppet-use-websocket setting.

Configuration file (puppetmasters.txt) format:
- host:port (uses default connection and game protocol)
- host:port:conn_protocol (specific connection: udp, websocket, or auto)
- host:port:conn_protocol:game_protocol (specific connection and game protocol like 69, 71)
- host:port:conn_protocol:game_protocol:request_type (specific request type: getservers or getserversExt)
- host port conn_protocol game_protocol (space-separated format)

Note: The Node.js master server (e.g., master.tremulous.online) uses 'getserversExt' request type
and responds with 'getserverswebResponse' format containing hostnames instead of raw IPs.
"""
import socket
from socket import SOCK_DGRAM, SOCK_STREAM
from time import sleep
import struct
import threading
from typing import Optional, Dict, Any, List, Set
from time import time

from .base import MasterPluginBase

# Try to import WebSocket support
try:
    from wsproto import ConnectionType, WSConnection
    from wsproto.events import Request, BytesMessage, AcceptConnection, CloseConnection, Ping, Pong
    WS_AVAILABLE = True
except ImportError:
    WS_AVAILABLE = False


class PuppetPlugin(MasterPluginBase):
    """Plugin that clones servers from remote master servers."""

    version = '1.0.0'
    description = 'Clones servers from remote master servers'

    # Default list of remote masters to query (empty - use puppetmasters.txt)
    DEFAULT_REMOTE_MASTERS = []

    # Default path to masters configuration file
    DEFAULT_MASTERS_FILE = 'puppetmasters.txt'

    def __init__(self, config: Any, servers: Dict, outSocks: Dict):
        super().__init__(config, servers, outSocks)
        self.remote_masters: List[tuple] = []  # List of (host, port, conn_protocol, game_protocol, request_type) tuples
        self.protocol: str = '71'  # Default game protocol
        self.use_websocket: bool = False  # Use WebSocket instead of UDP
        self.sync_interval: int = 300  # 5 minutes default
        self.last_sync: float = 0
        self.cloned_servers: Set[tuple] = set()  # Track cloned servers to prevent duplicates
        self.enabled = True
        self.sync_thread: Optional[threading.Thread] = None
        self.sync_stop_event = threading.Event()
        self.pre_fetched_servers: List[tuple] = []  # Store servers fetched before socket binding
        self.run_once = False  # If True, only run sync once and exit (don't start background thread)
        # Track master connection type for each server: {(host, port): 'udp' or 'websocket'}
        # This indicates what type of connection the REMOTE MASTER uses, not the game server itself
        self.master_connection_types: Dict[tuple, str] = {}

    def get_name(self) -> str:
        return 'puppet'

    def pre_initialize(self) -> bool:
        """Pre-initialize puppet plugin before socket binding.

        This method fetches servers from remote master and stores them.
        The actual server addition (with challenges) happens after socket binding
        in the initialize() method.

        Returns:
            bool: True if pre-initialization succeeded, False otherwise
        """
        from config import log, LOG_PRINT, LOG_VERBOSE, LOG_DEBUG, LOG_ERROR

        # Check for puppet configuration in config object
        if hasattr(self.config, 'puppet_remote_masters'):
            # Support list of (host, port) tuples
            masters = self.config.puppet_remote_masters
            if isinstance(masters, list) and all(isinstance(m, (tuple, list)) and len(m) >= 2 for m in masters):
                # Handle (host, port) or (host, port, protocol) tuples
                self.remote_masters = []
                for m in masters:
                    if len(m) >= 3:
                        protocol = m[2].strip().lower() if m[2] else None
                        self.remote_masters.append((m[0], int(m[1]), protocol, None, None))
                    else:
                        self.remote_masters.append((m[0], int(m[1]), None, None, None))
            else:
                log(LOG_ERROR, 'Puppet plugin: Invalid puppet_remote_masters format, expected list of (host, port) tuples')
        elif hasattr(self.config, 'puppet_remote_master') and self.config.puppet_remote_master is not None:
            # Support single master for backward compatibility
            host = self.config.puppet_remote_master
            port = self.config.puppet_remote_port if hasattr(self.config, 'puppet_remote_port') else 30710
            self.remote_masters = [(host, port, None, None, None)]
        else:
            # Try to read from puppetmasters.txt file
            self.remote_masters = self._read_masters_from_file()
            if not self.remote_masters:
                # Fall back to default list
                log(LOG_VERBOSE, f'Puppet plugin: No puppetmasters.txt found, using default masters')
                self.remote_masters = self.DEFAULT_REMOTE_MASTERS.copy()

        if hasattr(self.config, 'puppet_protocol'):
            self.protocol = self.config.puppet_protocol
        if hasattr(self.config, 'puppet_use_websocket') and self.config.puppet_use_websocket is not None:
            self.use_websocket = self.config.puppet_use_websocket
        if hasattr(self.config, 'puppet_interval'):
            self.sync_interval = self.config.puppet_interval
        if hasattr(self.config, 'puppet_enabled'):
            self.enabled = self.config.puppet_enabled
        if hasattr(self.config, 'puppet_run_once'):
            self.run_once = self.config.puppet_run_once

        if not self.remote_masters:
            log(LOG_PRINT, 'Puppet plugin: No remote masters configured, plugin disabled')
            self.enabled = False
            return False

        masters_str = ', '.join([f'{host}:{port}' for host, port, _, _, _ in self.remote_masters])
        log(LOG_VERBOSE, f'Puppet plugin pre-initialization: masters=[{masters_str}], '
                        f'protocol={self.protocol}, interval={self.sync_interval}s')

        # Fetch servers from remote master before socket binding
        log(LOG_VERBOSE, 'Puppet plugin: Pre-fetching servers from remote master...')
        self.pre_fetched_servers = self.fetch_remote_servers()
        log(LOG_VERBOSE, f'Puppet plugin: Pre-fetched {len(self.pre_fetched_servers)} servers')

        return True

    def _read_masters_from_file(self) -> List[tuple]:
        """Read list of masters from puppetmasters.txt file.

        Returns:
            List of (host, port, conn_protocol, game_protocol, request_type) tuples

        File format: one master per line, with optional protocols:
        - 'host:port' (uses defaults)
        - 'host:port:conn_protocol' (specific connection: udp, websocket, auto)
        - 'host:port:conn_protocol:game_protocol' (specific connection and game protocol like 69, 71)
        - 'host:port:conn_protocol:game_protocol:request_type' (specific request type: getservers or getserversExt)
        - 'host port conn_protocol game_protocol' (space-separated format)
        """
        from config import log, LOG_DEBUG, LOG_ERROR, LOG_VERBOSE

        masters = []
        try:
            with open(self.DEFAULT_MASTERS_FILE, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue

                    # Parse host:port or host port format, with optional protocol
                    if ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            host = parts[0].strip()
                            port_part = parts[1].strip()

                            # Check if protocols are specified after port
                            if ':' in port_part:
                                port_protocol_parts = port_part.split(':')
                                if len(port_protocol_parts) >= 2:
                                    try:
                                        port = int(port_protocol_parts[0].strip())
                                        conn_protocol = port_protocol_parts[1].strip().lower() if port_protocol_parts[1].strip() else None
                                        game_protocol = port_protocol_parts[2].strip() if len(port_protocol_parts) >= 3 and port_protocol_parts[2].strip() else None
                                        request_type = port_protocol_parts[3].strip() if len(port_protocol_parts) >= 4 and port_protocol_parts[3].strip() else None
                                        masters.append((host, port, conn_protocol, game_protocol, request_type))
                                        log(LOG_DEBUG, f'Puppet: Read master {host}:{port} (conn: {conn_protocol}, game: {game_protocol}, req: {request_type}) from file (line {line_num})')
                                    except ValueError:
                                        log(LOG_ERROR, f'Puppet: Invalid port on line {line_num}: {line}')
                                else:
                                    log(LOG_ERROR, f'Puppet: Invalid format on line {line_num}: {line}')
                            else:
                                # No protocols specified, use defaults
                                try:
                                    port = int(port_part)
                                    masters.append((host, port, None, None, None))  # None = use defaults
                                    log(LOG_DEBUG, f'Puppet: Read master {host}:{port} from file (line {line_num})')
                                except ValueError:
                                    log(LOG_ERROR, f'Puppet: Invalid port on line {line_num}: {line}')
                    else:
                        # Try space-separated format
                        parts = line.split()
                        if len(parts) >= 2:
                            host = parts[0].strip()
                            port_part = parts[1].strip()

                            # Check if protocols are specified
                            conn_protocol = parts[2].strip().lower() if len(parts) >= 3 and parts[2].strip() else None
                            game_protocol = parts[3].strip() if len(parts) >= 4 and parts[3].strip() else None
                            request_type = parts[4].strip() if len(parts) >= 5 and parts[4].strip() else None
                            
                            try:
                                port = int(port_part)
                                masters.append((host, port, conn_protocol, game_protocol, request_type))
                                log(LOG_DEBUG, f'Puppet: Read master {host}:{port} (conn: {conn_protocol}, game: {game_protocol}, req: {request_type}) from file (line {line_num})')
                            except ValueError:
                                log(LOG_ERROR, f'Puppet: Invalid port on line {line_num}: {line}')
                        else:
                            log(LOG_ERROR, f'Puppet: Invalid format on line {line_num}: {line}')

        except FileNotFoundError:
            log(LOG_DEBUG, f'Puppet: {self.DEFAULT_MASTERS_FILE} not found, using default masters')
            return []
        except Exception as e:
            log(LOG_ERROR, f'Puppet: Error reading {self.DEFAULT_MASTERS_FILE}: {e}')
            return []

        log(LOG_VERBOSE, f'Puppet: Loaded {len(masters)} masters from {self.DEFAULT_MASTERS_FILE}')
        return masters

    def initialize(self) -> bool:
        """Initialize puppet plugin.

        Reads configuration from config object or uses defaults.
        """
        from config import log, LOG_PRINT, LOG_VERBOSE, LOG_DEBUG

        # Configuration was already loaded in pre_initialize(), skip here
        # This method is called after socket binding

        if not self.remote_masters:
            log(LOG_PRINT, 'Puppet plugin: No remote masters configured, plugin disabled')
            self.enabled = False
            return False

        masters_str = ', '.join([f'{host}:{port}' for host, port, _, _, _ in self.remote_masters])
        log(LOG_VERBOSE, f'Puppet plugin initialized: masters=[{masters_str}], '
                        f'protocol={self.protocol}, interval={self.sync_interval}s')

        # If we pre-fetched servers, add them now that sockets are bound
        if self.pre_fetched_servers:
            log(LOG_VERBOSE, f'Puppet plugin: Adding {len(self.pre_fetched_servers)} pre-fetched servers...')
            self._add_pre_fetched_servers()
            self.pre_fetched_servers = []  # Clear the pre-fetched list
        else:
            # Perform initial sync if no pre-fetched servers
            log(LOG_VERBOSE, 'Puppet plugin: Performing initial sync...')
            self.sync_servers()

        # Start background sync thread only if run_once is False
        if not self.run_once:
            self.sync_stop_event.clear()
            self.sync_thread = threading.Thread(target=self._sync_loop, daemon=True, name='PuppetSyncThread')
            self.sync_thread.start()
            log(LOG_VERBOSE, 'Puppet plugin: Started background sync thread')
        else:
            log(LOG_VERBOSE, 'Puppet plugin: run_once=True, skipping background sync thread')

        return True

    def _sync_loop(self):
        """Background thread that performs periodic syncs."""
        from config import log, LOG_ERROR, LOG_DEBUG

        while not self.sync_stop_event.is_set():
            try:
                self.sync_servers()
            except Exception as e:
                log(LOG_ERROR, f'Puppet plugin: Error in sync loop: {e}')

            # Sleep until next sync or stop event
            if self.sync_stop_event.wait(timeout=self.sync_interval):
                break

    def _fetch_udp_servers(self, master: str, port: int, game_protocol: Optional[str] = None, request_type: Optional[str] = None) -> List[tuple]:
        """Fetch servers using UDP protocol.

        Args:
            master: Remote master hostname
            port: Remote master port
            game_protocol: Optional game protocol override (like 69, 71)
            request_type: Optional request type ('getservers' or 'getserversExt')

        Returns:
            List of (host, port) tuples
        """
        from config import log, LOG_DEBUG, LOG_ERROR, LOG_PRINT, LOG_VERBOSE
        from config import log, LOG_DEBUG, LOG_ERROR, LOG_PRINT, LOG_VERBOSE

        servers = []
        try:
            # Create a new UDP socket for sending requests to remote master
            # We cannot use the existing outSocks because they are bound to specific addresses/ports
            log(LOG_DEBUG, f'Puppet: Creating new UDP socket for {master}:{port}')

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(10)

            # Send getservers or getserversExt request using game protocol
            protocol_to_use = game_protocol if game_protocol else self.protocol
            req_type_to_use = request_type if request_type else 'getservers'
            request = b'\xff\xff\xff\xff' + req_type_to_use.encode('utf-8') + b' ' + protocol_to_use.encode('utf-8') + b' empty full'
            log(LOG_DEBUG, f'Puppet: Sending {req_type_to_use} request to {master}:{port} with game protocol {protocol_to_use}')
            log(LOG_DEBUG, f'Puppet: Request data: {request!r}')
            try:
                sock.sendto(request, (master, port))
            except socket.error as e:
                log(LOG_ERROR, f'Puppet: Failed to send UDP request to {master}:{port}: {e}')
                return servers

            # Receive multiple packets until timeout
            packet_count = 0
            while True:
                try:
                    data, _ = sock.recvfrom(4096)
                    packet_count += 1
                    log(LOG_DEBUG, f'Puppet: Received packet #{packet_count}, {len(data)} bytes from {master}:{port}')
                    log(LOG_DEBUG, f'Puppet: Response data: {data[:100]!r}...')
                except socket.timeout:
                    log(LOG_DEBUG, f'Puppet: Receive timeout after {packet_count} packets')
                    break
                except socket.error as e:
                    log(LOG_ERROR, f'Puppet: Socket error receiving from {master}:{port}: {e}')
                    break
                except Exception as e:
                    log(LOG_ERROR, f'Puppet: Unexpected error receiving from {master}:{port}: {e}')
                    break

                    # Parse getserversResponse, getserverswebResponse, or getserversExtResponse
                    if data.startswith(b'\xff\xff\xff\xffgetserverswebResponse'):
                        # JavaScript master server response: skip 24 bytes (4 byte header + 20 byte response string)
                        data = data[24:]
                        log(LOG_DEBUG, f'Puppet: getserverswebResponse header confirmed (JavaScript master server), parsing {len(data)} bytes')

                        # JavaScript master server format: \hostname:port\hostname:port\...\EOT
                        # Parse until \EOT marker
                        eot_index = data.find(b'EOT')
                        if eot_index != -1:
                            data = data[:eot_index]

                        while True:
                            # Check for end marker
                            if len(data) == 0 or (data[0:1] == b'\\' and len(data) == 1):
                                log(LOG_DEBUG, f'Puppet: End marker found, stopping receive loop')
                                break

                            # Find next separator
                            sep_index = data.find(b'\\')
                            if sep_index == -1:
                                log(LOG_PRINT, f'Puppet: No separator found, stopping parse')
                                break

                            # Extract server entry
                            server_entry = data[:sep_index]
                            data = data[sep_index + 1:]

                            # Parse hostname:port format
                            if b':' in server_entry:
                                parts = server_entry.split(b':')
                                if len(parts) == 2:
                                    host = parts[0].decode('utf-8')
                                    try:
                                        port = int(parts[1])
                                        servers.append((host, port))
                                        log(LOG_DEBUG, f'Puppet: Parsed server {host}:{port} (hostname format)')
                                    except ValueError:
                                        log(LOG_PRINT, f'Puppet: Invalid port number: {parts[1]}')
                                else:
                                    log(LOG_PRINT, f'Puppet: Invalid server entry format: {server_entry}')
                            break
                    elif data.startswith(b'\xff\xff\xff\xffgetserversResponse'):
                        # Standard response: skip 22 bytes (4 byte header + 17 byte response string + 1 byte)
                        data = data[22:]
                        log(LOG_DEBUG, f'Puppet: Standard getserversResponse header confirmed, parsing {len(data)} bytes')

                        while True:
                            # Check for end marker first (only if it's the ONLY byte remaining)
                            if len(data) == 0 or (data[0:1] == b'\\' and len(data) == 1):
                                log(LOG_DEBUG, f'Puppet: End marker found, stopping receive loop')
                                break
                            # Need at least 6 bytes for IPv4 address (1 separator + 4 IP + 2 port)
                            if len(data) < 6:
                                log(LOG_PRINT, f'Puppet: Not enough data for server address, stopping parse')
                                break
                            sep = data[0:1]
                            if sep == b'\\':
                                # IPv4
                                host = socket.inet_ntop(socket.AF_INET, data[1:5])
                                port = struct.unpack('!H', data[5:7])[0]
                                data = data[7:]
                            elif sep == b'/':
                                # IPv6
                                host = socket.inet_ntop(socket.AF_INET6, data[1:17])
                                port = struct.unpack('!H', data[17:19])[0]
                                data = data[19:]
                            else:
                                log(LOG_PRINT, f'Puppet: Unknown separator {sep!r}, stopping parse')
                                break

                            servers.append((host, port))
                            log(LOG_DEBUG, f'Puppet: Parsed server {host}:{port} (family: {"IPv4" if sep == b"\\" else "IPv6"})')
                    elif data.startswith(b'\xff\xff\xff\xffgetserversExtResponse'):
                        # Extended response: skip 27 bytes (4 byte header + 22 byte response string + 1 byte)
                        data = data[27:]
                        log(LOG_DEBUG, f'Puppet: Extended getserversExtResponse header confirmed, parsing {len(data)} bytes')

                        # Skip extended header: \0<index>\0<total>\0<label>\0
                        parts = data.split(b'\0', 3)
                        if len(parts) >= 4:
                            index = int(parts[0]) if parts[0] else 0
                            total = int(parts[1]) if parts[1] else 0
                            label = parts[2].decode('utf-8') if parts[2] else ''
                            server_data = parts[3]
                            log(LOG_DEBUG, f'Puppet: Extended packet {index} of {total}, label: {label}')

                            # Parse servers from server_data
                            while True:
                                # Check for end marker first (only if it's the ONLY byte remaining)
                                if len(server_data) == 0 or (server_data[0:1] == b'\\' and len(server_data) == 1):
                                    log(LOG_DEBUG, f'Puppet: End marker found, stopping receive loop')
                                    break
                                # Need at least 6 bytes for IPv4 address (1 separator + 4 IP + 2 port)
                                if len(server_data) < 6:
                                    log(LOG_PRINT, f'Puppet: Not enough data for server address, stopping parse')
                                    break
                                sep = server_data[0:1]
                                if sep == b'\\':
                                    # IPv4
                                    host = socket.inet_ntop(socket.AF_INET, server_data[1:5])
                                    port = struct.unpack('!H', server_data[5:7])[0]
                                    server_data = server_data[7:]
                                elif sep == b'/':
                                    # IPv6
                                    host = socket.inet_ntop(socket.AF_INET6, server_data[1:17])
                                    port = struct.unpack('!H', server_data[17:19])[0]
                                    server_data = server_data[19:]
                                else:
                                    log(LOG_PRINT, f'Puppet: Unknown separator {sep!r}, stopping parse')
                                    break

                                servers.append((host, port))
                                log(LOG_DEBUG, f'Puppet: Parsed server {host}:{port} (family: {"IPv4" if sep == b"\\" else "IPv6"})')
                            else:
                                log(LOG_PRINT, f'Puppet: Invalid getserversExt response format')
                    else:
                        log(LOG_PRINT, f'Puppet: Unexpected response format: {data[:30]!r}')

                except socket.timeout:
                    log(LOG_DEBUG, f'Puppet: Receive timeout after {packet_count} packets')
                    break

            try:
                sock.close()
            except Exception as close_err:
                log(LOG_DEBUG, f'Puppet: Error closing UDP socket: {close_err}')
            log(LOG_VERBOSE, f'Puppet: Total servers fetched: {len(servers)} from {packet_count} packets')
            return servers

        except Exception as e:
            log(LOG_ERROR, f'Puppet plugin: Error fetching UDP servers: {e}')
            return servers

    def _fetch_websocket_servers(self, master: str, port: int, game_protocol: Optional[str] = None, request_type: Optional[str] = None) -> List[tuple]:
        """Fetch servers using WebSocket protocol.

        Args:
            master: Remote master hostname
            port: Remote master port
            game_protocol: Optional game protocol override (like 69, 71)
            request_type: Optional request type ('getservers' or 'getserversExt')

        Returns:
            List of (host, port) tuples
        """
        from config import log, LOG_DEBUG, LOG_ERROR, LOG_PRINT, LOG_VERBOSE

        if not WS_AVAILABLE:
            log(LOG_PRINT, 'Puppet: WebSocket not available, falling back to UDP')
            return []

        servers = []
        try:
            # Use WebSocket connection
            log(LOG_DEBUG, f'Puppet: Creating WebSocket connection to {master}:{port}')

            # Create TCP socket for WebSocket with explicit timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)  # 10 second timeout for connection

            # Connect to remote master
            try:
                sock.connect((master, port))
            except socket.timeout:
                log(LOG_ERROR, f'Puppet: Connection timeout to {master}:{port}')
                return servers
            except socket.error as e:
                log(LOG_ERROR, f'Puppet: Failed to connect to {master}:{port}: {e}')
                return servers

            # Create WebSocket connection
            ws = WSConnection(ConnectionType.CLIENT)

            # Send WebSocket upgrade request
            outgoing_data = ws.send(Request(host=master, target='/'))
            sock.sendall(outgoing_data)
            log(LOG_DEBUG, f'Puppet: WebSocket upgrade request sent')

            # Wait for handshake to complete
            start_time = time()
            handshake_complete = False
            timeout = 10

            while time() - start_time < timeout:
                try:
                    data = sock.recv(4096)
                    if data:
                        log(LOG_DEBUG, f'Puppet: Received {len(data)} bytes during handshake')
                        log(LOG_DEBUG, f'Puppet: Handshake data: {data[:100]!r}...')
                        ws.receive_data(data)
                        for event in ws.events():
                            if isinstance(event, AcceptConnection):
                                log(LOG_DEBUG, f'Puppet: WebSocket handshake complete')
                                handshake_complete = True
                                break
                            elif isinstance(event, CloseConnection):
                                log(LOG_ERROR, f'Puppet: WebSocket connection closed by server during handshake')
                                return servers
                            elif isinstance(event, Ping):
                                # Respond to ping with pong
                                outgoing_data = ws.send(Pong(payload=event.payload))
                                sock.sendall(outgoing_data)
                            else:
                                log(LOG_DEBUG, f'Puppet: Unknown event during handshake: {type(event).__name__}')
                    else:
                        log(LOG_DEBUG, f'Puppet: No data received, connection closed by server')
                        return servers
                except BlockingIOError:
                    sleep(0.1)
                    continue
                except socket.error as e:
                    log(LOG_ERROR, f'Puppet: WebSocket receive error: {e}')
                    return servers

            if not handshake_complete:
                log(LOG_ERROR, f'Puppet: WebSocket handshake timeout')
                return servers

            # Send getservers or getserversExt request using game protocol
            protocol_to_use = game_protocol if game_protocol else self.protocol
            req_type_to_use = request_type if request_type else 'getservers'
            request = b'\xff\xff\xff\xff' + req_type_to_use.encode('utf-8') + b' ' + protocol_to_use.encode('utf-8') + b' empty full'
            log(LOG_DEBUG, f'Puppet: Sending {req_type_to_use} request to {master}:{port} with game protocol {protocol_to_use}')
            log(LOG_DEBUG, f'Puppet: Request data: {request!r}')

            # Send via WebSocket
            ws_data = ws.send(BytesMessage(data=request))
            sock.sendall(ws_data)

            # Receive response
            start_time = time()
            timeout = 10

            while time() - start_time < timeout:
                try:
                    data = sock.recv(4096)
                    if not data:
                        log(LOG_ERROR, f'Puppet: WebSocket connection closed')
                        return servers

                    ws.receive_data(data)

                    for event in ws.events():
                        if isinstance(event, BytesMessage):
                            message_data = event.data
                            log(LOG_DEBUG, f'Puppet: Received {len(message_data)} bytes from {master}:{port}')
                            log(LOG_DEBUG, f'Puppet: Response data: {message_data[:100]!r}...')

                            # Parse getserversResponse, getserverswebResponse, or getserversExtResponse
                            if message_data.startswith(b'\xff\xff\xff\xffgetserverswebResponse'):
                                # JavaScript master server response: skip 24 bytes (4 byte header + 20 byte response string)
                                data = message_data[24:]
                                log(LOG_DEBUG, f'Puppet: getserverswebResponse header confirmed (JavaScript master server), parsing {len(data)} bytes')

                                # JavaScript master server format: \hostname:port\hostname:port\...\EOT
                                # Parse until \EOT marker
                                eot_index = data.find(b'EOT')
                                if eot_index != -1:
                                    data = data[:eot_index]

                                while True:
                                    # Check for end marker
                                    if len(data) == 0 or (data[0:1] == b'\\' and len(data) == 1):
                                        log(LOG_DEBUG, f'Puppet: End marker found, stopping receive loop')
                                        break

                                    # Find next separator
                                    sep_index = data.find(b'\\')
                                    if sep_index == -1:
                                        log(LOG_PRINT, f'Puppet: No separator found, stopping parse')
                                        break

                                    # Extract server entry
                                    server_entry = data[:sep_index]
                                    data = data[sep_index + 1:]

                                    # Parse hostname:port format
                                    if b':' in server_entry:
                                        parts = server_entry.split(b':')
                                        if len(parts) == 2:
                                            host = parts[0].decode('utf-8')
                                            try:
                                                port = int(parts[1])
                                                servers.append((host, port))
                                                log(LOG_DEBUG, f'Puppet: Parsed server {host}:{port} (hostname format)')
                                            except ValueError:
                                                log(LOG_PRINT, f'Puppet: Invalid port number: {parts[1]}')
                                        else:
                                            log(LOG_PRINT, f'Puppet: Invalid server entry format: {server_entry}')
                                    break
                            elif message_data.startswith(b'\xff\xff\xff\xffgetserversResponse'):
                                # Standard response: skip 22 bytes (4 byte header + 17 byte response string + 1 byte)
                                data = message_data[22:]
                                log(LOG_DEBUG, f'Puppet: Standard getserversResponse header confirmed, parsing {len(data)} bytes')

                                while True:
                                    # Check for end marker first (only if it's the ONLY byte remaining)
                                    if len(data) == 0 or (data[0:1] == b'\\' and len(data) == 1):
                                        log(LOG_DEBUG, f'Puppet: End marker found, stopping receive loop')
                                        break
                                    # Need at least 6 bytes for IPv4 address (1 separator + 4 IP + 2 port)
                                    if len(data) < 6:
                                        log(LOG_PRINT, f'Puppet: Not enough data for server address, stopping parse')
                                        break
                                    sep = data[0:1]
                                    if sep == b'\\':
                                        # IPv4
                                        host = socket.inet_ntop(socket.AF_INET, data[1:5])
                                        port = struct.unpack('!H', data[5:7])[0]
                                        data = data[7:]
                                    elif sep == b'/':
                                        # IPv6
                                        host = socket.inet_ntop(socket.AF_INET6, data[1:17])
                                        port = struct.unpack('!H', data[17:19])[0]
                                        data = data[19:]
                                    else:
                                        log(LOG_PRINT, f'Puppet: Unknown separator {sep!r}, stopping parse')
                                        break

                                    servers.append((host, port))
                                    log(LOG_DEBUG, f'Puppet: Parsed server {host}:{port} (family: {"IPv4" if sep == b"\\" else "IPv6"})')
                            elif message_data.startswith(b'\xff\xff\xff\xffgetserversExtResponse'):
                                # Extended response: skip 27 bytes (4 byte header + 22 byte response string + 1 byte)
                                data = message_data[27:]
                                log(LOG_DEBUG, f'Puppet: Extended getserversExtResponse header confirmed, parsing {len(data)} bytes')

                                # Skip extended header: \0<index>\0<total>\0<label>\0
                                parts = data.split(b'\0', 3)
                                if len(parts) >= 4:
                                    index = int(parts[0]) if parts[0] else 0
                                    total = int(parts[1]) if parts[1] else 0
                                    label = parts[2].decode('utf-8') if parts[2] else ''
                                    server_data = parts[3]
                                    log(LOG_DEBUG, f'Puppet: Extended packet {index} of {total}, label: {label}')

                                    # Parse servers from server_data
                                    while True:
                                        # Check for end marker first (only if it's the ONLY byte remaining)
                                        if len(server_data) == 0 or (server_data[0:1] == b'\\' and len(server_data) == 1):
                                            log(LOG_DEBUG, f'Puppet: End marker found, stopping receive loop')
                                            break
                                        # Need at least 6 bytes for IPv4 address (1 separator + 4 IP + 2 port)
                                        if len(server_data) < 6:
                                            log(LOG_PRINT, f'Puppet: Not enough data for server address, stopping parse')
                                            break
                                        sep = server_data[0:1]
                                        if sep == b'\\':
                                            # IPv4
                                            host = socket.inet_ntop(socket.AF_INET, server_data[1:5])
                                            port = struct.unpack('!H', server_data[5:7])[0]
                                            server_data = server_data[7:]
                                        elif sep == b'/':
                                            # IPv6
                                            host = socket.inet_ntop(socket.AF_INET6, server_data[1:17])
                                            port = struct.unpack('!H', server_data[17:19])[0]
                                            server_data = server_data[19:]
                                        else:
                                            log(LOG_PRINT, f'Puppet: Unknown separator {sep!r}, stopping parse')
                                            break

                                        servers.append((host, port))
                                        log(LOG_DEBUG, f'Puppet: Parsed server {host}:{port} (family: {"IPv4" if sep == b"\\" else "IPv6"})')
                            else:
                                log(LOG_PRINT, f'Puppet: Invalid getserversExt response format')
                    else:
                        log(LOG_PRINT, f'Puppet: Unexpected response format: {message_data[:30]!r}')

                    # Close WebSocket connection
                    close_data = ws.send(CloseConnection())
                    sock.sendall(close_data)
                    sock.close()
                    return servers

                except BlockingIOError:
                    sleep(0.1)
                    continue
                except socket.error as e:
                    log(LOG_ERROR, f'Puppet: WebSocket receive error: {e}')
                    return servers

            log(LOG_ERROR, f'Puppet: WebSocket timeout waiting for response')
            return servers

        except Exception as e:
            log(LOG_ERROR, f'Puppet plugin: Error fetching WebSocket servers: {e}')
            return servers

    def fetch_remote_servers(self) -> List[tuple]:
        """Fetch server list from all configured remote masters.

        Returns:
            List of (host, port) tuples from all masters

        If auto-detect is enabled (use_websocket is not explicitly set),
        tries both UDP and WebSocket in parallel and uses whichever responds first.
        Also populates self.master_connection_types with the master's connection type for each server.
        This ensures UDP clients only see servers from UDP masters, and WebSocket clients
        only see servers from WebSocket masters.
        """
        from config import log, LOG_DEBUG, LOG_ERROR, LOG_PRINT, LOG_VERBOSE
        from socket import timeout as socket_timeout
        from threading import Thread

        if not self.enabled or not self.remote_masters:
            return []

        all_servers = []
        auto_detect = not hasattr(self.config, 'puppet_use_websocket') or self.config.puppet_use_websocket is None

        # Query each master in the list
        for master, port, conn_protocol, game_protocol, request_type in self.remote_masters:
            game_proto_str = f' game={game_protocol}' if game_protocol else ''
            req_type_str = f' req={request_type}' if request_type else ''
            log(LOG_VERBOSE, f'Puppet: Querying master {master}:{port}{game_proto_str}{req_type_str}...')

            # Determine connection method from per-master protocol or global setting
            if conn_protocol == 'udp':
                # Explicitly use UDP
                protocol_str = f' (conn: udp{game_proto_str}{req_type_str})'
                log(LOG_DEBUG, f'Puppet: Using UDP to {master}:{port}{protocol_str}')
                servers = self._fetch_udp_servers(master, port, game_protocol, request_type)
                # Track master connection type for all servers from this master
                # UDP clients will only see these servers
                for server in servers:
                    self.master_connection_types[server] = 'udp'
                all_servers.extend(servers)
            elif conn_protocol == 'websocket':
                # Explicitly use WebSocket
                protocol_str = f' (conn: websocket{game_proto_str}{req_type_str})'
                log(LOG_DEBUG, f'Puppet: Using WebSocket to {master}:{port}{protocol_str}')
                servers = self._fetch_websocket_servers(master, port, game_protocol, request_type)
                # Track master connection type for all servers from this master
                # WebSocket clients will only see these servers
                for server in servers:
                    self.master_connection_types[server] = 'websocket'
                all_servers.extend(servers)
            elif conn_protocol == 'auto' or (conn_protocol is None and auto_detect):
                # Auto-detect: try UDP first, then WebSocket if UDP fails
                protocol_str = f' (conn: {conn_protocol}{game_proto_str}{req_type_str})' if conn_protocol else f' (default{game_proto_str}{req_type_str})'
                log(LOG_VERBOSE, f'Puppet: Auto-detecting protocol for {master}:{port}{protocol_str} (trying UDP first)...')

                # Try UDP first
                try:
                    udp_servers = self._fetch_udp_servers(master, port, game_protocol, request_type)
                    log(LOG_VERBOSE, f'Puppet: Using UDP response from {master}:{port} (got {len(udp_servers)} servers)')
                    # Track master connection type for all servers from this master
                    # UDP clients will only see these servers
                    for server in udp_servers:
                        self.master_connection_types[server] = 'udp'
                    all_servers.extend(udp_servers)
                except Exception as e:
                    log(LOG_DEBUG, f'Puppet: UDP fetch from {master}:{port} failed: {e}')
                    # If UDP fails, try WebSocket
                    if WS_AVAILABLE:
                        log(LOG_VERBOSE, f'Puppet: UDP failed, trying WebSocket for {master}:{port}...')
                        try:
                            ws_servers = self._fetch_websocket_servers(master, port, game_protocol, request_type)
                            log(LOG_VERBOSE, f'Puppet: Using WebSocket response from {master}:{port} (got {len(ws_servers)} servers)')
                            # Track master connection type for all servers from this master
                            # WebSocket clients will only see these servers
                            for server in ws_servers:
                                self.master_connection_types[server] = 'websocket'
                            all_servers.extend(ws_servers)
                        except Exception as e:
                            log(LOG_DEBUG, f'Puppet: WebSocket fetch from {master}:{port} failed: {e}')
                            log(LOG_VERBOSE, f'Puppet: Both UDP and WebSocket failed for {master}:{port}')
                    else:
                        log(LOG_VERBOSE, f'Puppet: UDP failed and WebSocket not available for {master}:{port}')
            elif conn_protocol is None and self.use_websocket and WS_AVAILABLE:
                # No per-master protocol specified, use global WebSocket setting
                log(LOG_DEBUG, f'Puppet: Using WebSocket to {master}:{port} (global setting{game_proto_str}{req_type_str})')
                servers = self._fetch_websocket_servers(master, port, game_protocol, request_type)
                # Track master connection type for all servers from this master
                # WebSocket clients will only see these servers
                for server in servers:
                    self.master_connection_types[server] = 'websocket'
                all_servers.extend(servers)
            elif conn_protocol is None:
                # No per-master protocol specified, use UDP (default)
                log(LOG_DEBUG, f'Puppet: Using UDP to {master}:{port} (default{game_proto_str}{req_type_str})')
                servers = self._fetch_udp_servers(master, port, game_protocol, request_type)
                # Track master connection type for all servers from this master
                # UDP clients will only see these servers
                for server in servers:
                    self.master_connection_types[server] = 'udp'
                all_servers.extend(servers)

        # Remove duplicates while preserving order
        seen = set()
        unique_servers = []
        for server in all_servers:
            if server not in seen:
                seen.add(server)
                unique_servers.append(server)

        log(LOG_VERBOSE, f'Puppet: Total unique servers from all masters: {len(unique_servers)}')
        return unique_servers

    def _add_pre_fetched_servers(self) -> None:
        """Add pre-fetched servers to server list and send challenges.

        This is called after socket binding to add servers that were
        fetched during pre-initialization.
        """
        from config import log, LOG_VERBOSE, LOG_DEBUG, LOG_ERROR

        if not self.enabled or not self.pre_fetched_servers:
            return

        log(LOG_VERBOSE, f'Puppet: Adding {len(self.pre_fetched_servers)} pre-fetched servers...')

        # Track current sync server set from pre-fetched servers to identify servers to remove later
        current_sync_servers = set(self.pre_fetched_servers)
        log(LOG_DEBUG, f'Puppet: Pre-fetched sync server set: {len(current_sync_servers)} servers')

        # Get appropriate socket for sending challenges
        addr_family = socket.AF_INET
        challenge_sock = None
        for family, sock in self.outSocks.items():
            if family == addr_family:
                challenge_sock = sock
                break

        if not challenge_sock:
            log(LOG_ERROR, f'Puppet: No suitable socket found for sending challenges')
            return

        # Import Addr and Server classes dynamically to avoid circular import
        # Use sys.modules to get already-imported module to avoid re-executing module-level code
        import sys
        # The master module should already be imported by the time this code runs
        # (master.py module-level code runs when master.py is imported)
        # Just use the already-loaded module directly
        # Note: When run as 'python3 master.py', the module is '__main__', not 'master'
        if 'master' in sys.modules:
            master_module = sys.modules['master']
        elif '__main__' in sys.modules:
            master_module = sys.modules['__main__']
        else:
            # This should not happen - log an error
            from config import log, LOG_ERROR
            log(LOG_ERROR, 'Puppet plugin: master module not loaded - cannot import Addr and Server classes')
            master_module = None

        # Check if puppet label exists (to prevent infinite loops)
        puppet_label = 'puppet'
        existing_puppet_servers = set()
        if puppet_label in self.servers:
            existing_puppet_servers = set(self.servers[puppet_label].keys())
            log(LOG_DEBUG, f'Puppet: Found {len(existing_puppet_servers)} existing servers in puppet label')

        added_count = 0
        skipped_cloned = 0
        skipped_puppet = 0
        skipped_master = 0
        removed_count = 0  # Track servers removed from puppet label

        for host, port in self.pre_fetched_servers:
            try:
                addr = master_module.Addr((host, port))

                # SAFEGUARD 1: Skip if already in our cloned set
                if addr in self.cloned_servers:
                    skipped_cloned += 1
                    log(LOG_DEBUG, f'Puppet: SAFEGUARD 1 - Skipping already cloned server {addr}')
                    continue

                # SAFEGUARD 2: Skip if already exists in puppet label
                if addr in existing_puppet_servers:
                    skipped_puppet += 1
                    log(LOG_DEBUG, f'Puppet: SAFEGUARD 2 - Skipping server already in puppet label {addr}')
                    continue

                # SAFEGUARD 3: Skip if server is from one of our remote masters
                if host in [m for m, _, _, _, _ in self.remote_masters]:
                    skipped_master += 1
                    log(LOG_DEBUG, f'Puppet: SAFEGUARD 3 - Skipping server from remote master itself {addr}')
                    continue

                # Add to servers dict if not already present
                if puppet_label not in self.servers:
                    self.servers[puppet_label] = {}

                # Get master connection type for this server (from which remote master it came)
                conn_type = self.master_connection_types.get((host, port), 'udp')

                # Create a new server instance with connection type and send challenge
                server = master_module.Server(addr, conn_type)
                server.send_challenge(challenge_sock)
                self.servers[puppet_label][addr] = server
                self.cloned_servers.add(addr)
                added_count += 1
                log(LOG_DEBUG, f'Puppet: Added server {addr} to puppet label (from {conn_type} master), sending challenge')

            except Exception as e:
                log(LOG_DEBUG, f'Puppet: Error adding server {host}:{port}: {e}')

        # Remove servers that are no longer in the pre-fetched server list
        # These are servers that were previously cloned but are no longer present
        servers_to_remove = self.cloned_servers - current_sync_servers
        if servers_to_remove:
            log(LOG_VERBOSE, f'Puppet: Removing {len(servers_to_remove)} servers that are no longer in pre-fetched list')
            for addr in servers_to_remove:
                if addr in self.servers.get(puppet_label, {}):
                    del self.servers[puppet_label][addr]
                    removed_count += 1
                    log(LOG_DEBUG, f'Puppet: Removed server {addr} from puppet label (no longer in pre-fetched list)')

        log(LOG_VERBOSE, f'Puppet: Pre-fetched servers added - added: {added_count}, removed: {removed_count}, '
                        f'skipped (cloned): {skipped_cloned}, skipped (puppet): {skipped_puppet}, '
                        f'skipped (master): {skipped_master}')

    def sync_servers(self) -> None:
        """Sync servers from remote master to local server list."""
        from config import log, LOG_VERBOSE, LOG_DEBUG, LOG_ERROR

        if not self.enabled:
            return

        current_time = time()
        if current_time - self.last_sync < self.sync_interval:
            time_until_sync = self.sync_interval - (current_time - self.last_sync)
            log(LOG_DEBUG, f'Puppet: Sync skipped, {time_until_sync:.1f}s until next sync')
            return

        self.last_sync = current_time

        log(LOG_VERBOSE, f'Puppet: Syncing servers from remote master...')
        log(LOG_DEBUG, f'Puppet: Current puppet label servers: {len(self.servers.get("puppet", {}))}')
        log(LOG_DEBUG, f'Puppet: Cloned servers set size: {len(self.cloned_servers)}')

        # Get appropriate socket for sending challenges
        # Use existing outSocks from master server instead of creating new socket
        # The local master already has UDP sockets bound for challenges
        log(LOG_DEBUG, f'Puppet: Using existing outSocks for {len(self.remote_masters)} remote masters')

        # Get appropriate socket based on address family
        addr_family = socket.AF_INET
        for family, sock in self.outSocks.items():
            if family == addr_family:
                challenge_sock = sock
                break

        if not challenge_sock:
            log(LOG_ERROR, f'Puppet: No suitable socket found for {self.remote_masters} (family {addr_family})')
            return []

        remote_servers = self.fetch_remote_servers()

        if not remote_servers:
            log(LOG_DEBUG, 'Puppet: No servers received from remote master')
        else:
            log(LOG_DEBUG, f'Puppet: Fetched {len(remote_servers)} servers from remote master')

        # Import Addr and Server classes dynamically to avoid circular import
        # Use sys.modules to get already-imported module to avoid re-executing module-level code
        import sys
        # The master module should already be imported by the time this code runs
        # (master.py module-level code runs when master.py is imported)
        # Just use the already-loaded module directly
        # Note: When run as 'python3 master.py', module is '__main__', not 'master'
        if 'master' in sys.modules:
            master_module = sys.modules['master']
        elif '__main__' in sys.modules:
            master_module = sys.modules['__main__']
        else:
            # This should not happen - log an error
            from config import log, LOG_ERROR
            log(LOG_ERROR, 'Puppet plugin: master module not loaded - cannot import Addr and Server classes')
            master_module = None

        # Check if puppet label exists (to prevent infinite loops)
        puppet_label = 'puppet'
        existing_puppet_servers = set()
        if puppet_label in self.servers:
            # Get all addresses currently in puppet label
            existing_puppet_servers = set(self.servers[puppet_label].keys())
            log(LOG_DEBUG, f'Puppet: Found {len(existing_puppet_servers)} existing servers in puppet label')
    
            # Track current server set from this sync to identify servers to remove later
            current_sync_servers = set(remote_servers)
            log(LOG_DEBUG, f'Puppet: Current sync server set: {len(current_sync_servers)} servers')
    
            processed_count = 0
            skipped_cloned = 0
            skipped_puppet = 0
            skipped_master = 0
            added_count = 0
            removed_count = 0  # Track servers removed from puppet label

        for host, port in remote_servers:
            processed_count += 1
            try:
                addr = master_module.Addr((host, port))

                # SAFEGUARD 1: Skip if already in our cloned set
                if addr in self.cloned_servers:
                    skipped_cloned += 1
                    log(LOG_DEBUG, f'Puppet: SAFEGUARD 1 - Skipping already cloned server {addr}')
                    continue

                # SAFEGUARD 2: Skip if already exists in puppet label
                # This prevents two master servers with puppet from cloning each other
                if addr in existing_puppet_servers:
                    skipped_puppet += 1
                    log(LOG_DEBUG, f'Puppet: SAFEGUARD 2 - Skipping server already in puppet label {addr}')
                    continue

                # SAFEGUARD 3: Skip if server is from one of our remote masters
                # Prevent cloning servers that are actually ours
                if host in [m for m, _, _, _, _ in self.remote_masters]:
                    skipped_master += 1
                    log(LOG_DEBUG, f'Puppet: SAFEGUARD 3 - Skipping server from remote master itself {addr}')
                    continue

                # Add to servers dict if not already present
                if puppet_label not in self.servers:
                    self.servers[puppet_label] = {}

                # Get master connection type for this server (from which remote master it came)
                conn_type = self.master_connection_types.get((host, port), 'udp')

                # Create a new server instance with connection type and send challenge
                server = master_module.Server(addr, conn_type)
                server.send_challenge(challenge_sock)
                self.servers[puppet_label][addr] = server
                self.cloned_servers.add(addr)
                added_count += 1
                log(LOG_DEBUG, f'Puppet: Added server {addr} to puppet label (from {conn_type} master), sending challenge')

            except Exception as e:
                log(LOG_DEBUG, f'Puppet: Error adding server {host}:{port}: {e}')

        # Remove servers that are no longer in the remote master's response
        # These are servers that were previously cloned but are no longer present
        servers_to_remove = self.cloned_servers - current_sync_servers
        if servers_to_remove:
            log(LOG_VERBOSE, f'Puppet: Removing {len(servers_to_remove)} servers that are no longer in remote master response')
            for addr in servers_to_remove:
                if addr in self.servers.get(puppet_label, {}):
                    del self.servers[puppet_label][addr]
                    removed_count += 1
                    log(LOG_DEBUG, f'Puppet: Removed server {addr} from puppet label (no longer in remote master)')

        log(LOG_VERBOSE, f'Puppet: Sync complete - processed: {processed_count}, added: {added_count}, removed: {removed_count}, '
                        f'skipped (cloned): {skipped_cloned}, skipped (puppet): {skipped_puppet}, '
                        f'skipped (master): {skipped_master}')

        # Count verified servers
        verified_count = len([s for s in self.servers.get(puppet_label, {}).values() if s])
        log(LOG_VERBOSE, f'Puppet: Puppet label now has {verified_count} verified servers')

    def on_heartbeat(self, addr: tuple, data: bytes) -> Optional[bool]:
        """Hook into heartbeat processing to trigger periodic sync."""
        from config import log, LOG_DEBUG
        log(LOG_DEBUG, f'Puppet: on_heartbeat hook triggered by {addr}')
        # Sync is handled by background thread, no need to trigger here
        return None

    def on_getservers(self, sock, addr: tuple, data: bytes) -> Optional[bool]:
        """Hook into getservers processing to ensure synced servers are available."""
        from config import log, LOG_DEBUG
        log(LOG_DEBUG, f'Puppet: on_getservers hook triggered by {addr}')
        # Sync is handled by background thread, no need to trigger here
        return None

    def cleanup(self) -> None:
        """Cleanup when plugin is unloaded."""
        from config import log, LOG_VERBOSE, LOG_DEBUG, LOG_PRINT

        log(LOG_VERBOSE, 'Puppet plugin: Cleanup starting...')

        # Stop sync thread
        self.enabled = False
        self.sync_stop_event.set()

        if self.sync_thread and self.sync_thread.is_alive():
            log(LOG_DEBUG, 'Puppet plugin: Waiting for sync thread to stop...')
            self.sync_thread.join(timeout=5)
            if self.sync_thread.is_alive():
                log(LOG_PRINT, 'Puppet plugin: Sync thread did not stop gracefully')
            else:
                log(LOG_DEBUG, 'Puppet plugin: Sync thread stopped')
        else:
            log(LOG_DEBUG, 'Puppet plugin: No sync thread running')

        log(LOG_VERBOSE, 'Puppet plugin: Cleanup complete')
