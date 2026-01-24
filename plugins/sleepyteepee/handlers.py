"""
REST API Endpoint Handlers for Sleepyteepee Plugin.

This module provides handler functions for all REST API endpoints of the
Sleepyteepee plugin. Handlers are designed to be framework-agnostic and
can be used with various HTTP transport implementations (Flask, FastAPI, etc.).
"""
import json
import time
from typing import Any, Dict, Optional, Tuple, List
from socket import AF_INET, AF_INET6
import os

from .auth import APIKeyAuth


class HandlerResponse:
    """Standard response wrapper for API handlers.

    This class provides a consistent response format that can be adapted
    to different HTTP frameworks.
    """

    def __init__(self, status_code: int, data: Dict[str, Any]):
        """Initialize a handler response.

        Args:
            status_code: HTTP status code
            data: Response data (will be JSON serialized)
        """
        self.status_code = status_code
        self.data = data

    def to_tuple(self) -> Tuple[int, Dict[str, Any]]:
        """Convert to a tuple for framework compatibility.

        Returns:
            Tuple of (status_code, data)
        """
        return (self.status_code, self.data)


class HandlerContext:
    """Context object passed to handler functions.

    This contains all the resources a handler might need to process a request.
    """

    def __init__(
        self,
        config: Any,
        servers: Dict,
        outSocks: Dict,
        auth: APIKeyAuth,
        plugin_instance: Any
    ):
        """Initialize handler context.

        Args:
            config: The master server configuration object
            servers: The servers dictionary (dict of [label][addr] -> Server)
            outSocks: Dictionary of output sockets keyed by address family
            auth: API key authentication helper
            plugin_instance: The plugin instance for accessing plugin-specific data
        """
        self.config = config
        self.servers = servers
        self.outSocks = outSocks
        self.auth = auth
        self.plugin = plugin_instance

        # In-memory log storage for /api/logs endpoint
        # This will be populated by the plugin
        self.log_entries: List[Dict[str, Any]] = []


# ============================================================================
# Unauthenticated Endpoints
# ============================================================================

def handle_root(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext,
    client_ip: str = 'unknown',
    method: str = 'GET',
    path: str = '/'
) -> HandlerResponse:
    """Handle GET / - Get list of all registered servers.

    This is a public endpoint that returns information about all registered
    game servers without requiring authentication.

    Args:
        headers: HTTP headers
        body: Request body (not used)
        query_params: Query parameters
        ctx: Handler context with server registry
        client_ip: Client IP address
        method: HTTP method
        path: Request path

    Returns:
        HandlerResponse with status code and JSON list of servers
    """
    servers_list = []

    for label, servers_dict in ctx.servers.items():
        label_name = label if label else 'default'
        for addr, server in servers_dict.items():
            # Extract server information
            server_info = {
                'address': str(addr),
                'label': label_name,
                'verified': bool(server),
                'connection_type': getattr(server, 'connection_type', 'udp'),
                'family': 'IPv4' if addr.family == AF_INET else 'IPv6'
            }

            # SECURITY FIX: Do not expose sensitive challenge data in public API response
            # Challenge strings should not be publicly exposed as they could be used for replay attacks

            servers_list.append(server_info)

    return HandlerResponse(200, {
        'servers': servers_list,
        'count': len(servers_list)
    })


def handle_heartbeat(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext,
    client_ip: str = 'unknown',
    method: str = 'POST',
    path: str = '/heartbeat'
) -> HandlerResponse:
    """Handle POST /heartbeat - JSON heartbeat from tremded servers.

    This endpoint allows game servers to send heartbeats via JSON instead of
    traditional UDP protocol. The heartbeat data should include server
    information such as address, protocol, and game state.

    Args:
        headers: HTTP headers
        body: Request body as parsed JSON
        query_params: Query parameters
        ctx: Handler context with config and server registry
        client_ip: Client IP address
        method: HTTP method
        path: Request path

    Returns:
        HandlerResponse with status code and data
    """
    from config import log, LOG_ERROR, LOG_VERBOSE, LOG_DEBUG
    from utils import stringtosockaddr, valid_addr

    # Validate request body
    if not body:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Request body is required'
        })

    # Extract required fields
    address = body.get('address')
    protocol = body.get('protocol')

    if not address:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Missing required field: address'
        })

    if not protocol:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Missing required field: protocol'
        })

    # Parse address
    try:
        addr = stringtosockaddr(address)
    except Exception as e:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': f'Invalid address format: {e}'
        })

    # Import master functions
    import master

    # Check if this is a flatline
    if body.get('dead', False):
        label = master.find_featured(addr)
        if label is None:
            if addr in list(ctx.servers[None].keys()):
                log(LOG_VERBOSE, f'<< {addr}: flatline via REST API')
                del ctx.servers[None][addr]
                return HandlerResponse(200, {
                    'status': 'success',
                    'message': 'Server removed from registry'
                })
            else:
                return HandlerResponse(404, {
                    'error': 'Not Found',
                    'message': 'Server not found in registry'
                })
        else:
            # Featured servers cannot be flatlined
            return HandlerResponse(403, {
                'error': 'Forbidden',
                'message': 'Featured servers cannot be removed via heartbeat'
            })

    # Check max servers limit
    if hasattr(ctx.config, 'max_servers') and ctx.config.max_servers >= 0:
        total_servers = sum(len(s) for s in ctx.servers.values())
        if total_servers >= ctx.config.max_servers:
            return HandlerResponse(503, {
                'error': 'Service Unavailable',
                'message': 'Maximum server count reached'
            })

    # Find or create server record
    label = master.find_featured(addr)
    if addr in list(ctx.servers[label].keys()):
        server = ctx.servers[label][addr]
    else:
        server = master.Server(addr)

    # Send challenge to verify server
    server.send_challenge()
    ctx.servers[label][addr] = server

    log(LOG_VERBOSE, f'<< {addr}: heartbeat via REST API')

    return HandlerResponse(200, {
        'status': 'success',
        'message': 'Heartbeat received, challenge sent',
        'challenge': server.challenge
    })


def handle_get_info(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext,
    client_ip: str = 'unknown',
    method: str = 'GET',
    path: str = '/api/info'
) -> HandlerResponse:
    """Handle GET /api/info - Get master server information.

    This is a public endpoint that returns information about the master server
    including version, configuration, and status without requiring authentication.

    Args:
        headers: HTTP headers
        body: Request body (not used)
        query_params: Query parameters
        ctx: Handler context with server registry and config
        client_ip: Client IP address
        method: HTTP method
        path: Request path

    Returns:
        HandlerResponse with status code and server information
    """
    # Count servers
    total_servers = sum(len(s) for s in ctx.servers.values())
    verified_servers = sum(1 for s_dict in ctx.servers.values() for s in s_dict.values() if bool(s))

    # Get configuration info
    info = {
        'name': 'Tremulous Master Server',
        'version': '1.0.1',
        'description': 'Tremulous Master Server with WebSocket support',
        'status': 'online',
        'servers': {
            'total': total_servers,
            'verified': verified_servers,
        },
        'configuration': {
            'listen_addr': getattr(ctx.config, 'listen_addr', '0.0.0.0'),
            'ports': getattr(ctx.config, 'ports', []),
            'challenge_port': getattr(ctx.config, 'challengeport', 30710),
            'websocket_enabled': getattr(ctx.config, 'use_ws', False),
            'websocket_ports': getattr(ctx.config, 'ws_ports', []),
            'ipv4_enabled': getattr(ctx.config, 'ipv4', True),
            'ipv6_enabled': getattr(ctx.config, 'ipv6', False),
            'max_servers': getattr(ctx.config, 'max_servers', -1),
        },
        'featured_groups': len(ctx.config.featured_servers),
        'endpoints': {
            'GET /': 'List all registered servers',
            'GET /api/servers': 'List all registered servers (alias for /)',
            'GET /api/info': 'Get master server information',
            'GET /api/motd': 'Get message of the day',
            'GET /api/stats': 'Get server statistics (requires auth)',
            'GET /api/servers/rss': 'Get RSS feed of servers',
            'GET /api/blacklist': 'Get blacklist entries (requires auth)',
            'POST /api/blacklist': 'Add blacklist entry (requires auth)',
            'DELETE /api/blacklist/{id}': 'Delete blacklist entry (requires auth)',
            'GET /api/featured': 'Get featured server groups (requires auth)',
            'PUT /api/featured': 'Update featured servers (requires auth)',
            'PUT /api/motd': 'Update message of the day (requires auth)',
            'GET /api/logs': 'Get recent log entries (requires auth)',
            'POST /api/admin/reload-config': 'Reload server configuration (requires auth)',
            'GET /api/plugins': 'List all plugins (requires auth)',
        }
    }

    return HandlerResponse(200, info)


# ============================================================================
# Authenticated Endpoints
# ============================================================================

def _require_auth(
    headers: Dict[str, str],
    ctx: HandlerContext,
    client_ip: str,
    method: str,
    path: str
) -> Tuple[bool, Optional[HandlerResponse]]:
    """Helper function to check authentication.

    Args:
        headers: HTTP headers
        ctx: Handler context
        client_ip: Client IP address
        method: HTTP method
        path: Request path

    Returns:
        Tuple of (is_authenticated, error_response)
        - is_authenticated: True if authenticated
        - error_response: HandlerResponse with error if not authenticated
    """
    is_auth, error_data = ctx.auth.require_auth(headers)
    if not is_auth:
        return False, HandlerResponse(401, error_data)
    
    # Log successful admin API access
    from config import log, LOG_PRINT
    log(LOG_PRINT, f'WARNING: Admin API access: {method} {path} from {client_ip}')
    
    return True, None


def handle_get_blacklist(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext,
    client_ip: str = 'unknown',
    method: str = 'GET',
    path: str = '/api/blacklist'
) -> HandlerResponse:
    """Handle GET /api/blacklist - Get all blacklist entries.

    Args:
        headers: HTTP headers
        body: Request body (not used)
        query_params: Query parameters
        ctx: Handler context
        client_ip: Client IP address
        method: HTTP method
        path: Request path

    Returns:
        HandlerResponse with status code and data
    """
    # Check authentication
    is_auth, error_response = _require_auth(headers, ctx, client_ip, method, path)
    if not is_auth:
        return error_response

    # Read blacklist entries from ignore.txt
    entries = []
    try:
        with open(ctx.config.IGNORE_FILE) as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                entries.append({
                    'id': line_num,
                    'entry': line
                })
    except FileNotFoundError:
        entries = []
    except Exception as e:
        from config import log, LOG_ERROR
        log(LOG_ERROR, f'Error reading blacklist: {e}')
        return HandlerResponse(500, {
            'error': 'Internal Server Error',
            'message': 'Failed to read blacklist'
        })

    return HandlerResponse(200, {
        'entries': entries,
        'count': len(entries)
    })


def handle_add_blacklist(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext,
    client_ip: str = 'unknown',
    method: str = 'POST',
    path: str = '/api/blacklist'
) -> HandlerResponse:
    """Handle POST /api/blacklist - Add blacklist entry.

    Args:
        headers: HTTP headers
        body: Request body with 'entry' field
        query_params: Query parameters
        ctx: Handler context
        client_ip: Client IP address
        method: HTTP method
        path: Request path

    Returns:
        HandlerResponse with status code and data
    """
    # Check authentication
    is_auth, error_response = _require_auth(headers, ctx, client_ip, method, path)
    if not is_auth:
        return error_response

    # Validate request body
    if not body:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Request body is required'
        })

    entry = body.get('entry')
    if not entry:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Missing required field: entry'
        })

    # Validate entry format (IP or CIDR)
    from utils import valid_addr
    try:
        if '/' in entry:
            addr, mask = entry.split('/', 1)
            int(mask)  # Validate mask is integer
            valid_addr(addr)
        else:
            valid_addr(entry)
    except Exception:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Invalid entry format. Use IP address or CIDR notation.'
        })

    # Append to blacklist file
    try:
        with open(ctx.config.IGNORE_FILE, 'a') as f:
            f.write(entry + '\n')
    except Exception as e:
        from config import log, LOG_ERROR
        log(LOG_ERROR, f'Error adding to blacklist: {e}')
        return HandlerResponse(500, {
            'error': 'Internal Server Error',
            'message': 'Failed to add blacklist entry'
        })

    return HandlerResponse(201, {
        'status': 'success',
        'message': 'Blacklist entry added',
        'entry': entry
    })


def handle_delete_blacklist(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext,
    client_ip: str = 'unknown',
    method: str = 'DELETE',
    path: str = '/api/blacklist'
) -> HandlerResponse:
    """Handle DELETE /api/blacklist/{id} - Remove blacklist entry.

    Args:
        headers: HTTP headers
        body: Request body (not used)
        query_params: Query parameters with 'id' field
        ctx: Handler context
        client_ip: Client IP address
        method: HTTP method
        path: Request path

    Returns:
        HandlerResponse with status code and data
    """
    # Check authentication
    is_auth, error_response = _require_auth(headers, ctx, client_ip, method, path)
    if not is_auth:
        return error_response

    # Get entry ID from query params or path
    entry_id = query_params.get('id')
    if not entry_id:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Missing required parameter: id'
        })

    try:
        entry_id = int(entry_id)
    except ValueError:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Invalid id parameter: must be an integer'
        })

    # SECURITY FIX: Use file locking to prevent race conditions
    # Read all entries, remove the specified one, write back
    try:
        try:
            import fcntl
            with open(ctx.config.IGNORE_FILE, 'r') as f:
                fcntl.flock(f, fcntl.LOCK_SH)  # Shared lock for reading
                lines = f.readlines()
        except ImportError:
            # Windows or other systems without fcntl
            with open(ctx.config.IGNORE_FILE, 'r') as f:
                lines = f.readlines()

        # SECURITY FIX: Validate that entry_id is positive
        if entry_id < 1:
            return HandlerResponse(404, {
                'error': 'Bad Request',
                'message': 'Blacklist entry ID must be a positive integer'
            })

        if entry_id > len(lines):
            return HandlerResponse(404, {
                'error': 'Not Found',
                'message': f'Blacklist entry {entry_id} not found'
            })

        removed_entry = lines[entry_id - 1].strip()
        lines.pop(entry_id - 1)

        # SECURITY FIX: Use atomic write with temporary file
        try:
            import fcntl
            temp_file = ctx.config.IGNORE_FILE + '.tmp'
            with open(temp_file, 'w') as f:
                fcntl.flock(f, fcntl.LOCK_EX)  # Exclusive lock for writing
                f.writelines(lines)
            import os
            os.rename(temp_file, ctx.config.IGNORE_FILE)
        except ImportError:
            # Windows or other systems without fcntl
            import os
            temp_file = ctx.config.IGNORE_FILE + '.tmp'
            with open(temp_file, 'w') as f:
                f.writelines(lines)
            os.replace(temp_file, ctx.config.IGNORE_FILE)

        return HandlerResponse(200, {
            'status': 'success',
            'message': 'Blacklist entry removed',
            'entry': removed_entry
        })
    except FileNotFoundError:
        return HandlerResponse(404, {
            'error': 'Not Found',
            'message': 'Blacklist file not found'
        })
    except Exception as e:
        from config import log, LOG_ERROR
        log(LOG_ERROR, f'Error deleting blacklist entry: {e}')
        return HandlerResponse(500, {
            'error': 'Internal Server Error',
            'message': 'Failed to delete blacklist entry'
        })


def handle_get_featured(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext,
    client_ip: str = 'unknown',
    method: str = 'GET',
    path: str = '/api/featured'
) -> HandlerResponse:
    """Handle GET /api/featured - Get featured server groups.

    Args:
        headers: HTTP headers
        body: Request body (not used)
        query_params: Query parameters
        ctx: Handler context
        client_ip: Client IP address
        method: HTTP method
        path: Request path

    Returns:
        HandlerResponse with status code and data
    """
    # Check authentication
    is_auth, error_response = _require_auth(headers, ctx, client_ip, method, path)
    if not is_auth:
        return error_response

    # Get featured servers from config
    featured = {}
    for label, servers_dict in ctx.config.featured_servers.items():
        featured[label] = [str(addr) for addr in servers_dict.keys()]

    return HandlerResponse(200, {
        'featured_servers': featured
    })


def handle_put_featured(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext,
    client_ip: str = 'unknown',
    method: str = 'PUT',
    path: str = '/api/featured'
) -> HandlerResponse:
    """Handle PUT /api/featured - Add/modify featured servers.

    Args:
        headers: HTTP headers
        body: Request body with 'label' and 'servers' fields
        query_params: Query parameters
        ctx: Handler context
        client_ip: Client IP address
        method: HTTP method
        path: Request path

    Returns:
        HandlerResponse with status code and data
    """
    # Check authentication
    is_auth, error_response = _require_auth(headers, ctx, client_ip, method, path)
    if not is_auth:
        return error_response

    # Validate request body
    if not body:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Request body is required'
        })

    label = body.get('label')
    servers = body.get('servers')

    if not label:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Missing required field: label'
        })

    if not isinstance(servers, list):
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Field "servers" must be an array'
        })

    # SECURITY FIX: Comprehensive label validation
    # Check for slashes (path traversal prevention)
    if '\\' in label or '/' in label:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Label cannot contain backslashes or forward slashes'
        })
    # Check for null bytes
    if '\x00' in label:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Label cannot contain null bytes'
        })
    # Check length (prevent excessively long labels)
    if len(label) > 255:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Label cannot exceed 255 characters'
        })
    # Check for valid characters (allowlist approach)
    import re
    if not re.match(r'^[a-zA-Z0-9_\-]+$', label):
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Label can only contain alphanumeric characters, hyphens, and underscores'
        })

    # Validate server addresses
    from utils import stringtosockaddr
    valid_servers = []
    for addr_str in servers:
        try:
            addr = stringtosockaddr(addr_str)
            valid_servers.append(str(addr))
        except Exception as e:
            return HandlerResponse(400, {
                'error': 'Bad Request',
                'message': f'Invalid server address "{addr_str}": {e}'
            })

    # Update featured servers in config
    ctx.config.featured_servers[label] = {}

    # SECURITY FIX: Remove duplicate file write - write once with all data
    # Rebuild the featured file
    try:
        # First, update the featured servers in config with new servers
        ctx.config.featured_servers[label] = {
            stringtosockaddr(addr): None for addr in valid_servers
        }

        # SECURITY FIX: Use atomic write with temporary file
        try:
            import fcntl
            temp_file = ctx.config.FEATURED_FILE + '.tmp'
            with open(temp_file, 'w') as f:
                fcntl.flock(f, fcntl.LOCK_EX)  # Exclusive lock for writing
                for feat_label, feat_servers in ctx.config.featured_servers.items():
                    f.write(feat_label + '\n')
                    for addr in feat_servers.keys():
                        f.write('  ' + str(addr) + '\n')
            import os
            os.rename(temp_file, ctx.config.FEATURED_FILE)
        except ImportError:
            # Windows or other systems without fcntl
            import os
            temp_file = ctx.config.FEATURED_FILE + '.tmp'
            with open(temp_file, 'w') as f:
                for feat_label, feat_servers in ctx.config.featured_servers.items():
                    f.write(feat_label + '\n')
                    for addr in feat_servers.keys():
                        f.write('  ' + str(addr) + '\n')
            os.replace(temp_file, ctx.config.FEATURED_FILE)

        return HandlerResponse(200, {
            'status': 'success',
            'message': f'Featured servers updated for label: {label}',
            'label': label,
            'servers': valid_servers
        })
    except Exception as e:
        from config import log, LOG_ERROR
        log(LOG_ERROR, f'Error updating featured servers: {e}')
        return HandlerResponse(500, {
            'error': 'Internal Server Error',
            'message': 'Failed to update featured servers'
        })


def handle_get_motd(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext,
    client_ip: str = 'unknown',
    method: str = 'GET',
    path: str = '/api/motd'
) -> HandlerResponse:
    """Handle GET /api/motd - Get current MOTD.

    This is a public endpoint that returns current MOTD without requiring
    authentication.

    Args:
        headers: HTTP headers
        body: Request body (not used)
        query_params: Query parameters
        ctx: Handler context
        client_ip: Client IP address
        method: HTTP method
        path: Request path

    Returns:
        HandlerResponse with status code and data
    """
    motd = ctx.config.getmotd()

    return HandlerResponse(200, {
        'motd': motd if motd else ''
    })


def handle_put_motd(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext,
    client_ip: str = 'unknown',
    method: str = 'PUT',
    path: str = '/api/motd'
) -> HandlerResponse:
    """Handle PUT /api/motd - Update MOTD.

    Args:
        headers: HTTP headers
        body: Request body with 'motd' field
        query_params: Query parameters
        ctx: Handler context
        client_ip: Client IP address
        method: HTTP method
        path: Request path

    Returns:
        HandlerResponse with status code and data
    """
    # Check authentication
    is_auth, error_response = _require_auth(headers, ctx, client_ip, method, path)
    if not is_auth:
        return error_response

    # Validate request body
    if not body:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Request body is required'
        })

    motd = body.get('motd')
    if motd is None:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Missing required field: motd'
        })

    # Write MOTD to file
    try:
        with open(ctx.config.MOTD_FILE, 'w') as f:
            f.write(motd + '\n')
    except Exception as e:
        from config import log, LOG_ERROR
        log(LOG_ERROR, f'Error updating MOTD: {e}')
        return HandlerResponse(500, {
            'error': 'Internal Server Error',
            'message': 'Failed to update MOTD'
        })

    return HandlerResponse(200, {
        'status': 'success',
        'message': 'MOTD updated'
    })


def handle_get_logs(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext,
    client_ip: str = 'unknown',
    method: str = 'GET',
    path: str = '/api/logs'
) -> HandlerResponse:
    """Handle GET /api/logs - Get recent log entries.

    Args:
        headers: HTTP headers
        body: Request body (not used)
        query_params: Query parameters (limit, level)
        ctx: Handler context
        client_ip: Client IP address
        method: HTTP method
        path: Request path

    Returns:
        HandlerResponse with status code and data
    """
    # Check authentication
    is_auth, error_response = _require_auth(headers, ctx, client_ip, method, path)
    if not is_auth:
        return error_response

    # Parse query parameters
    limit = query_params.get('limit', 100)
    level = query_params.get('level')

    # SECURITY FIX: Validate log level parameter against allowlist
    if level:
        valid_levels = ['ALWAYS', 'ERROR', 'PRINT', 'VERBOSE', 'DEBUG']
        if level not in valid_levels:
            return HandlerResponse(400, {
                'error': 'Bad Request',
                'message': f'Invalid log level. Must be one of: {", ".join(valid_levels)}'
            })

    try:
        limit = int(limit)
        if limit < 1 or limit > 1000:
            return HandlerResponse(400, {
                'error': 'Bad Request',
                'message': 'Limit must be between 1 and 1000'
            })
    except ValueError:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Invalid limit parameter'
        })

    # Get log entries from context
    entries = ctx.log_entries

    # Filter by level if specified
    if level:
        entries = [e for e in entries if e.get('level') == level]

    # Limit results
    entries = entries[-limit:]

    return HandlerResponse(200, {
        'entries': entries,
        'count': len(entries)
    })


# Disabled shutdown endpoint for security
# def handle_admin_shutdown(
#     headers: Dict[str, str],
#     body: Optional[Dict[str, Any]],
#     query_params: Dict[str, Any],
#     ctx: HandlerContext,
#     client_ip: str = 'unknown',
#     method: str = 'POST',
#     path: str = '/api/admin/shutdown'
# ) -> HandlerResponse:
    """Handle POST /api/admin/shutdown - Emergency shutdown.

    Args:
        headers: HTTP headers
        body: Request body (not used)
        query_params: Query parameters
        ctx: Handler context
        client_ip: Client IP address
        method: HTTP method
        path: Request path

    Returns:
        HandlerResponse with status code and data
    """
    # Check authentication
    is_auth, error_response = _require_auth(headers, ctx, client_ip, method, path)
    if not is_auth:
        return error_response

    from config import log, LOG_PRINT
    import sys

    log(LOG_PRINT, 'Shutdown requested via REST API')

    # Trigger graceful shutdown
    import master
    master.serialise()
    master.cleanup_plugins()

    # Schedule shutdown
    import os
    import signal

    def delayed_shutdown():
        time.sleep(1)  # Give time for response to be sent
        # Use os._exit() instead of os.kill() to avoid thread issues
        os._exit(0)

    import threading
    threading.Thread(target=delayed_shutdown, daemon=True).start()

    return HandlerResponse(200, {
        'status': 'success',
        'message': 'Shutdown initiated'
    })


def handle_admin_reload_config(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext,
    client_ip: str = 'unknown',
    method: str = 'POST',
    path: str = '/api/admin/reload-config'
) -> HandlerResponse:
    """Handle POST /api/admin/reload-config - Reload configuration.

    Args:
        headers: HTTP headers
        body: Request body (not used)
        query_params: Query parameters
        ctx: Handler context
        client_ip: Client IP address
        method: HTTP method
        path: Request path

    Returns:
        HandlerResponse with status code and data
    """
    # Check authentication
    is_auth, error_response = _require_auth(headers, ctx, client_ip, method, path)
    if not is_auth:
        return error_response

    from config import log, LOG_PRINT

    log(LOG_PRINT, 'Configuration reload requested via REST API')

    # Reload featured servers
    try:
        ctx.config.files()
        log(LOG_PRINT, 'Configuration reloaded successfully')
    except Exception as e:
        log(LOG_PRINT, f'Error reloading configuration: {e}')
        return HandlerResponse(500, {
            'error': 'Internal Server Error',
            'message': f'Failed to reload configuration: {e}'
        })

    return HandlerResponse(200, {
        'status': 'success',
        'message': 'Configuration reloaded'
    })


def handle_get_stats(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext,
    client_ip: str = 'unknown',
    method: str = 'GET',
    path: str = '/api/stats'
) -> HandlerResponse:
    """Handle GET /api/stats - Get server statistics.

    Args:
        headers: HTTP headers
        body: Request body (not used)
        query_params: Query parameters
        ctx: Handler context
        client_ip: Client IP address
        method: HTTP method
        path: Request path

    Returns:
        HandlerResponse with status code and data
    """
    # Check authentication
    is_auth, error_response = _require_auth(headers, ctx, client_ip, method, path)
    if not is_auth:
        return error_response

    # Count servers by label
    server_counts = {}
    total_servers = 0
    verified_servers = 0

    for label, servers_dict in ctx.servers.items():
        label_name = label if label else 'default'
        count = len(servers_dict)
        verified = sum(1 for s in servers_dict.values() if bool(s))
        server_counts[label_name] = {
            'total': count,
            'verified': verified
        }
        total_servers += count
        verified_servers += verified

    # Count by connection type
    udp_servers = 0
    ws_servers = 0

    for servers_dict in ctx.servers.values():
        for server in servers_dict.values():
            conn_type = getattr(server, 'connection_type', 'udp')
            if conn_type == 'websocket':
                ws_servers += 1
            else:
                udp_servers += 1

    # Count by address family
    ipv4_servers = 0
    ipv6_servers = 0

    for servers_dict in ctx.servers.values():
        for server in servers_dict.values():
            if server.addr.family == AF_INET:
                ipv4_servers += 1
            elif server.addr.family == AF_INET6:
                ipv6_servers += 1

    return HandlerResponse(200, {
        'total_servers': total_servers,
        'verified_servers': verified_servers,
        'by_label': server_counts,
        'by_connection_type': {
            'udp': udp_servers,
            'websocket': ws_servers
        },
        'by_address_family': {
            'ipv4': ipv4_servers,
            'ipv6': ipv6_servers
        },
        'featured_groups': len(ctx.config.featured_servers)
    })


def handle_get_plugins(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext,
    client_ip: str = 'unknown',
    method: str = 'GET',
    path: str = '/api/plugins'
) -> HandlerResponse:
    """Handle GET /api/plugins - List all plugins.
    
    Args:
        headers: HTTP headers
        body: Request body (not used)
        query_params: Query parameters
        ctx: Handler context
        client_ip: Client IP address
        method: HTTP method
        path: Request path
        
    Returns:
        HandlerResponse with status code and plugin list
    """
    # Check authentication
    is_auth, error_response = _require_auth(headers, ctx, client_ip, method, path)
    if not is_auth:
        return error_response
    
    # Get list of loaded plugins from master module
    import master
    plugins_list = []
    
    for plugin in master.loaded_plugins:
        try:
            info = plugin.get_info()
            plugins_list.append({
                'name': info.get('name', 'Unknown'),
                'version': info.get('version', 'Unknown'),
                'description': info.get('description', ''),
                'enabled': True  # All loaded plugins are considered enabled
            })
        except Exception as e:
            from config import log, LOG_ERROR
            log(LOG_ERROR, f'Error getting plugin info: {e}')
    
    return HandlerResponse(200, {
        'plugins': plugins_list,
        'count': len(plugins_list)
    })


def handle_apitest(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext,
    client_ip: str = 'unknown',
    method: str = 'POST',
    path: str = '/api/plugins/disable'
) -> HandlerResponse:
    """Handle POST /api/plugins/disable - Disable a plugin.
    
    Args:
        headers: HTTP headers
        body: Request body with 'plugin' field
        query_params: Query parameters
        ctx: Handler context
        client_ip: Client IP address
        method: HTTP method
        path: Request path
        
    Returns:
        HandlerResponse with status code and data
    """
    # Check authentication
    is_auth, error_response = _require_auth(headers, ctx, client_ip, method, path)
    if not is_auth:
        return error_response
    
    # Validate request body
    if not body:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Request body is required'
        })
    
    plugin_name = body.get('plugin')
    if not plugin_name:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Missing required field: plugin'
        })
    
    import master
    
    # Find the plugin by name
    plugin_to_disable = None
    for plugin in master.loaded_plugins:
        try:
            info = plugin.get_info()
            if info.get('name') == plugin_name:
                plugin_to_disable = plugin
                break
        except Exception:
            pass
    
    if not plugin_to_disable:
        return HandlerResponse(404, {
            'error': 'Not Found',
            'message': f'Plugin "{plugin_name}" not found'
        })
    
    # Call cleanup on the plugin
    try:
        if hasattr(plugin_to_disable, 'cleanup'):
            plugin_to_disable.cleanup()
        master.loaded_plugins.remove(plugin_to_disable)
        
        from config import log, LOG_PRINT
        log(LOG_PRINT, f'Plugin "{plugin_name}" disabled via REST API')
        
        return HandlerResponse(200, {
            'status': 'success',
            'message': f'Plugin "{plugin_name}" disabled'
        })
    except Exception as e:
        from config import log, LOG_ERROR
        log(LOG_ERROR, f'Error disabling plugin "{plugin_name}": {e}')
        return HandlerResponse(500, {
            'error': 'Internal Server Error',
            'message': f'Failed to disable plugin: {e}'
        })


def handle_plugin_enable(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext,
    client_ip: str = 'unknown',
    method: str = 'POST',
    path: str = '/api/plugins/enable'
) -> HandlerResponse:
    """Handle POST /api/plugins/enable - Enable a plugin.
    
    Note: This requires the plugin to be reloaded from stevedore.
    This is a simplified implementation that just returns a message
    explaining that plugins are loaded at startup.
    
    Args:
        headers: HTTP headers
        body: Request body with 'plugin' field
        query_params: Query parameters
        ctx: Handler context
        client_ip: Client IP address
        method: HTTP method
        path: Request path
        
    Returns:
        HandlerResponse with status code and data
    """
    # Check authentication
    is_auth, error_response = _require_auth(headers, ctx, client_ip, method, path)
    if not is_auth:
        return error_response
    
    # Validate request body
    if not body:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Request body is required'
        })
    
    plugin_name = body.get('plugin')
    if not plugin_name:
        return HandlerResponse(400, {
            'error': 'Bad Request',
            'message': 'Missing required field: plugin'
        })
    
    # Note: Enabling a plugin requires reloading from stevedore
    # This is a complex operation that would require significant changes
    # to the plugin system. For now, return a message explaining
    # the limitation.
    return HandlerResponse(501, {
        'error': 'Not Implemented',
        'message': 'Plugin enable at runtime is not supported. '
                   'Plugins are loaded at server startup. '
                   'To enable a plugin, add it to the entry points '
                   'and restart the server.'
    })


def handle_apitest(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext,
    client_ip: str = 'unknown',
    method: str = 'GET',
    path: str = '/apitest'
) -> HandlerResponse:
    """Handle GET /apitest - Serve API test HTML page.
    
    This endpoint serves the API test HTML page directly from the plugin,
    avoiding CORS issues since it's served from the same origin.
    
    Args:
        headers: HTTP headers
        body: Request body (not used)
        query_params: Query parameters
        ctx: Handler context
        client_ip: Client IP address
        method: HTTP method
        path: Request path

    Returns:
        HandlerResponse with status code and HTML content
    """
    # SECURITY FIX: Validate file path to prevent directory traversal
    # Get path to static HTML file
    static_dir = os.path.join(os.path.dirname(__file__), 'static')
    html_file = os.path.join(static_dir, 'apitest.html')
    
    # Validate that the resolved path stays within the expected directory
    real_static_dir = os.path.realpath(static_dir)
    real_html_file = os.path.realpath(html_file)
    if not real_html_file.startswith(real_static_dir + os.sep):
        from config import log, LOG_ERROR
        log(LOG_ERROR, f'Path traversal attempt detected: {real_html_file}')
        return HandlerResponse(403, {
            'error': 'Forbidden',
            'message': 'Access denied'
        })
    
    try:
        with open(html_file, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        return HandlerResponse(200, {
            'content_type': 'text/html; charset=utf-8',
            'content': html_content
        })
    except FileNotFoundError:
        return HandlerResponse(404, {
            'error': 'Not Found',
            'message': 'API test page not found'
        })
    except Exception as e:
        from config import log, LOG_ERROR
        log(LOG_ERROR, f'Error serving apitest.html: {e}')
        return HandlerResponse(500, {
            'error': 'Internal Server Error',
            'message': 'Failed to serve API test page'
        })


def handle_get_servers_rss(
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
    query_params: Dict[str, Any],
    ctx: HandlerContext,
    client_ip: str = 'unknown',
    method: str = 'GET',
    path: str = '/api/servers/rss'
) -> HandlerResponse:
    """Handle GET /api/servers/rss - RSS feed of server additions.

    Args:
        headers: HTTP headers
        body: Request body (not used)
        query_params: Query parameters
        ctx: Handler context

    Returns:
        HandlerResponse with status code and data (XML content)
    """
    # Note: This endpoint returns XML, not JSON
    # The HTTP transport layer will need to handle content-type

    # Get all servers
    servers = []
    for label, servers_dict in ctx.servers.items():
        label_name = label if label else 'default'
        for addr, server in servers_dict.items():
            servers.append({
                'address': str(addr),
                'label': label_name,
                'verified': bool(server),
                'connection_type': getattr(server, 'connection_type', 'udp'),
                'family': 'IPv4' if addr.family == AF_INET else 'IPv6'
            })

    # Generate RSS XML
    from datetime import datetime
    from time import time as timestamp

    rss_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Tremulous Master Server - Server List</title>
    <link>http://{ctx.config.listen_addr}:{ctx.config.ports[0] if ctx.config.ports else 30710}/</link>
    <description>Current list of Tremulous game servers</description>
    <language>en-us</language>
    <lastBuildDate>{datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}</lastBuildDate>
"""

    for server in servers:
        rss_xml += f"""    <item>
      <title>{server['address']}</title>
      <description>Server: {server['address']} | Label: {server['label']} | Verified: {server['verified']} | Type: {server['connection_type']}</description>
      <pubDate>{datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}</pubDate>
    </item>
"""

    rss_xml += """  </channel>
</rss>"""

    # Return as plain text (XML will be set by transport layer)
    return HandlerResponse(200, {
        'content_type': 'application/rss+xml',
        'content': rss_xml
    })


# ============================================================================
# Handler Registry
# ============================================================================

# Map of endpoint paths to handler functions
# Format: (method, path_pattern) -> handler_function
HANDLERS = {
    # Unauthenticated endpoints
    ('GET', '/'): handle_root,
    ('GET', '/api/servers'): handle_root,  # Alias for /
    ('GET', '/api/info'): handle_get_info,
    ('GET', '/api/motd'): handle_get_motd,
    # ('POST', '/heartbeat'): handle_heartbeat,

    # Authenticated endpoints
    ('GET', '/api/blacklist'): handle_get_blacklist,
    ('POST', '/api/blacklist'): handle_add_blacklist,
    ('DELETE', '/api/blacklist/{id}'): handle_delete_blacklist,
    ('GET', '/api/featured'): handle_get_featured,
    ('PUT', '/api/featured'): handle_put_featured,
    ('PUT', '/api/motd'): handle_put_motd,
    ('GET', '/api/logs'): handle_get_logs,
    # ('POST', '/api/admin/shutdown'): handle_admin_shutdown,  # Disabled for security
    ('POST', '/api/admin/reload-config'): handle_admin_reload_config,
    ('GET', '/api/stats'): handle_get_stats,
    ('GET', '/api/servers/rss'): handle_get_servers_rss,
    ('GET', '/apitest'): handle_apitest,
    ('GET', '/api/plugins'): handle_get_plugins,
}


def get_handler(method: str, path: str) -> Optional[Any]:
    """Get handler function for a given method and path.

    Args:
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        path: Request path

    Returns:
        Handler function or None if not found
    """
    # Direct match
    key = (method.upper(), path)
    if key in HANDLERS:
        return HANDLERS[key]

    # Pattern match for paths with parameters
    # e.g., /api/blacklist/{id}
    for (handler_method, pattern), handler in HANDLERS.items():
        if handler_method != method.upper():
            continue

        # Simple pattern matching - check if path starts with pattern
        # and extract parameters
        if '{' in pattern and '}' in pattern:
            # Extract static prefix
            prefix = pattern.split('{')[0]
            if path.startswith(prefix):
                return handler

    return None


def extract_path_params(pattern: str, path: str) -> Dict[str, str]:
    """Extract path parameters from a URL pattern.

    Args:
        pattern: URL pattern with {param} placeholders
        path: Actual URL path

    Returns:
        Dictionary of parameter names to values
    """
    params = {}

    if '{' not in pattern or '}' not in pattern:
        return params

    # Simple extraction - this is a basic implementation
    # For more complex patterns, consider using a proper URL routing library
    prefix = pattern.split('{')[0]
    suffix = pattern.split('}')[-1]

    if path.startswith(prefix) and path.endswith(suffix):
        param_value = path[len(prefix):]
        param_name = pattern.split('{')[1].split('}')[0]
        params[param_name] = param_value

    return params
