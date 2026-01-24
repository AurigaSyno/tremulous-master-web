"""
Sleepyteepee Plugin - REST API for managing the Tremulous Master Server.

This plugin provides a REST API for managing the Tremulous Master Server,
allowing external applications to query and manage server listings via HTTP.

The plugin uses a two-phase initialization pattern:
1. pre_initialize() - Called BEFORE socket binding. Loads configuration and
   sets up the HTTP transport abstraction.
2. initialize() - Called AFTER socket binding. Starts the HTTP server and
   registers API endpoints.

The plugin integrates with:
- HTTP transport abstraction (plugins/http_transport.py)
- API key authentication (plugins/sleepyteepee/auth.py)
- Server registry from the master server

Configuration:
- --api-host: Host to bind the REST API server (default: '127.0.0.1')
- --api-port: Port for the REST API server (default: 8067)
- --api-keys: Comma-separated list of API keys (or SLEEPYTEEPEE_API_KEYS env var)
- --rate-limit: Maximum requests per minute per IP (default: 30)
"""
from typing import Optional, Dict, Any, List
from time import time
import os

from ..base import MasterPluginBase
from ..http_transport import HTTPTransportBase
from .auth import APIKeyAuth
from .ratelimit import RateLimiter
from .handlers import (
    HandlerContext,
    HandlerResponse,
    HANDLERS,
    get_handler,
    extract_path_params,
)


class SleepyteepeePlugin(MasterPluginBase):
    """Plugin that provides a REST API for managing the master server."""

    version = '1.0.0'
    description = 'REST API for managing the Tremulous Master Server'

    # Default configuration values
    DEFAULT_API_HOST = '127.0.0.1'
    DEFAULT_API_PORT = 8067
    DEFAULT_RATE_LIMIT = 60
    DEFAULT_CORS_ENABLED = False
    DEFAULT_CORS_ORIGIN = '*'

    def __init__(self, config: Any, servers: Dict, outSocks: Dict):
        """Initialize the Sleepyteepee plugin.

        Args:
            config: The master server configuration object
            servers: The servers dictionary (dict of [label][addr] -> Server)
            outSocks: Dictionary of output sockets keyed by address family
        """
        super().__init__(config, servers, outSocks)

        # Configuration values (loaded in pre_initialize)
        self.api_host: str = self.DEFAULT_API_HOST
        self.api_port: int = self.DEFAULT_API_PORT
        self.rate_limit: int = self.DEFAULT_RATE_LIMIT
        self.cors_enabled: bool = self.DEFAULT_CORS_ENABLED
        self.cors_origin: str = self.DEFAULT_CORS_ORIGIN

        # HTTP transport instance (set in pre_initialize)
        self.http_transport: Optional[HTTPTransportBase] = None

        # Rate limiter instance (set in pre_initialize)
        self.rate_limiter: Optional[RateLimiter] = None

        # Authentication helper
        self.auth: Optional[APIKeyAuth] = None

        # Track whether the plugin is enabled
        self.enabled: bool = True

        # Handler context for passing to handler functions
        self._handler_context: Optional[HandlerContext] = None

        # Log storage for /api/logs endpoint
        self._log_entries: List[Dict[str, Any]] = []
        self._max_log_entries: int = 1000

    def get_name(self) -> str:
        """Return the name of this plugin.

        Returns:
            The plugin name 'sleepyteepee'
        """
        return 'sleepyteepee'

    def pre_initialize(self) -> bool:
        """Pre-initialize the Sleepyteepee plugin before socket binding.

        This method is called BEFORE the master server binds its sockets.
        It performs setup that doesn't require the network to be ready:
        - Load configuration from config object
        - Initialize the HTTP transport abstraction
        - Set up API key authentication

        Returns:
            bool: True if pre-initialization succeeded, False otherwise
        """
        from config import log, LOG_PRINT, LOG_VERBOSE, LOG_DEBUG, LOG_ERROR

        # Load API host configuration
        if hasattr(self.config, 'api_host') and self.config.api_host:
            self.api_host = self.config.api_host

        # Load API port configuration
        if hasattr(self.config, 'api_port') and self.config.api_port:
            self.api_port = int(self.config.api_port)
        elif hasattr(self.config, 'api_port_from_env'):
            self.api_port = int(self.config.api_port_from_env)

        # Load rate limit configuration
        if hasattr(self.config, 'rate_limit') and self.config.rate_limit:
            self.rate_limit = int(self.config.rate_limit)
        elif os.environ.get('API_RATE_LIMIT'):
            self.rate_limit = int(os.environ.get('API_RATE_LIMIT'))

        # Load CORS configuration
        if hasattr(self.config, 'cors_enabled') and self.config.cors_enabled is not None:
            self.cors_enabled = self.config.cors_enabled.lower() in ('true', '1', 'yes', 'on')

        if hasattr(self.config, 'cors_origin') and self.config.cors_origin:
            self.cors_origin = self.config.cors_origin

        # Initialize rate limiter
        self.rate_limiter = RateLimiter(max_requests=self.rate_limit)

        # Initialize authentication helper
        self.auth = APIKeyAuth(self.config)

        # Check if API keys are configured
        if not self.auth.has_keys_configured():
            log(LOG_PRINT, 'Sleepyteepee plugin: No API keys configured. '
                          'Set API_KEYS environment variable or use --api-keys argument.')
            self.enabled = False
            return False

        # Initialize HTTP transport (actual implementation will be set later)
        # For now, we'll set up the structure - the specific transport
        # (Flask, FastAPI, etc.) will be instantiated based on availability
        self.http_transport = None

        # Create handler context
        self._handler_context = HandlerContext(
            config=self.config,
            servers=self.servers,
            outSocks=self.outSocks,
            auth=self.auth,
            plugin_instance=self
        )

        log(LOG_VERBOSE, f'Sleepyteepee plugin pre-initialization: '
                        f'host={self.api_host}, port={self.api_port}, '
                        f'cors_enabled={self.cors_enabled}, cors_origin={self.cors_origin}')

        return True

    def initialize(self) -> bool:
        """Initialize the Sleepyteepee plugin after socket binding.

        This method is called AFTER the master server has bound its sockets.
        It performs setup that requires the network to be ready:
        - Instantiate the HTTP transport implementation
        - Register REST API endpoints
        - Start the HTTP server

        Returns:
            bool: True if initialization was successful, False otherwise
        """
        from config import log, LOG_PRINT, LOG_VERBOSE, LOG_DEBUG, LOG_ERROR

        if not self.enabled:
            log(LOG_PRINT, 'Sleepyteepee plugin: Plugin is disabled, skipping initialization')
            return False

        # Try to instantiate a transport implementation
        # Try in order of preference: stdlib (no deps), Flask, FastAPI, aiohttp
        transport = None
        transport_name = None

        # Try stdlib transport first (no external dependencies)
        try:
            from ..transports.stdlib import StdlibTransport
            transport = StdlibTransport(self.config, plugin=self)
            transport_name = 'stdlib'
            log(LOG_VERBOSE, 'Sleepyteepee plugin: Using stdlib transport')
        except ImportError:
            pass

        # Try Flask transport
        if not transport:
            try:
                from ..transports.flask import FlaskTransport
                transport = FlaskTransport(self.config, plugin=self)
                transport_name = 'Flask'
                log(LOG_VERBOSE, 'Sleepyteepee plugin: Using Flask transport')
            except ImportError:
                pass

        # Try FastAPI transport
        if not transport:
            try:
                from ..transports.fastapi import FastAPITransport
                transport = FastAPITransport(self.config, plugin=self)
                transport_name = 'FastAPI'
                log(LOG_VERBOSE, 'Sleepyteepee plugin: Using FastAPI transport')
            except ImportError:
                pass

        # Try aiohttp transport
        if not transport:
            try:
                from ..transports.aiohttp import AiohttpTransport
                transport = AiohttpTransport(self.config, plugin=self)
                transport_name = 'aiohttp'
                log(LOG_VERBOSE, 'Sleepyteepee plugin: Using aiohttp transport')
            except ImportError:
                pass

        if not transport:
            log(LOG_ERROR, 'Sleepyteepee plugin: No HTTP transport implementation available. '
                         'Install Flask, FastAPI, aiohttp, or use stdlib transport.')
            return False

        self.http_transport = transport

        # Register all handlers from the handlers registry
        try:
            self.http_transport.register_handlers()
            log(LOG_VERBOSE, f'Sleepyteepee plugin: Registered {len(HANDLERS)} API endpoints')
        except Exception as e:
            log(LOG_ERROR, f'Sleepyteepee plugin: Failed to register handlers: {e}')
            return False

        # Start the HTTP server
        try:
            self.http_transport.start(self.api_host, self.api_port)
            log(LOG_PRINT, f'Sleepyteepee plugin initialized ({transport_name}): '
                          f'listening on {self.api_host}:{self.api_port}')
        except Exception as e:
            log(LOG_ERROR, f'Sleepyteepee plugin: Failed to start HTTP server: {e}')
            return False

        return True

    def cleanup(self) -> None:
        """Cleanup resources when the plugin is being unloaded.

        This method is called during shutdown. It performs cleanup:
        - Stop the HTTP server
        - Release any resources
        """
        from config import log, LOG_VERBOSE, LOG_DEBUG, LOG_PRINT, LOG_ERROR

        log(LOG_VERBOSE, 'Sleepyteepee plugin: Cleanup starting...')

        # Stop the HTTP server if running
        if self.http_transport:
            try:
                self.http_transport.stop()
                log(LOG_DEBUG, 'Sleepyteepee plugin: HTTP server stopped')
            except Exception as e:
                log(LOG_ERROR, f'Sleepyteepee plugin: Error stopping HTTP server: {e}')

        log(LOG_VERBOSE, 'Sleepyteepee plugin: Cleanup complete')

    def get_info(self) -> Dict[str, Any]:
        """Return plugin information.

        Returns:
            A dictionary with plugin metadata including configuration
        """
        info = super().get_info()
        info.update({
            'api_host': self.api_host,
            'api_port': self.api_port,
            'rate_limit': self.rate_limit,
            'cors_enabled': self.cors_enabled,
            'cors_origin': self.cors_origin,
            'enabled': self.enabled,
        })
        return info

    def get_handler_context(self) -> HandlerContext:
        """Get the handler context for processing requests.

        Returns:
            The HandlerContext instance
        """
        return self._handler_context

    def add_log_entry(self, level: str, message: str, **kwargs) -> None:
        """Add a log entry to the in-memory log storage.

        This is used by the /api/logs endpoint to retrieve recent log entries.

        Args:
            level: Log level (ERROR, PRINT, VERBOSE, DEBUG)
            message: Log message
            **kwargs: Additional metadata to include in the log entry
        """
        from time import time

        entry = {
            'timestamp': int(time()),
            'level': level,
            'message': message,
        }
        entry.update(kwargs)

        self._log_entries.append(entry)

        # Limit the number of log entries
        if len(self._log_entries) > self._max_log_entries:
            self._log_entries = self._log_entries[-self._max_log_entries:]

    def process_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: Optional[Dict[str, Any]],
        query_params: Dict[str, Any],
        client_ip: str = 'unknown'
    ) -> HandlerResponse:
        """Process an HTTP request and return the handler response.

        This method is called by the HTTP transport layer to handle incoming requests.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            path: Request path
            headers: HTTP headers
            body: Parsed request body (for POST/PUT requests)
            query_params: Query parameters
            client_ip: Client IP address

        Returns:
            HandlerResponse with status code and data
        """
        from config import log, LOG_DEBUG

        # Find the appropriate handler
        handler = get_handler(method, path)

        if not handler:
            return HandlerResponse(404, {
                'error': 'Not Found',
                'message': f'No handler for {method} {path}'
            })

        log(LOG_DEBUG, f'Sleepyteepee: Processing {method} {path}')

        # Extract path parameters if any
        # Get the pattern for the found handler
        pattern = None
        for (h_method, h_pattern), h_func in HANDLERS.items():
            if h_method.upper() == method.upper() and h_func == handler:
                pattern = h_pattern
                break

        path_params = extract_path_params(pattern, path) if pattern else {}

        # Merge path params into query params
        all_params = {**query_params, **path_params}

        # Call the handler
        try:
            return handler(
                headers=headers,
                body=body,
                query_params=all_params,
                ctx=self._handler_context,
                client_ip=client_ip,
                method=method,
                path=path
            )
        except Exception as e:
            log(LOG_DEBUG, f'Sleepyteepee: Error in handler: {e}')
            return HandlerResponse(500, {
                'error': 'Internal Server Error',
                'message': str(e)
            })
