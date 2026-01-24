"""
Standard library HTTP transport implementation using http.server.

This module provides an HTTP transport implementation using Python's
built-in http.server module, requiring no external dependencies.
"""
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Callable, Optional, Dict, Any
from urllib.parse import urlparse, parse_qs

from plugins.http_transport import HTTPTransportBase
from plugins.sleepyteepee.handlers import HANDLERS


class _RequestHandler(BaseHTTPRequestHandler):
    """Internal request handler for the stdlib transport.

    This class handles individual HTTP requests and dispatches them
    to the appropriate registered route handler.
    """

    # Class-level storage for routes and plugin (shared across instances)
    routes: Dict[str, Dict[str, Callable]] = {}
    plugin: Optional[Any] = None
    cors_enabled: bool = False
    cors_origin: str = '*'

    def log_message(self, format: str, *args) -> None:
        """Override to suppress default logging."""
        pass

    def _send_cors_headers(self) -> None:
        """Send CORS headers if enabled."""
        if self.cors_enabled:
            self.send_header('Access-Control-Allow-Origin', self.cors_origin)
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-API-Key, Authorization')
            self.send_header('Access-Control-Max-Age', '86400')

    def _send_response(self, data: Any, status_code: int = 200, content_type: str = 'application/json') -> None:
        """Send a response.

        Args:
            data: The data to send (will be JSON serialized for JSON content type)
            status_code: The HTTP status code
            content_type: The content type header
        """
        self.send_response(status_code)
        self.send_header('Content-Type', content_type)
        self._send_cors_headers()
        self.end_headers()
        if content_type == 'application/json':
            self.wfile.write(json.dumps(data).encode('utf-8'))
        else:
            self.wfile.write(data.encode('utf-8') if isinstance(data, str) else data)

    def _send_error_response(self, status_code: int, error: str, message: str) -> None:
        """Send an error response.

        Args:
            status_code: The HTTP status code
            error: The error type
            message: The error message
        """
        self._send_response({
            'error': error,
            'message': message
        }, status_code)

    def _get_request_body(self) -> Optional[Dict[str, Any]]:
        """Parse and return the JSON request body.

        Returns:
            The parsed JSON body, or None if parsing fails
        """
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                return {}
            body = self.rfile.read(content_length).decode('utf-8')
            return json.loads(body) if body else {}
        except (json.JSONDecodeError, ValueError):
            return None

    def _get_headers_dict(self) -> Dict[str, str]:
        """Convert headers to a dictionary.

        Returns:
            Dictionary of headers
        """
        return {k.lower(): v for k, v in dict(self.headers).items()}

    def _get_query_params(self) -> Dict[str, str]:
        """Parse query parameters from the URL.

        Returns:
            Dictionary of query parameters
        """
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        return {k: v[0] if len(v) == 1 else v for k, v in params.items()}

    def _handle_route(self) -> None:
        """Handle the request by finding and calling the appropriate route handler."""
        parsed = urlparse(self.path)
        path = parsed.path
        method = self.command.upper()

        # Check if plugin is available
        if not self.plugin:
            self._send_error_response(500, 'Internal Server Error', 'Plugin not configured')
            return

        # Check rate limit
        client_ip = self.client_address[0]
        if hasattr(self.plugin, 'rate_limiter') and self.plugin.rate_limiter:
            allowed, retry_after = self.plugin.rate_limiter.is_allowed(client_ip)
            if not allowed:
                self.send_response(429)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Retry-After', str(retry_after))
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({
                    'error': 'Too Many Requests',
                    'message': f'Rate limit exceeded. Try again in {retry_after} seconds.'
                }).encode('utf-8'))
                return

        # Get request data
        request_body = self._get_request_body()
        query_params = self._get_query_params()
        headers = self._get_headers_dict()
        client_ip = self.client_address[0]

        # Call plugin's process_request method
        try:
            handler_response = self.plugin.process_request(
                method=method,
                path=path,
                headers=headers,
                body=request_body,
                query_params=query_params,
                client_ip=client_ip
            )

            # Extract response details
            status_code = handler_response.status_code
            data = handler_response.data

            # Check for custom content type (e.g., RSS XML)
            content_type = 'application/json'
            if isinstance(data, dict) and 'content_type' in data:
                content_type = data['content_type']
                response_data = data.get('content', data)
            else:
                response_data = data

            self._send_response(response_data, status_code, content_type)
        except Exception as e:
            self._send_error_response(500, 'Internal Server Error', str(e))

    def do_GET(self) -> None:
        """Handle GET requests."""
        self._handle_route()

    def do_POST(self) -> None:
        """Handle POST requests."""
        self._handle_route()

    def do_PUT(self) -> None:
        """Handle PUT requests."""
        self._handle_route()

    def do_DELETE(self) -> None:
        """Handle DELETE requests."""
        self._handle_route()

    def do_PATCH(self) -> None:
        """Handle PATCH requests."""
        self._handle_route()

    def do_OPTIONS(self) -> None:
        """Handle OPTIONS requests (CORS preflight)."""
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()


class StdlibTransport(HTTPTransportBase):
    """HTTP transport implementation using Python's built-in http.server.

    This transport uses the standard library's http.server module,
    requiring no external dependencies. It runs the HTTP server in a
    separate thread to avoid blocking the main thread.

    Attributes:
        server: The HTTPServer instance
        server_thread: The thread running the HTTP server
        auth: The API key authenticator
    """

    def __init__(self, config: Any = None, plugin: Any = None):
        """Initialize the stdlib transport.

        Args:
            config: Optional config object with api_keys attribute
            plugin: Optional plugin instance for processing requests
        """
        self.server: Optional[HTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.plugin = plugin

        # Get CORS configuration from plugin if available
        if plugin and hasattr(plugin, 'cors_enabled'):
            _RequestHandler.cors_enabled = plugin.cors_enabled
        if plugin and hasattr(plugin, 'cors_origin'):
            _RequestHandler.cors_origin = plugin.cors_origin

        # Clear any existing routes (for testing/reuse)
        _RequestHandler.routes = {}
        _RequestHandler.plugin = self.plugin

    def start(self, host: str, port: int) -> None:
        """Start the HTTP server.

        Args:
            host: The hostname or IP address to bind to
            port: The port number to listen on

        Raises:
            OSError: If the server cannot bind to the specified address
        """
        if self.server is not None:
            raise RuntimeError('Server is already running')

        try:
            self.server = HTTPServer((host, port), _RequestHandler)
            self.server_thread = threading.Thread(
                target=self.server.serve_forever,
                daemon=True
            )
            self.server_thread.start()
        except OSError as e:
            self.server = None
            raise OSError(f"Failed to bind to {host}:{port}: {e}")

    def stop(self) -> None:
        """Stop the HTTP server.

        Raises:
            RuntimeError: If the server is not running
        """
        if self.server is None:
            raise RuntimeError('Server is not running')

        self.server.shutdown()
        if self.server_thread:
            self.server_thread.join(timeout=5)
        self.server = None
        self.server_thread = None

    def register_handlers(self) -> None:
        """Register all handlers from the HANDLERS registry."""
        if not self.plugin:
            return

        for (method, path), handler in HANDLERS.items():
            route_key = f"{method}:{path}"
            _RequestHandler.routes[route_key] = {
                'handler': handler,
                'auth_required': False  # Authentication is handled by handlers
            }

    def route(self, method: str, path: str, auth_required: bool = False) -> Callable:
        """Decorator for route registration.

        Args:
            method: The HTTP method (e.g., 'GET', 'POST', 'PUT', 'DELETE')
            path: The URL path for the route
            auth_required: Whether the route requires authentication

        Returns:
            A decorator function that registers the route handler
        """
        def decorator(handler: Callable) -> Callable:
            route_key = f"{method.upper()}:{path}"
            _RequestHandler.routes[route_key] = {
                'handler': handler,
                'auth_required': auth_required
            }
            return handler
        return decorator
