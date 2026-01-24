"""
aiohttp HTTP transport implementation.

This module provides an HTTP transport implementation using the aiohttp framework.
aiohttp is an asynchronous HTTP client/server framework.
"""
import asyncio
import threading
from typing import Callable, Optional, Dict, Any

from plugins.http_transport import HTTPTransportBase
from plugins.sleepyteepee.handlers import HANDLERS

try:
    from aiohttp import web
except ImportError:
    raise ImportError(
        'aiohttp is required for AiohttpTransport. '
        'Install it with: pip install aiohttp'
    )


class AiohttpTransport(HTTPTransportBase):
    """HTTP transport implementation using aiohttp.

    This transport uses the aiohttp framework to provide HTTP server
    functionality. aiohttp is an asynchronous HTTP framework that is
    well-suited for high-performance applications.

    Attributes:
        app: The aiohttp Application instance
        plugin: The plugin instance for processing requests
        _runner: The AppRunner instance
        _site: The TCPSite instance
        _running: Whether the server is running
        _loop: The event loop for the server
    """

    def __init__(self, config: Any = None, plugin: Any = None):
        """Initialize the aiohttp transport.

        Args:
            config: Optional config object with api_keys attribute
            plugin: Optional plugin instance for processing requests
        """
        self.app = web.Application()
        self.plugin = plugin
        self._runner = None
        self._site = None
        self._running = False
        self._loop = None
        self._server_thread = None
        self.cors_enabled = False
        self.cors_origin = '*'

        # Get CORS configuration from plugin if available
        if plugin and hasattr(plugin, 'cors_enabled'):
            self.cors_enabled = plugin.cors_enabled
        if plugin and hasattr(plugin, 'cors_origin'):
            self.cors_origin = plugin.cors_origin

    def _get_request_context(self, request: web.Request) -> Dict[str, Any]:
        """Build the request context for handlers.

        Args:
            request: The aiohttp Request object

        Returns:
            Dictionary containing request data, query params, headers, etc.
        """
        return {
            'body': request.get('json_body', {}),
            'query': dict(request.query),
            'headers': {k.lower(): v for k, v in request.headers.items()},
            'path': request.path,
            'method': request.method,
        }

    async def _check_auth(self, request: web.Request) -> Optional[web.Response]:
        """Check authentication and return error response if required.

        Args:
            request: The aiohttp Request object

        Returns:
            None if authenticated, error Response otherwise
        """
        if self.auth:
            headers = {k.lower(): v for k, v in request.headers.items()}
            is_authenticated, error_response = self.auth.require_auth(headers)
            if not is_authenticated:
                return web.json_response(error_response, status=401)
        return None

    def _send_response(self, handler_response: Any) -> web.Response:
        """Send response from handler.

        Args:
            handler_response: HandlerResponse from plugin

        Returns:
            web.Response with appropriate status and content
        """
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

        # Create response
        if content_type == 'application/json':
            return web.json_response(response_data, status=status_code)
        else:
            return web.Response(
                text=response_data if isinstance(response_data, str) else response_data,
                status=status_code,
                content_type=content_type
            )

    async def _handler_wrapper(
        self,
        handler: Callable,
        request: web.Request,
        auth_required: bool
    ) -> web.Response:
        """Wrapper for route handlers that handles auth and errors.

        Args:
            handler: The route handler function
            request: The aiohttp Request object
            auth_required: Whether authentication is required

        Returns:
            web.Response with the handler result or error
        """
        # Check authentication if required
        if auth_required:
            error_response = await self._check_auth(request)
            if error_response:
                return error_response

        # Get request context and call handler
        request_context = self._get_request_context(request)
        try:
            result = handler(request_context)
            return web.json_response(result)
        except web.HTTPException:
            raise
        except Exception as e:
            return web.json_response(
                {
                    'error': 'Internal Server Error',
                    'message': str(e)
                },
                status=500
            )

    async def _setup_route(
        self,
        handler: Callable,
        method: str,
        path: str,
        auth_required: bool
    ) -> None:
        """Set up a route with the aiohttp application.

        Args:
            handler: The route handler function
            method: The HTTP method
            path: The URL path
            auth_required: Whether authentication is required
        """
        async def wrapper(request: web.Request) -> web.Response:
            # Try to parse JSON body
            try:
                request['json_body'] = await request.json()
            except Exception:
                request['json_body'] = {}

            return await self._handler_wrapper(handler, request, auth_required)

        self.app.router.add_route(method.upper(), path, wrapper)

        # Add OPTIONS handler for CORS preflight
        if self.cors_enabled:
            async def options_handler(request: web.Request) -> web.Response:
                response = web.Response(status=204)
                return self._send_cors_headers(response)

            if self._loop and not self._loop.is_closed():
                self._loop.call_soon_threadsafe(
                    lambda: asyncio.create_task(
                        self.app.router.add_route('OPTIONS', path, options_handler)
                    )
                )
            else:
                if not hasattr(self, '_pending_options_routes'):
                    self._pending_options_routes = []
                self._pending_options_routes.append((path, options_handler))

    def start(self, host: str, port: int) -> None:
        """Start the HTTP server.

        Args:
            host: The hostname or IP address to bind to
            port: The port number to listen on

        Raises:
            OSError: If the server cannot bind to the specified address
        """
        if self._running:
            raise RuntimeError('Server is already running')

        # Create new event loop for the server thread
        self._loop = asyncio.new_event_loop()

        # Run the server in a separate thread
        self._server_thread = threading.Thread(
            target=self._run_server,
            args=(host, port),
            daemon=True
        )
        self._server_thread.start()
        self._running = True

    def _run_server(self, host: str, port: int) -> None:
        """Run the aiohttp server in the current thread.

        Args:
            host: The hostname or IP address to bind to
            port: The port number to listen on
        """
        asyncio.set_event_loop(self._loop)
        try:
            self._runner = web.AppRunner(self.app)
            self._loop.run_until_complete(self._runner.setup())
            self._site = web.TCPSite(self._runner, host, port)
            self._loop.run_until_complete(self._site.start())
            self._loop.run_forever()
        except Exception as e:
            self._running = False
            raise OSError(f"Failed to bind to {host}:{port}: {e}")

    def stop(self) -> None:
        """Stop the HTTP server.

        Raises:
            RuntimeError: If the server is not running
        """
        if not self._running:
            raise RuntimeError('Server is not running')

        if self._runner:
            # Schedule cleanup on the server's event loop
            if self._loop and not self._loop.is_closed():
                self._loop.call_soon_threadsafe(self._loop.stop)

            # Wait for the thread to finish
            if self._server_thread:
                self._server_thread.join(timeout=5)

            self._running = False

    def register_handlers(self) -> None:
        """Register all handlers from HANDLERS registry."""
        if not self.plugin:
            return

        for (method, path), _ in HANDLERS.items():
            self._register_single_handler(method, path)

    def _register_single_handler(self, method: str, path: str) -> None:
        """Register a single handler route.

        Args:
            method: The HTTP method
            path: The URL path
        """
        async def wrapper(request: web.Request) -> web.Response:
            # Check if plugin is available
            if not self.plugin:
                return web.json_response(
                    {
                        'error': 'Internal Server Error',
                        'message': 'Plugin not configured'
                    },
                    status=500
                )

            # Get request context
            request_context = self._get_request_context(request)
            
            # Get client IP address
            peername = request.transport.get_extra_info('peername')
            client_ip = peername[0] if peername else 'unknown'

            # Call plugin's process_request method
            try:
                handler_response = self.plugin.process_request(
                    method=method,
                    path=path,
                    headers=request_context['headers'],
                    body=request_context['body'],
                    query_params=request_context['query'],
                    client_ip=client_ip
                )
                return self._send_response(handler_response)
            except web.HTTPException:
                raise
            except Exception as e:
                return web.json_response(
                    {
                        'error': 'Internal Server Error',
                        'message': str(e)
                    },
                    status=500
                )

        # Schedule route setup on the event loop if running
        if self._loop and not self._loop.is_closed():
            self._loop.call_soon_threadsafe(
                lambda: asyncio.create_task(
                    self._setup_route(wrapper, method, path, False)
                )
            )
        else:
            # If not running, we need to schedule it later
            # Store for when the server starts
            if not hasattr(self, '_pending_routes'):
                self._pending_routes = []
            self._pending_routes.append((wrapper, method, path, False))

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
            # Schedule route setup on the event loop if running
            if self._loop and not self._loop.is_closed():
                self._loop.call_soon_threadsafe(
                    lambda: asyncio.create_task(
                        self._setup_route(handler, method, path, auth_required)
                    )
                )
            else:
                # If not running, we need to schedule it later
                # Store for when the server starts
                if not hasattr(self, '_pending_routes'):
                    self._pending_routes = []
                self._pending_routes.append((handler, method, path, auth_required))

            return handler
        return decorator

    def _setup_pending_routes(self) -> None:
        """Set up any routes that were registered before the server started."""
        if hasattr(self, '_pending_routes'):
            for handler, method, path, auth_required in self._pending_routes:
                asyncio.create_task(
                    self._setup_route(handler, method, path, auth_required)
                )
            delattr(self, '_pending_routes')
