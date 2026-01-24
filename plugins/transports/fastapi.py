"""
FastAPI HTTP transport implementation.

This module provides an HTTP transport implementation using the FastAPI framework.
FastAPI is a modern, fast (high-performance) web framework for building APIs.
"""
import asyncio
import threading
from typing import Callable, Optional, Dict, Any

from plugins.http_transport import HTTPTransportBase
from plugins.sleepyteepee.handlers import HANDLERS

try:
    from fastapi import FastAPI, Request, HTTPException
    from fastapi.responses import JSONResponse, Response  # type: ignore
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn  # type: ignore
except ImportError:
    raise ImportError(
        'FastAPI and uvicorn are required for FastAPITransport. '
        'Install them with: pip install fastapi uvicorn'
    )


class FastAPITransport(HTTPTransportBase):
    """HTTP transport implementation using FastAPI.

    This transport uses the FastAPI framework to provide HTTP server
    functionality. FastAPI is a modern, high-performance web framework
    with automatic OpenAPI documentation and type validation.

    Attributes:
        app: The FastAPI application instance
        plugin: The plugin instance for processing requests
        _uvicorn_server: The uvicorn server instance
        _running: Whether the server is running
    """

    def __init__(self, config: Any = None, plugin: Any = None):
        """Initialize the FastAPI transport.

        Args:
            config: Optional config object with api_keys attribute
            plugin: Optional plugin instance for processing requests
        """
        self.app = FastAPI()
        self.plugin = plugin
        self.auth = None
        self._uvicorn_server = None
        self._running = False
        self._server_thread = None
        self.cors_enabled = False
        self.cors_origin = '*'

        # Get CORS configuration from plugin if available
        if plugin and hasattr(plugin, 'cors_enabled'):
            self.cors_enabled = plugin.cors_enabled
        if plugin and hasattr(plugin, 'cors_origin'):
            self.cors_origin = plugin.cors_origin

    def _get_request_context(self, request: Request) -> Dict[str, Any]:
        """Build the request context for handlers.

        Args:
            request: The FastAPI Request object

        Returns:
            Dictionary containing request data, query params, headers, etc.
        """
        return {
            'body': request.state.json_body if hasattr(request.state, 'json_body') else {},
            'query': dict(request.query_params),
            'headers': {k.lower(): v for k, v in request.headers.items()},
            'path': request.url.path,
            'method': request.method,
        }

    async def _check_auth(self, request: Request) -> None:
        """Check authentication and raise exception if required.

        Args:
            request: The FastAPI Request object

        Raises:
            HTTPException: If authentication fails
        """
        if self.auth:
            headers = {k.lower(): v for k, v in request.headers.items()}
            is_authenticated, error_response = self.auth.require_auth(headers)
            if not is_authenticated:
                raise HTTPException(status_code=401, detail=error_response)

    def _send_cors_headers(self, response: Response) -> Response:
        """Add CORS headers to response if enabled."""
        if self.cors_enabled:
            response.headers['Access-Control-Allow-Origin'] = self.cors_origin
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key, Authorization'
            response.headers['Access-Control-Max-Age'] = '86400'
        return response

    def _send_response(self, handler_response: Any) -> Response:
        """Send response from handler.

        Args:
            handler_response: HandlerResponse from plugin

        Returns:
            Response with appropriate status and content
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
            response = JSONResponse(content=response_data, status_code=status_code)
            return self._send_cors_headers(response)
        else:
            response = Response(
                content=response_data,
                status_code=status_code,
                media_type=content_type
            )
            return self._send_cors_headers(response)

    async def _handler_wrapper(
        self,
        handler: Callable,
        request: Request,
        auth_required: bool
    ) -> Response:
        """Wrapper for route handlers that handles auth and errors.

        Args:
            handler: The route handler function
            request: The FastAPI Request object
            auth_required: Whether authentication is required

        Returns:
            Response with the handler result or error
        """
        # Check authentication if required
        if auth_required:
            await self._check_auth(request)

        # Get request context and call handler
        request_context = self._get_request_context(request)
        try:
            result = handler(request_context)
            return JSONResponse(content=result)
        except HTTPException:
            raise
        except Exception as e:
            return JSONResponse(
                status_code=500,
                content={
                    'error': 'Internal Server Error',
                    'message': str(e)
                }
            )

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

        # Create uvicorn config
        self._uvicorn_server = uvicorn.Server(
            uvicorn.Config(
                app=self.app,
                host=host,
                port=port,
                log_level='error'  # Reduce uvicorn logging
            )
        )

        # Add CORS middleware if enabled
        if self.cors_enabled:
            self.app.add_middleware(
                CORSMiddleware,
                allow_origins=[self.cors_origin],
                allow_credentials=True,
                allow_methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
                allow_headers=['Content-Type', 'X-API-Key', 'Authorization'],
            )

        # Run in a separate thread
        self._server_thread = threading.Thread(
            target=self._run_server,
            daemon=True
        )
        self._server_thread.start()
        self._running = True

    def _run_server(self) -> None:
        """Run the uvicorn server in the current thread."""
        if self._uvicorn_server:
            asyncio.run(self._uvicorn_server.serve())

    def stop(self) -> None:
        """Stop the HTTP server.

        Raises:
            RuntimeError: If the server is not running
        """
        if not self._running:
            raise RuntimeError('Server is not running')

        if self._uvicorn_server:
            # uvicorn doesn't have a clean shutdown from another thread
            # We set the flag and the thread will exit when the main thread exits
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
        async def wrapper(request: Request) -> Response:
            # Check if plugin is available
            if not self.plugin:
                return JSONResponse(
                    status_code=500,
                    content={
                        'error': 'Internal Server Error',
                        'message': 'Plugin not configured'
                    }
                )

            # Store JSON body in request state for later use
            try:
                request.state.json_body = await request.json()
            except Exception:
                request.state.json_body = {}

            # Get request context
            request_context = self._get_request_context(request)
            client_ip = request.client.host if request.client else 'unknown'

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
            except HTTPException:
                raise
            except Exception as e:
                return JSONResponse(
                    status_code=500,
                    content={
                        'error': 'Internal Server Error',
                        'message': str(e)
                    }
                )

        # Register the route with FastAPI
        self.app.add_api_route(
            path,
            wrapper,
            methods=[method.upper()]
        )

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
            async def wrapper(request: Request) -> Response:
                # Store JSON body in request state for later use
                try:
                    request.state.json_body = await request.json()
                except Exception:
                    request.state.json_body = {}

                return await self._handler_wrapper(handler, request, auth_required)

            # Register the route with FastAPI
            # FastAPI uses a list of methods
            self.app.add_api_route(
                path,
                wrapper,
                methods=[method.upper()]
            )
            return handler
        return decorator
