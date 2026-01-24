"""
Flask HTTP transport implementation.

This module provides an HTTP transport implementation using the Flask framework.
Flask is a lightweight WSGI web application framework.
"""
from typing import Callable, Optional, Dict, Any

from plugins.http_transport import HTTPTransportBase
from plugins.sleepyteepee.handlers import HANDLERS

try:
    from flask import Flask, request, jsonify
except ImportError:
    raise ImportError(
        'Flask is required for FlaskTransport. '
        'Install it with: pip install flask'
    )


class FlaskTransport(HTTPTransportBase):
    """HTTP transport implementation using Flask.

    This transport uses the Flask framework to provide HTTP server
    functionality. Flask is a lightweight WSGI framework with excellent
    support for REST APIs.

    Attributes:
        app: The Flask application instance
        plugin: The plugin instance for processing requests
    """

    def __init__(self, config: Any = None, plugin: Any = None):
        """Initialize the Flask transport.

        Args:
            config: Optional config object with api_keys attribute
            plugin: Optional plugin instance for processing requests
        """
        self.app = Flask(__name__)
        self.plugin = plugin
        self._running = False
        self.cors_enabled = False
        self.cors_origin = '*'

        # Get CORS configuration from plugin if available
        if plugin and hasattr(plugin, 'cors_enabled'):
            self.cors_enabled = plugin.cors_enabled
        if plugin and hasattr(plugin, 'cors_origin'):
            self.cors_origin = plugin.cors_origin

    def _get_request_context(self) -> Dict[str, Any]:
        """Build the request context for handlers.

        Returns:
            Dictionary containing request data, query params, headers, etc.
        """
        return {
            'body': request.get_json(silent=True) or {},
            'query': dict(request.args),
            'headers': {k.lower(): v for k, v in dict(request.headers).items()},
            'path': request.path,
            'method': request.method,
        }

    def _send_cors_headers(self, response):
        """Add CORS headers to response if enabled."""
        if self.cors_enabled:
            response.headers['Access-Control-Allow-Origin'] = self.cors_origin
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key, Authorization'
            response.headers['Access-Control-Max-Age'] = '86400'

    def _send_response(self, handler_response, original_response_func):
        """Send response from handler.

        Args:
            handler_response: HandlerResponse from plugin
            original_response_func: Flask's make_response function
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
            from flask import jsonify
            resp = jsonify(response_data)
            resp.status_code = status_code
            self._send_cors_headers(resp)
            return resp
        else:
            resp = original_response_func(response_data)
            resp.status_code = status_code
            resp.headers['Content-Type'] = content_type
            self._send_cors_headers(resp)
            return resp

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

        try:
            # Run Flask in a separate thread to avoid blocking
            import threading
            self._server_thread = threading.Thread(
                target=self.app.run,
                kwargs={'host': host, 'port': port, 'threaded': True},
                daemon=True
            )
            self._server_thread.start()
            self._running = True
        except OSError as e:
            self._running = False
            raise OSError(f"Failed to bind to {host}:{port}: {e}")

    def stop(self) -> None:
        """Stop the HTTP server.

        Raises:
            RuntimeError: If the server is not running
        """
        if not self._running:
            raise RuntimeError('Server is not running')

        # Flask doesn't provide a clean way to stop from outside
        # We set a flag and the thread will exit when the main thread exits
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
        def wrapper(*args, **kwargs):
            # Check if plugin is available
            if not self.plugin:
                return {
                    'error': 'Internal Server Error',
                    'message': 'Plugin not configured'
                }, 500

            # Get request data
            request_context = self._get_request_context()
            client_ip = request.remote_addr or 'unknown'

            # Call plugin's process_request method
            try:
                from flask import make_response
                handler_response = self.plugin.process_request(
                    method=method,
                    path=path,
                    headers=request_context['headers'],
                    body=request_context['body'],
                    query_params=request_context['query'],
                    client_ip=client_ip
                )
                return self._send_response(handler_response, make_response)
            except Exception as e:
                return {
                    'error': 'Internal Server Error',
                    'message': str(e)
                }, 500

        # Register the route with Flask
        self.app.route(path, methods=[method.upper()])(wrapper)

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
            def wrapper(*args, **kwargs):
                # Check authentication if required
                if auth_required:
                    is_authenticated, error_response = self._check_auth()
                    if not is_authenticated:
                        from flask import jsonify
                        return jsonify(error_response), 401

                # Get request context and call handler
                request_context = self._get_request_context()
                try:
                    result = handler(request_context)
                    from flask import jsonify
                    return jsonify(result)
                except Exception as e:
                    from flask import jsonify
                    return jsonify({
                        'error': 'Internal Server Error',
                        'message': str(e)
                    }), 500

            # Register the route with Flask
            # Flask uses methods as a list, so we wrap our single method
            self.app.route(path, methods=[method.upper()])(wrapper)
            return handler
        return decorator
