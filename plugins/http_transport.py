"""
HTTP transport abstraction layer for the sleepyteepee REST API plugin.

This module provides an abstract base class that defines the interface
for HTTP transport implementations, allowing the sleepyteepee plugin to
support multiple HTTP frameworks through a unified API.
"""
import abc
from typing import Callable, Optional


class HTTPTransportBase(metaclass=abc.ABCMeta):
    """Abstract base class for HTTP transport implementations.

    The sleepyteepee REST API plugin uses this abstraction layer to support
    multiple HTTP frameworks (e.g., Flask, FastAPI, aiohttp) without being
    tightly coupled to any specific framework. Implementations of this class
    handle the low-level HTTP server details while providing a consistent
    interface for route registration and server lifecycle management.

    Usage:
        Subclass this class and implement the abstract methods to create
        a transport for a specific HTTP framework. The route() method should
        be used as a decorator to register endpoint handlers.
    """

    @abc.abstractmethod
    def start(self, host: str, port: int) -> None:
        """Start the HTTP server.

        This method should bind the server to the specified host and port
        and begin accepting HTTP requests. The implementation should handle
        any necessary framework-specific setup.

        Args:
            host: The hostname or IP address to bind to
            port: The port number to listen on

        Raises:
            OSError: If the server cannot bind to the specified address
        """
        pass

    @abc.abstractmethod
    def stop(self) -> None:
        """Stop the HTTP server.

        This method should gracefully shut down the HTTP server, releasing
        any resources and closing all active connections. The implementation
        should ensure that in-flight requests are handled appropriately.

        Raises:
            RuntimeError: If the server is not running
        """
        pass

    @abc.abstractmethod
    def route(self, method: str, path: str, auth_required: bool = False) -> Callable:
        """Decorator for route registration.

        This method returns a decorator that can be used to register
        HTTP endpoint handlers. The decorated function will be called
        when a matching HTTP request is received.

        Args:
            method: The HTTP method (e.g., 'GET', 'POST', 'PUT', 'DELETE')
            path: The URL path pattern for the route
            auth_required: Whether the route requires authentication

        Returns:
            A decorator function that registers the route handler

        Example:
            @transport.route('GET', '/api/servers')
            def get_servers():
                return {'servers': []}
        """
        pass
