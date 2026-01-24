"""
HTTP transport implementations for sleepyteepee REST API plugin.

This package provides multiple HTTP transport implementations that extend
HTTPTransportBase, allowing to sleepyteepee plugin to support various
HTTP frameworks through a unified API.

Available transports:
- stdlib: Python's built-in http.server (no external dependencies)
- flask: Flask framework
- fastapi: FastAPI framework
- aiohttp: aiohttp framework (async)

Each transport implements the same interface defined in HTTPTransportBase.
"""

# Try to import each transport, handling ImportError gracefully
_stdlib_transport = None
_flask_transport = None
_fastapi_transport = None
_aiohttp_transport = None

try:
    from .stdlib import StdlibTransport
    _stdlib_transport = StdlibTransport
except ImportError:
    pass

try:
    from .flask import FlaskTransport
    _flask_transport = FlaskTransport
except ImportError:
    pass

try:
    from .fastapi import FastAPITransport
    _fastapi_transport = FastAPITransport
except ImportError:
    pass

try:
    from .aiohttp import AiohttpTransport
    _aiohttp_transport = AiohttpTransport
except ImportError:
    pass

# Export available transports
__all__ = [
    'StdlibTransport',
    'FlaskTransport',
    'FastAPITransport',
    'AiohttpTransport',
]

# Set module-level attributes for available transports
if _stdlib_transport:
    StdlibTransport = _stdlib_transport
if _flask_transport:
    FlaskTransport = _flask_transport
if _fastapi_transport:
    FastAPITransport = _fastapi_transport
if _aiohttp_transport:
    AiohttpTransport = _aiohttp_transport
