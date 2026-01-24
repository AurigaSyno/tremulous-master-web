"""
Sleepyteepee Plugin - REST API for Tremulous Master Server.

This plugin provides a REST API for managing the Tremulous Master Server,
allowing remote administration and monitoring via HTTP requests.
"""
from .auth import APIKeyAuth, get_api_keys, validate_api_key

__all__ = ['APIKeyAuth', 'get_api_keys', 'validate_api_key']
