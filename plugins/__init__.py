"""
Tremulous Master Server Plugins

This package provides a plugin system for extending the master server functionality.
Plugins can extend server discovery, add new protocol handlers, or integrate with
external master servers.
"""

from .base import MasterPluginBase

__all__ = ['MasterPluginBase']
