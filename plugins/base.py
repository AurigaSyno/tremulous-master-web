"""
Base class for Tremulous Master Server plugins.

Plugins can extend the master server functionality by implementing
the methods defined in this abstract base class.
"""
import abc
from typing import Optional, Dict, Any


class MasterPluginBase(metaclass=abc.ABCMeta):
    """Base class for master server plugins.

    All plugins must implement the methods defined in this class.
    The plugin system uses stevedore to dynamically load plugins
    at runtime.
    """

    def __init__(self, config: Any, servers: Dict, outSocks: Dict):
        """Initialize the plugin.

        Args:
            config: The master server configuration object
            servers: The servers dictionary (dict of [label][addr] -> Server)
            outSocks: Dictionary of output sockets keyed by address family
        """
        self.config = config
        self.servers = servers
        self.outSocks = outSocks

    @abc.abstractmethod
    def get_name(self) -> str:
        """Return the name of this plugin.

        Returns:
            A string identifying this plugin
        """
        pass

    @abc.abstractmethod
    def initialize(self) -> bool:
        """Initialize the plugin.

        This method is called when the plugin is first loaded.
        Perform any setup work here.

        Returns:
            True if initialization was successful, False otherwise
        """
        pass

    def on_heartbeat(self, addr: tuple, data: bytes) -> Optional[bool]:
        """Called when a heartbeat is received.

        Plugins can intercept and modify heartbeat processing.

        Args:
            addr: The address tuple (host, port)
            data: The heartbeat data

        Returns:
            True to stop further processing, False to continue,
            None to not interfere
        """
        return None

    def on_getservers(self, sock, addr: tuple, data: bytes) -> Optional[bool]:
        """Called when a getservers request is received.

        Plugins can intercept and modify getservers processing.

        Args:
            sock: The socket to respond on
            addr: The address tuple (host, port)
            data: The getservers data

        Returns:
            True to stop further processing, False to continue,
            None to not interfere
        """
        return None

    def on_server_timeout(self, server: Any) -> None:
        """Called when a server times out.

        Args:
            server: The Server instance that timed out
        """
        pass

    def cleanup(self) -> None:
        """Cleanup resources when the plugin is being unloaded.

        This method is called during shutdown.
        """
        pass

    def get_info(self) -> Dict[str, Any]:
        """Return plugin information.

        Returns:
            A dictionary with plugin metadata
        """
        return {
            'name': self.get_name(),
            'version': getattr(self, 'version', 'unknown'),
            'description': getattr(self, 'description', ''),
        }
