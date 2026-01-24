"""
API Key Authentication Module for Sleepyteepee REST API.

This module provides API key authentication for securing REST API endpoints.
API keys can be configured via environment variable or command-line arguments.
"""
import os
import time
from typing import Optional, Set, Dict, Any

# Global storage for API keys (never logged)
_api_keys: Set[str] = set()

# SECURITY FIX: Rate limiting for failed authentication attempts
# Dictionary to track failed attempts per IP address: {ip: [(timestamp, count), ...]}
# Format: IP address -> list of (timestamp, attempts_count)
# Each IP can make up to 5 attempts per minute before being temporarily blocked
_auth_failures: Dict[str, list] = {}

# Rate limiting configuration
_MAX_ATTEMPTS_PER_MINUTE = 5  # Maximum failed attempts per minute per IP address
_RATE_LIMIT_WINDOW = 60  # Time window in seconds
_TEMPORARY_BLOCK_DURATION = 300  # How long to temporarily block an IP after exceeding rate limit (in seconds)

def get_rate_limit_config() -> Dict[str, int]:
    """Load rate limiting configuration from environment variables.
    
    Returns:
        Dictionary with rate limiting configuration values.
    """
    config = {
        'max_attempts': int(os.environ.get('API_RATE_LIMIT_MAX_ATTEMPTS', '5')),
        'window_seconds': int(os.environ.get('API_RATE_LIMIT_WINDOW', '60')),
        'block_duration': int(os.environ.get('API_RATE_LIMIT_BLOCK_DURATION', '300'))
    }
    return config

def get_api_keys(config: Any = None) -> Set[str]:
    """Get API keys from config or environment variable.

    Args:
        config: Optional config object with api_keys attribute

    Returns:
        Set of configured API keys
    """
    global _api_keys
    
    # If keys already loaded, return them
    if _api_keys:
        return _api_keys
    
    # Try to get from config object
    if config and hasattr(config, 'api_keys'):
        _api_keys = set(config.api_keys)
        return _api_keys
    
    # Try to get from environment variable
    env_keys = os.environ.get('API_KEYS')
    if env_keys:
        # Support comma-separated keys
        _api_keys = set(key.strip() for key in env_keys.split(','))
    
    return _api_keys

def validate_api_key(api_key: Optional[str], config: Any = None, client_ip: str = 'unknown') -> bool:
    """Validate an API key against the configured keys with rate limiting.

    Args:
        api_key: The API key to validate (from X-API-Key header)
        config: Optional config object for loading keys
        client_ip: Client IP address for rate limiting

    Returns:
        True if API key is valid, False otherwise

    Note:
        API keys are never logged for security reasons.
    """
    if not api_key:
        return False
    
    # SECURITY FIX: Check rate limiting before validating key
    # Check if this IP has exceeded rate limit for failed attempts
    current_time = time.time()
    
    # Load rate limiting configuration from environment variables
    rate_limit_config = get_rate_limit_config()
    
    # Clean up old entries from the failures dictionary
    for ip in list(_auth_failures.keys()):
        # Remove entries older than the rate limit window
        _auth_failures[ip] = [(ts, count) for ts, count in _auth_failures[ip] 
                                   if current_time - ts < rate_limit_config['window_seconds']]
    
    # Check if this IP is currently blocked
    if client_ip in _auth_failures:
        # Get recent attempts within the window
        recent_attempts = [(ts, count) for ts, count in _auth_failures[client_ip] 
                               if current_time - ts < rate_limit_config['window_seconds']]
        
        # If exceeded max attempts, block the request
        total_attempts = sum(count for ts, count in recent_attempts)
        
        if total_attempts >= rate_limit_config['max_attempts']:
            return False
    
    keys = get_api_keys(config)
    
    # If key is valid, reset the failure count for this IP
    if api_key in keys:
        # Remove this IP from failures dictionary on successful auth
        if client_ip in _auth_failures:
            del _auth_failures[client_ip]
        return True
    
    # Key is invalid, record the failure
    # Add this failure to the dictionary
    if client_ip not in _auth_failures:
        _auth_failures[client_ip] = []
        _auth_failures[client_ip].append((current_time, 1))
    else:
        # Get existing failures
        existing_failures = _auth_failures.get(client_ip, [])
        
        # Check if we're still within the temporary block duration
        # Find the most recent failure that's still within the block window
        recent_failures = [(ts, count) for ts, count in existing_failures 
                               if current_time - ts < rate_limit_config['block_duration']]
        
        if recent_failures:
            # Increment the count from the most recent failure
            last_ts, last_count = recent_failures[-1]
            _auth_failures[client_ip] = existing_failures + [(current_time, last_count + 1)]
        else:
            # No recent failures within the block window, can add new entry
            _auth_failures[client_ip] = [(current_time, 1)]
    
    return False

def get_auth_failure_response() -> Dict[str, Any]:
    """Get a standard authentication failure response.

    Returns:
        Dictionary with 401 Unauthorized response data
    """
    return {
        'error': 'Unauthorized',
        'message': 'Valid API key required. Provide a valid API key via the X-API-Key header.'
    }

def get_missing_key_response() -> Dict[str, Any]:
    """Get a response for missing API key configuration.

    Returns:
        Dictionary with error response when no API keys are configured.
    """
    return {
        'error': 'Configuration Error',
        'message': 'No API keys configured. Set API_KEYS environment variable or use --api-keys argument.'
    }

class APIKeyAuth:
    """API Key Authentication helper class.

    This class provides methods for validating API keys from HTTP headers.
    It's designed to work with various HTTP transport implementations.
    """

    def __init__(self, config: Any = None):
        """Initialize an API key authenticator.

        Args:
            config: Optional config object with api_keys attribute

        """
        self.config = config

    def is_authenticated(self, headers: Dict[str, str]) -> bool:
        """Check if a request is authenticated.

        Args:
            headers: Dictionary of HTTP headers

        Returns:
            True if authenticated, False otherwise

        """
        # Headers may be lowercased by some HTTP transports (e.g., stdlib)
        api_key = headers.get('X-API-Key') or headers.get('x-api-key')
        return validate_api_key(api_key, self.config)

    def get_api_key(self, headers: Dict[str, str]) -> Optional[str]:
        """Extract an API key from headers.

        Args:
            headers: Dictionary of HTTP headers

        Returns:
            The API key if present, None otherwise

        Note:
            The API key value is returned but should not be logged.
        """
        # Headers may be lowercased by some HTTP transports (e.g., stdlib)
        return headers.get('X-API-Key') or headers.get('x-api-key')

    def has_keys_configured(self) -> bool:
        """Check if any API keys are configured.

        Returns:
            True if at least one API key is configured, False otherwise

        """
        return len(get_api_keys(self.config)) > 0

    def require_auth(self, headers: Dict[str, str]) -> tuple[bool, Optional[Dict[str, Any]]]:
        """Validate authentication and return status with error response if needed.

        Args:
            headers: Dictionary of HTTP headers

        Returns:
            Tuple of (is_authenticated, error_response)
            - is_authenticated: True if authenticated, False otherwise
            - error_response: None if authenticated, error dict otherwise

        """
        if not self.has_keys_configured():
            return False, get_missing_key_response()

        if not self.is_authenticated(headers):
            return False, get_auth_failure_response()

        return True, None
