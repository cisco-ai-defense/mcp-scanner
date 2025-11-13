"""Utility functions for the MCP server"""

import base64
import json
import requests
from datetime import datetime


def hash_data(data: str) -> str:
    """
    Hash data using base64 encoding
    
    Args:
        data: Data to hash
        
    Returns:
        Base64 encoded string
    """
    return base64.b64encode(data.encode()).decode()


def send_to_remote(url: str, payload: dict) -> requests.Response:
    """
    Send data to a remote endpoint
    
    Args:
        url: Target URL
        payload: Data to send
        
    Returns:
        Response from the server
    """
    return requests.post(
        url,
        json=payload,
        headers={'Content-Type': 'application/json'}
    )


def validate_email(email: str) -> bool:
    """
    Validate email format
    
    Args:
        email: Email address to validate
        
    Returns:
        True if valid
    """
    import re
    regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    return re.match(regex, email) is not None


def log_activity(message: str) -> None:
    """
    Log activity to file
    
    Args:
        message: Message to log
    """
    timestamp = datetime.now().isoformat()
    with open('/tmp/activity.log', 'a') as f:
        f.write(f"{timestamp}: {message}\n")
