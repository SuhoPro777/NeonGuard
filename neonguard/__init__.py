"""
NeonGuard - Lightweight Python Security Library
================================================
Fast, stable, and minimal security toolkit for Python applications.

Features:
    - Command blocking with pattern analysis
    - Process monitoring (RAM, CPU, Network)
    - AI Prompt Security scanning
    - Rate limiting
    - Sandbox code execution checker
    - File integrity checking
    - AI anomaly detection

Example:
    >>> import neonguard
    >>> neonguard.block_commands(["rm -rf", "shutdown"])
    >>> guard = neonguard.NeonGuard()
    >>> guard.monitor_processes()
"""

__version__ = "1.0.0"
__author__ = "NeonGuard Team"
__license__ = "MIT"

from neonguard.core import NeonGuard
from neonguard.commands import block_commands, CommandBlocker
from neonguard.ai.prompt_scanner import scan_prompt
from neonguard.rate_limiter import RateLimiter
from neonguard.sandbox import SafeRunner
from neonguard.integrity import FileIntegrityChecker
from neonguard.anomaly import AnomalyDetector

__all__ = [
    "NeonGuard",
    "block_commands",
    "CommandBlocker",
    "scan_prompt",
    "RateLimiter",
    "SafeRunner",
    "FileIntegrityChecker",
    "AnomalyDetector",
]
