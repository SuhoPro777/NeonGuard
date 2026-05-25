"""
NeonGuard Command Blocker
=========================
Blocks dangerous shell commands using pattern matching and heuristic analysis.
Not just a simple blacklist — uses regex patterns and danger scoring.
"""

import re
import logging
import shlex
from typing import List, Dict, Any, Optional

logger = logging.getLogger("neonguard.commands")

# Built-in dangerous patterns (pattern, description, severity)
_BUILTIN_PATTERNS = [
    # Destructive filesystem
    (r"rm\s+(-\S*r\S*|-\S*f\S*|\s).*(/|~|\*|\$HOME)", "Recursive/force remove", "critical"),
    (r"rm\s+.*-rf", "rm -rf variant", "critical"),
    (r"mkfs\b", "Filesystem format", "critical"),
    (r"dd\s+.*of=/dev/", "Raw disk write", "critical"),
    (r"shred\b", "Secure file delete", "high"),
    (r"> /dev/s[d-z]", "Overwrite disk device", "critical"),

    # System control
    (r"\bshutdown\b", "System shutdown", "critical"),
    (r"\breboot\b", "System reboot", "critical"),
    (r"\bhalt\b", "System halt", "critical"),
    (r"\bpoweroff\b", "System power off", "critical"),
    (r"\binit\s+[06]\b", "Init runlevel 0/6", "critical"),

    # Fork bomb / resource exhaustion
    (r":\(\)\s*\{.*:\|:.*\}", "Fork bomb", "critical"),
    (r"forkbomb", "Fork bomb keyword", "critical"),
    (r"while\s*true.*do.*done", "Infinite loop in shell", "high"),

    # Privilege escalation
    (r"\bsudo\s+su\b", "Sudo su escalation", "high"),
    (r"\bchmod\s+777\b", "World-writable chmod", "medium"),
    (r"\bchown\s+root\b", "Change ownership to root", "high"),
    (r"\bpasswd\b", "Password change", "medium"),

    # Network exfiltration
    (r"curl\s+.*\|\s*bash", "Curl pipe to bash", "critical"),
    (r"wget\s+.*\|\s*bash", "Wget pipe to bash", "critical"),
    (r"curl\s+.*\|\s*sh", "Curl pipe to sh", "critical"),
    (r"nc\s+-[le]", "Netcat listener/execute", "high"),
    (r"\bncat\b.*-e", "Ncat execute", "high"),

    # Python/code execution tricks
    (r"exec\(.*base64", "Base64 exec", "critical"),
    (r"eval\(.*base64", "Base64 eval", "critical"),
    (r"__import__\(['\"]os['\"]", "Dynamic OS import", "high"),
    (r"subprocess\.(call|run|Popen).*shell=True", "Shell subprocess", "high"),

    # Cron / persistence
    (r"crontab\s+-[re]", "Cron modification", "high"),
    (r"@reboot", "Cron reboot persistence", "high"),

    # Crypto mining
    (r"\bxmrig\b|\bminerd\b|\bcpuminer\b", "Crypto miner", "critical"),
    (r"stratum\+tcp://", "Mining pool connection", "high"),
]

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "safe": 0}


def block_commands(commands: List[str]) -> "CommandBlocker":
    """
    Module-level convenience function to create and configure a CommandBlocker.

    Example:
        >>> import neonguard
        >>> neonguard.block_commands(["rm -rf", "shutdown", "forkbomb"])
    """
    blocker = CommandBlocker()
    blocker.add_patterns(commands)
    return blocker


class CommandBlocker:
    """
    Advanced command security checker with pattern analysis.

    Features:
        - Built-in dangerous pattern library
        - Custom user-defined patterns
        - Heuristic danger scoring
        - Command tokenization for bypass detection
    """

    def __init__(self, use_builtins: bool = True):
        self._patterns: List[Dict[str, Any]] = []
        self._custom_literals: List[str] = []

        if use_builtins:
            for pattern, desc, severity in _BUILTIN_PATTERNS:
                self._patterns.append({
                    "regex": re.compile(pattern, re.IGNORECASE | re.DOTALL),
                    "description": desc,
                    "severity": severity,
                    "pattern": pattern,
                })

    def add_patterns(self, items: List[str]) -> None:
        """
        Add custom block patterns (string literals or regex).

        Args:
            items: List of strings. Each is treated as a substring match
                   AND compiled as a regex if valid.
        """
        for item in items:
            self._custom_literals.append(item.lower())
            try:
                compiled = re.compile(re.escape(item), re.IGNORECASE)
                self._patterns.append({
                    "regex": compiled,
                    "description": f"Custom block: {item}",
                    "severity": "high",
                    "pattern": item,
                })
            except re.error:
                logger.warning(f"Could not compile pattern: {item!r}")

    def check(self, command: str) -> Dict[str, Any]:
        """
        Analyze a command string for dangerous patterns.

        Returns:
            {
                'blocked': bool,
                'matched_pattern': str | None,
                'description': str | None,
                'severity': str,
                'score': int,
                'all_matches': list
            }
        """
        if not command or not command.strip():
            return self._safe_result()

        normalized = self._normalize(command)
        matches = []

        for p in self._patterns:
            if p["regex"].search(normalized):
                matches.append(p)

        # Also check tokenized form to detect bypass attempts like "r''m -rf"
        tokenized = self._tokenize(command)
        for literal in self._custom_literals:
            if literal in tokenized:
                # Avoid duplicates
                already = any(m["description"] == f"Custom block: {literal}" for m in matches)
                if not already:
                    matches.append({
                        "pattern": literal,
                        "description": f"Custom block (tokenized): {literal}",
                        "severity": "high",
                    })

        if not matches:
            return self._safe_result()

        top = max(matches, key=lambda m: _SEVERITY_ORDER.get(m["severity"], 0))
        score = sum(_SEVERITY_ORDER.get(m["severity"], 0) for m in matches)

        return {
            "blocked": True,
            "matched_pattern": top["pattern"],
            "description": top["description"],
            "severity": top["severity"],
            "score": score,
            "all_matches": [
                {"pattern": m["pattern"], "description": m["description"], "severity": m["severity"]}
                for m in matches
            ],
        }

    def pattern_count(self) -> int:
        return len(self._patterns)

    def _normalize(self, cmd: str) -> str:
        """Collapse whitespace, remove common obfuscation."""
        cmd = re.sub(r"\s+", " ", cmd)
        # Remove common quote obfuscation: r''m -> rm
        cmd = re.sub(r"['\"](['\"])", "", cmd)
        return cmd.strip()

    def _tokenize(self, cmd: str) -> str:
        """Join all tokens for substring matching."""
        try:
            tokens = shlex.split(cmd)
            return " ".join(tokens).lower()
        except ValueError:
            return cmd.lower()

    @staticmethod
    def _safe_result() -> Dict[str, Any]:
        return {
            "blocked": False,
            "matched_pattern": None,
            "description": None,
            "severity": "safe",
            "score": 0,
            "all_matches": [],
        }
