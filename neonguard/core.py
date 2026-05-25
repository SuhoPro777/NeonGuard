"""
NeonGuard Core Module
=====================
Main NeonGuard class that ties all features together.
"""

import logging
import threading
from typing import Optional, List, Dict, Any

from neonguard.commands import CommandBlocker
from neonguard.monitoring import ProcessMonitor
from neonguard.rate_limiter import RateLimiter
from neonguard.sandbox import SafeRunner
from neonguard.integrity import FileIntegrityChecker
from neonguard.anomaly import AnomalyDetector

logger = logging.getLogger("neonguard")


class NeonGuard:
    """
    Main NeonGuard security controller.

    Example:
        >>> guard = NeonGuard()
        >>> guard.block_commands(["rm -rf", "shutdown"])
        >>> guard.monitor_processes()
        >>> guard.watch("/etc/passwd")
    """

    def __init__(self, log_level: int = logging.INFO):
        logging.basicConfig(
            level=log_level,
            format="[NeonGuard] %(levelname)s - %(message)s"
        )
        self._command_blocker = CommandBlocker()
        self._process_monitor = ProcessMonitor()
        self._rate_limiter = RateLimiter()
        self._sandbox = SafeRunner()
        self._integrity = FileIntegrityChecker()
        self._anomaly = AnomalyDetector()
        self._monitor_thread: Optional[threading.Thread] = None
        logger.info("NeonGuard v1.0.0 initialized.")

    # ── Command Blocking ──────────────────────────────────────────────────────

    def block_commands(self, commands: List[str]) -> None:
        """Register commands/patterns to block."""
        self._command_blocker.add_patterns(commands)
        logger.info(f"Blocked {len(commands)} command pattern(s).")

    def check_command(self, command: str) -> Dict[str, Any]:
        """
        Check if a command is blocked.

        Returns:
            dict: {'blocked': bool, 'matched_pattern': str|None, 'reason': str}
        """
        return self._command_blocker.check(command)

    # ── Process Monitoring ────────────────────────────────────────────────────

    def monitor_processes(
        self,
        cpu_threshold: float = 90.0,
        ram_threshold_mb: float = 500.0,
        net_threshold_mb: float = 100.0,
        interval: int = 5,
        callback=None
    ) -> None:
        """
        Start background process monitoring.

        Args:
            cpu_threshold: Alert if CPU% exceeds this value.
            ram_threshold_mb: Alert if RAM usage (MB) exceeds this value.
            net_threshold_mb: Alert if network I/O (MB/s) exceeds this value.
            interval: Check interval in seconds.
            callback: Optional callable(alert_dict) for custom handling.
        """
        self._process_monitor.start(
            cpu_threshold=cpu_threshold,
            ram_threshold_mb=ram_threshold_mb,
            net_threshold_mb=net_threshold_mb,
            interval=interval,
            callback=callback,
        )
        logger.info("Process monitoring started.")

    def stop_monitoring(self) -> None:
        """Stop background process monitoring."""
        self._process_monitor.stop()
        logger.info("Process monitoring stopped.")

    def get_process_report(self) -> List[Dict[str, Any]]:
        """Return snapshot of top processes sorted by CPU usage."""
        return self._process_monitor.snapshot()

    # ── Rate Limiting ─────────────────────────────────────────────────────────

    def limit(self, ip: str, rpm: int = 60) -> None:
        """
        Set rate limit for an IP address.

        Args:
            ip: IP address to limit.
            rpm: Max requests per minute allowed.
        """
        self._rate_limiter.set_limit(ip, rpm)
        logger.info(f"Rate limit set: {ip} -> {rpm} req/min")

    def check_rate(self, ip: str) -> Dict[str, Any]:
        """
        Check if an IP has exceeded its rate limit.

        Returns:
            dict: {'allowed': bool, 'remaining': int, 'reset_in': float}
        """
        return self._rate_limiter.check(ip)

    def is_allowed(self, ip: str) -> bool:
        """Quick boolean check — returns False if rate limit exceeded."""
        return self._rate_limiter.check(ip)["allowed"]

    # ── Sandbox ───────────────────────────────────────────────────────────────

    def run_safe(self, code: str) -> Dict[str, Any]:
        """
        Analyze Python code for dangerous patterns before execution.

        Returns:
            dict: {'safe': bool, 'risks': list, 'severity': str}
        """
        return self._sandbox.analyze(code)

    # ── File Integrity ────────────────────────────────────────────────────────

    def watch(self, path: str) -> None:
        """
        Begin watching a file or directory for changes.

        Args:
            path: File or directory path to monitor.
        """
        self._integrity.watch(path)
        logger.info(f"Watching: {path}")

    def check_integrity(self, path: str) -> Dict[str, Any]:
        """
        Check if a watched file has been modified.

        Returns:
            dict: {'changed': bool, 'path': str, 'details': dict}
        """
        return self._integrity.check(path)

    def integrity_report(self) -> List[Dict[str, Any]]:
        """Return integrity status of all watched paths."""
        return self._integrity.report()

    # ── Anomaly Detection ─────────────────────────────────────────────────────

    def record_request(self, ip: str, payload_size: int = 0) -> Dict[str, Any]:
        """
        Record an incoming request for anomaly analysis.

        Args:
            ip: Source IP address.
            payload_size: Request payload size in bytes.

        Returns:
            dict: {'anomaly': bool, 'reasons': list, 'score': float}
        """
        return self._anomaly.record(ip, payload_size)

    def anomaly_report(self) -> Dict[str, Any]:
        """Return full anomaly detection report."""
        return self._anomaly.report()

    # ── Status ────────────────────────────────────────────────────────────────

    def status(self) -> Dict[str, Any]:
        """Return overall NeonGuard status summary."""
        return {
            "version": "1.0.0",
            "blocked_patterns": self._command_blocker.pattern_count(),
            "watched_paths": self._integrity.watched_count(),
            "rate_limited_ips": self._rate_limiter.limited_count(),
            "monitoring_active": self._process_monitor.is_running(),
            "anomaly_ips_tracked": self._anomaly.tracked_count(),
        }
