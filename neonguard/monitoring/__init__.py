"""
NeonGuard Process Monitor
=========================
Real-time monitoring of CPU, RAM, and network usage per process.
"""

import threading
import logging
import time
from typing import List, Dict, Any, Optional, Callable

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False

logger = logging.getLogger("neonguard.monitoring")


class ProcessMonitor:
    """
    Background process monitor that alerts on resource abuse.

    Monitors:
        - CPU usage above threshold
        - RAM usage above threshold
        - Network I/O rate above threshold
    """

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._alerts: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._net_baseline: Optional[Dict] = None

    def start(
        self,
        cpu_threshold: float = 90.0,
        ram_threshold_mb: float = 500.0,
        net_threshold_mb: float = 100.0,
        interval: int = 5,
        callback: Optional[Callable] = None,
    ) -> None:
        if not _PSUTIL_AVAILABLE:
            logger.error("psutil not installed. Run: pip install psutil")
            return

        if self._running:
            logger.warning("Monitor already running.")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            args=(cpu_threshold, ram_threshold_mb, net_threshold_mb, interval, callback),
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("Process monitor stopped.")

    def is_running(self) -> bool:
        return self._running

    def snapshot(self) -> List[Dict[str, Any]]:
        """Return top 10 processes sorted by CPU usage."""
        if not _PSUTIL_AVAILABLE:
            return []

        results = []
        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "status"]):
            try:
                info = proc.info
                ram_mb = info["memory_info"].rss / (1024 * 1024) if info["memory_info"] else 0
                results.append({
                    "pid": info["pid"],
                    "name": info["name"],
                    "cpu_percent": info["cpu_percent"] or 0.0,
                    "ram_mb": round(ram_mb, 2),
                    "status": info["status"],
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        results.sort(key=lambda x: x["cpu_percent"], reverse=True)
        return results[:10]

    def get_alerts(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._alerts)

    def _monitor_loop(
        self,
        cpu_threshold: float,
        ram_threshold_mb: float,
        net_threshold_mb: float,
        interval: int,
        callback: Optional[Callable],
    ) -> None:
        # Initialize network baseline
        self._net_baseline = psutil.net_io_counters(pernic=False)
        prev_net = self._net_baseline
        prev_time = time.time()

        while self._running:
            time.sleep(interval)
            now = time.time()
            elapsed = now - prev_time

            alerts = []

            # Network rate check
            try:
                curr_net = psutil.net_io_counters(pernic=False)
                sent_mb = (curr_net.bytes_sent - prev_net.bytes_sent) / (1024 * 1024 * elapsed)
                recv_mb = (curr_net.bytes_recv - prev_net.bytes_recv) / (1024 * 1024 * elapsed)

                if sent_mb > net_threshold_mb or recv_mb > net_threshold_mb:
                    alert = {
                        "type": "network",
                        "send_mbps": round(sent_mb, 2),
                        "recv_mbps": round(recv_mb, 2),
                        "threshold_mb": net_threshold_mb,
                        "timestamp": now,
                    }
                    alerts.append(alert)
                    logger.warning(
                        f"High network usage: sent={sent_mb:.1f}MB/s recv={recv_mb:.1f}MB/s"
                    )

                prev_net = curr_net
                prev_time = now
            except Exception as e:
                logger.debug(f"Network check error: {e}")

            # Per-process CPU & RAM check
            for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
                try:
                    cpu = proc.info["cpu_percent"] or 0.0
                    ram_mb = proc.info["memory_info"].rss / (1024 * 1024) if proc.info["memory_info"] else 0

                    if cpu > cpu_threshold:
                        alert = {
                            "type": "cpu",
                            "pid": proc.info["pid"],
                            "name": proc.info["name"],
                            "cpu_percent": cpu,
                            "threshold": cpu_threshold,
                            "timestamp": now,
                        }
                        alerts.append(alert)
                        logger.warning(
                            f"High CPU: {proc.info['name']} (PID {proc.info['pid']}) = {cpu:.1f}%"
                        )

                    if ram_mb > ram_threshold_mb:
                        alert = {
                            "type": "ram",
                            "pid": proc.info["pid"],
                            "name": proc.info["name"],
                            "ram_mb": round(ram_mb, 2),
                            "threshold_mb": ram_threshold_mb,
                            "timestamp": now,
                        }
                        alerts.append(alert)
                        logger.warning(
                            f"High RAM: {proc.info['name']} (PID {proc.info['pid']}) = {ram_mb:.1f}MB"
                        )

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if alerts:
                with self._lock:
                    self._alerts.extend(alerts)
                    # Keep last 1000 alerts
                    if len(self._alerts) > 1000:
                        self._alerts = self._alerts[-1000:]

                if callback:
                    try:
                        for alert in alerts:
                            callback(alert)
                    except Exception as e:
                        logger.error(f"Monitor callback error: {e}")
