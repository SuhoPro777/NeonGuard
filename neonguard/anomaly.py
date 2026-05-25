"""
NeonGuard Anomaly Detector
===========================
Detects unusual traffic and behavioral patterns:
- Sudden request spikes
- Unusual IP activity
- Oversized payloads
- Geographic impossibility (Pro)
"""

import time
import logging
import threading
from collections import deque
from typing import Dict, Any, List, Deque

logger = logging.getLogger("neonguard.anomaly")

# Thresholds
_SPIKE_WINDOW_SECONDS = 60
_SPIKE_THRESHOLD = 1000       # requests in window = anomaly
_PAYLOAD_THRESHOLD_BYTES = 1_000_000  # 1 MB
_BURST_WINDOW_SECONDS = 5
_BURST_THRESHOLD = 100        # requests in 5 seconds = burst


class AnomalyDetector:
    """
    Statistical anomaly detection for incoming requests.

    Tracks per-IP request rates and payload sizes.
    Flags unusual patterns like sudden spikes, large payloads,
    and rapid bursts.

    Example:
        >>> detector = AnomalyDetector()
        >>> result = detector.record("192.168.1.1", payload_size=500)
        >>> print(result['anomaly'])  # False
        >>> result = detector.record("10.0.0.1", payload_size=2_000_000)
        >>> print(result['anomaly'])  # True
    """

    def __init__(self):
        self._lock = threading.Lock()
        # IP -> deque of (timestamp, payload_size)
        self._requests: Dict[str, Deque] = {}
        self._anomalies: List[Dict[str, Any]] = []

    def record(self, ip: str, payload_size: int = 0) -> Dict[str, Any]:
        """
        Record a request and check for anomalies.

        Args:
            ip: Source IP address.
            payload_size: Request payload size in bytes.

        Returns:
            {
                'anomaly': bool,
                'reasons': list,
                'score': float,
                'ip': str,
            }
        """
        now = time.time()

        with self._lock:
            if ip not in self._requests:
                self._requests[ip] = deque()

            queue = self._requests[ip]
            queue.append((now, payload_size))

            # Prune entries older than the spike window
            cutoff = now - _SPIKE_WINDOW_SECONDS
            while queue and queue[0][0] < cutoff:
                queue.popleft()

        reasons = []
        score = 0.0

        # Check request count in spike window
        with self._lock:
            window_requests = list(self._requests.get(ip, []))

        total_in_window = len(window_requests)
        if total_in_window > _SPIKE_THRESHOLD:
            reasons.append(
                f"Request spike: {total_in_window} requests in {_SPIKE_WINDOW_SECONDS}s "
                f"(threshold: {_SPIKE_THRESHOLD})"
            )
            score += 8.0

        # Check burst in short window
        burst_cutoff = now - _BURST_WINDOW_SECONDS
        burst_count = sum(1 for ts, _ in window_requests if ts >= burst_cutoff)
        if burst_count > _BURST_THRESHOLD:
            reasons.append(
                f"Traffic burst: {burst_count} requests in {_BURST_WINDOW_SECONDS}s "
                f"(threshold: {_BURST_THRESHOLD})"
            )
            score += 6.0

        # Check payload size
        if payload_size > _PAYLOAD_THRESHOLD_BYTES:
            mb = payload_size / (1024 * 1024)
            reasons.append(f"Oversized payload: {mb:.1f} MB (threshold: 1 MB)")
            score += 5.0

        # Check for completely new IP that immediately sends large payloads
        if total_in_window == 1 and payload_size > 500_000:
            reasons.append("New IP with large first payload (suspicious)")
            score += 3.0

        anomaly = len(reasons) > 0

        if anomaly:
            alert = {
                "ip": ip,
                "anomaly": True,
                "reasons": reasons,
                "score": score,
                "timestamp": now,
            }
            with self._lock:
                self._anomalies.append(alert)
                if len(self._anomalies) > 5000:
                    self._anomalies = self._anomalies[-5000:]

            logger.warning(f"Anomaly detected from {ip}: {reasons}")
            return alert

        return {"ip": ip, "anomaly": False, "reasons": [], "score": 0.0}

    def report(self) -> Dict[str, Any]:
        """Return full anomaly report."""
        with self._lock:
            anomaly_ips = list(set(a["ip"] for a in self._anomalies))
            return {
                "total_anomalies": len(self._anomalies),
                "unique_anomaly_ips": len(anomaly_ips),
                "top_offenders": self._top_offenders(),
                "recent_anomalies": self._anomalies[-20:],
            }

    def _top_offenders(self) -> List[Dict]:
        counts: Dict[str, int] = {}
        for a in self._anomalies:
            counts[a["ip"]] = counts.get(a["ip"], 0) + 1
        sorted_ips = sorted(counts.items(), key=lambda x: x[1], reverse=True)
        return [{"ip": ip, "count": c} for ip, c in sorted_ips[:10]]

    def tracked_count(self) -> int:
        return len(self._requests)
