"""
NeonGuard File Integrity Checker
=================================
Watches files and directories for unauthorized changes using SHA-256 hashing.
"""

import hashlib
import os
import logging
import time
from typing import Dict, Any, List, Optional

logger = logging.getLogger("neonguard.integrity")


class FileIntegrityChecker:
    """
    File integrity monitoring using SHA-256 checksums.

    Example:
        >>> checker = FileIntegrityChecker()
        >>> checker.watch("/etc/passwd")
        >>> checker.watch("/app/config.json")
        >>> report = checker.report()
    """

    def __init__(self):
        self._watched: Dict[str, "_WatchEntry"] = {}

    def watch(self, path: str) -> None:
        """
        Start watching a file or directory.

        Args:
            path: Absolute or relative path to watch.
        """
        path = os.path.abspath(path)
        if not os.path.exists(path):
            logger.warning(f"Path does not exist (will watch when created): {path}")
            self._watched[path] = _WatchEntry(path, baseline=None)
            return

        entry = _WatchEntry(path)
        self._watched[path] = entry
        logger.info(f"Watching: {path} [sha256: {entry.baseline[:12]}...]" if entry.baseline else f"Watching: {path}")

    def unwatch(self, path: str) -> None:
        """Stop watching a path."""
        path = os.path.abspath(path)
        self._watched.pop(path, None)

    def check(self, path: str) -> Dict[str, Any]:
        """
        Check if a watched path has changed.

        Returns:
            {
                'changed': bool,
                'path': str,
                'baseline_hash': str | None,
                'current_hash': str | None,
                'details': dict,
            }
        """
        path = os.path.abspath(path)
        if path not in self._watched:
            return {"changed": False, "path": path, "error": "Path not being watched."}

        entry = self._watched[path]
        return entry.check()

    def report(self) -> List[Dict[str, Any]]:
        """Return integrity status of all watched paths."""
        return [entry.check() for entry in self._watched.values()]

    def update_baseline(self, path: str) -> None:
        """Update the baseline hash for a path (after approved change)."""
        path = os.path.abspath(path)
        if path in self._watched:
            self._watched[path].update_baseline()
            logger.info(f"Baseline updated: {path}")

    def watched_count(self) -> int:
        return len(self._watched)


class _WatchEntry:
    def __init__(self, path: str, baseline: Optional[str] = ...):
        self.path = path
        self.watched_at = time.time()

        if baseline is ...:
            self.baseline = self._compute_hash()
        else:
            self.baseline = baseline

    def _compute_hash(self) -> Optional[str]:
        if not os.path.exists(self.path):
            return None

        sha256 = hashlib.sha256()

        if os.path.isfile(self.path):
            try:
                with open(self.path, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        sha256.update(chunk)
                return sha256.hexdigest()
            except (PermissionError, OSError) as e:
                logger.warning(f"Cannot hash {self.path}: {e}")
                return None

        elif os.path.isdir(self.path):
            # Hash all files in directory recursively
            for root, _, files in sorted(os.walk(self.path)):
                for fname in sorted(files):
                    fpath = os.path.join(root, fname)
                    try:
                        sha256.update(fpath.encode())
                        with open(fpath, "rb") as f:
                            for chunk in iter(lambda: f.read(65536), b""):
                                sha256.update(chunk)
                    except (PermissionError, OSError):
                        continue
            return sha256.hexdigest()

        return None

    def check(self) -> Dict[str, Any]:
        current = self._compute_hash()
        exists = os.path.exists(self.path)
        changed = (current != self.baseline)

        details = {}
        if not exists:
            details["status"] = "deleted"
        elif self.baseline is None and current is not None:
            details["status"] = "created"
        elif changed:
            details["status"] = "modified"
        else:
            details["status"] = "unchanged"

        # File metadata
        if exists and os.path.isfile(self.path):
            stat = os.stat(self.path)
            details["size_bytes"] = stat.st_size
            details["modified_time"] = stat.st_mtime

        return {
            "changed": changed,
            "path": self.path,
            "baseline_hash": self.baseline,
            "current_hash": current,
            "details": details,
        }

    def update_baseline(self) -> None:
        self.baseline = self._compute_hash()
