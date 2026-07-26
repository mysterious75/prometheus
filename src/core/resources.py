"""Resource Monitor — system resource monitoring during scans.

Monitors CPU, memory, and disk usage to prevent scans from
overwhelming the host system. Provides throttling recommendations.
"""

import os
import logging
from typing import Dict, Optional

from src.core.logger import logger

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


class ResourceMonitor:
    """Monitors system resources during scans.

    Thresholds:
    - CPU    > 90% → throttle
    - Memory > 85% → throttle
    - Disk   > 95% → throttle
    """

    CPU_THROTTLE = 90.0
    MEM_THROTTLE = 85.0
    DISK_THROTTLE = 95.0

    def __init__(self):
        self._last_check: Optional[Dict] = None

    def check_resources(self) -> Dict:
        """Check CPU, memory, disk usage.

        Uses psutil if available, falls back to /proc on Linux.
        Returns dict with cpu_percent, memory_percent, disk_percent,
        memory_available_gb, and raw details.
        """
        result = {
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "memory_available_gb": 0.0,
            "disk_percent": 0.0,
            "source": "unknown",
        }

        if HAS_PSUTIL:
            result.update(self._check_psutil())
        else:
            result.update(self._check_proc())

        self._last_check = result
        return result

    def should_throttle(self) -> bool:
        """Should we slow down scanning?

        Returns True if any resource exceeds throttle threshold.
        """
        res = self.check_resources()
        return (
            res["cpu_percent"] > self.CPU_THROTTLE
            or res["memory_percent"] > self.MEM_THROTTLE
            or res["disk_percent"] > self.DISK_THROTTLE
        )

    def get_safe_thread_count(self) -> int:
        """How many concurrent scans are safe?

        Base calculation on available CPU cores and memory headroom.
        """
        res = self.check_resources()

        if HAS_PSUTIL:
            cpu_count = psutil.cpu_count(logical=True) or 2
        else:
            cpu_count = os.cpu_count() or 2

        # Start with half the cores
        threads = max(1, cpu_count // 2)

        # Reduce if resources are tight
        if res["cpu_percent"] > 70:
            threads = max(1, threads // 2)
        if res["memory_percent"] > 70:
            threads = max(1, threads // 2)
        if res["memory_available_gb"] < 1.0:
            threads = 1

        return threads

    def warn_if_low(self) -> Optional[str]:
        """Return a warning message if resources are critically low.

        Returns None if everything is fine.
        """
        res = self.check_resources()
        warnings = []

        if res["cpu_percent"] > self.CPU_THROTTLE:
            warnings.append(f"CPU at {res['cpu_percent']:.1f}% (>{self.CPU_THROTTLE}%)")
        if res["memory_percent"] > self.MEM_THROTTLE:
            warnings.append(f"Memory at {res['memory_percent']:.1f}% (>{self.MEM_THROTTLE}%)")
        if res["disk_percent"] > self.DISK_THROTTLE:
            warnings.append(f"Disk at {res['disk_percent']:.1f}% (>{self.DISK_THROTTLE}%)")

        if warnings:
            msg = "⚠️  Resource warnings: " + " | ".join(warnings)
            logger.warning(msg)
            return msg
        return None

    # ------------------------------------------------------------------
    # psutil backend
    # ------------------------------------------------------------------

    @staticmethod
    def _check_psutil() -> Dict:
        """Resource check via psutil."""
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        return {
            "cpu_percent": cpu,
            "memory_percent": mem.percent,
            "memory_available_gb": round(mem.available / (1024 ** 3), 2),
            "disk_percent": disk.percent,
            "source": "psutil",
        }

    # ------------------------------------------------------------------
    # /proc fallback (Linux only)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_proc() -> Dict:
        """Resource check via /proc (Linux fallback)."""
        result = {
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "memory_available_gb": 0.0,
            "disk_percent": 0.0,
            "source": "proc",
        }

        # CPU: parse /proc/stat for instantaneous usage
        try:
            with open("/proc/stat") as f:
                line = f.readline()
            parts = line.split()[1:]
            values = [int(v) for v in parts]
            idle = values[3] if len(values) > 3 else 0
            total = sum(values)
            # This is cumulative, so we can only estimate
            busy = total - idle
            result["cpu_percent"] = round(busy / max(total, 1) * 100, 1)
        except Exception:
            pass

        # Memory: parse /proc/meminfo
        try:
            meminfo = {}
            with open("/proc/meminfo") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip().split()[0]
                        meminfo[key] = int(val)

            total = meminfo.get("MemTotal", 0)
            available = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
            if total > 0:
                result["memory_percent"] = round((total - available) / total * 100, 1)
                result["memory_available_gb"] = round(available / (1024 ** 2), 2)
        except Exception:
            pass

        # Disk: use os.statvfs
        try:
            st = os.statvfs("/")
            total = st.f_blocks * st.f_frsize
            free = st.f_bavail * st.f_frsize
            if total > 0:
                result["disk_percent"] = round((total - free) / total * 100, 1)
        except Exception:
            pass

        return result
