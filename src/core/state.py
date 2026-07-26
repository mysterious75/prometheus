"""State Persistence — checkpoint & journal for resumable scans.

Provides JSON checkpoints for quick resume and JSONL journal for
full execution history (append-only, crash-safe).
"""

import json
import time
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path
from datetime import datetime, timedelta

from src.core.logger import logger


class ScanState:
    """Persistent scan state — enables resume from checkpoint.

    Uses two files:
    - state.json:  Latest checkpoint (overwritten each save)
    - journal.jsonl: Append-only execution log (crash-safe)
    """

    def __init__(self, scan_id: str, state_dir: str = None):
        self.scan_id = scan_id
        self.state_dir = Path(state_dir or "data/scans") / scan_id
        self.state_file = self.state_dir / "state.json"
        self.journal_file = self.state_dir / "journal.jsonl"
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        """Create state directory if it doesn't exist."""
        self.state_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Checkpoint
    # ------------------------------------------------------------------

    def save_checkpoint(self, stage: str, data: Dict) -> None:
        """Save current scan state to disk (overwrites previous checkpoint).

        Args:
            stage: Current scan stage (e.g., 'recon', 'scanning', 'validation')
            data: Arbitrary state data to persist
        """
        checkpoint = {
            "scan_id": self.scan_id,
            "stage": stage,
            "timestamp": datetime.now().isoformat(),
            "epoch": time.time(),
            "data": data,
        }
        try:
            self.state_file.write_text(json.dumps(checkpoint, indent=2, default=str))
            self.append_journal({
                "event": "checkpoint",
                "stage": stage,
                "summary": {k: str(v)[:100] for k, v in data.items()},
            })
            logger.debug(f"Checkpoint saved: {stage}")
        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}")

    def load_checkpoint(self) -> Optional[Dict]:
        """Load last checkpoint from disk."""
        if not self.state_file.exists():
            return None
        try:
            return json.loads(self.state_file.read_text())
        except Exception as e:
            logger.error(f"Failed to load checkpoint: {e}")
            return None

    # ------------------------------------------------------------------
    # Journal (append-only JSONL)
    # ------------------------------------------------------------------

    def append_journal(self, entry: Dict) -> None:
        """Append an entry to the execution journal.

        Each line is a standalone JSON object — safe for concurrent
        append and crash recovery.
        """
        entry.setdefault("timestamp", datetime.now().isoformat())
        entry.setdefault("scan_id", self.scan_id)
        try:
            with open(self.journal_file, "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except Exception as e:
            logger.error(f"Failed to write journal entry: {e}")

    def get_journal(self) -> List[Dict]:
        """Read the full execution journal."""
        if not self.journal_file.exists():
            return []
        entries = []
        try:
            for line in self.journal_file.read_text().splitlines():
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        except Exception as e:
            logger.error(f"Failed to read journal: {e}")
        return entries

    # ------------------------------------------------------------------
    # Resume
    # ------------------------------------------------------------------

    def can_resume(self) -> bool:
        """Check if a previous scan can be resumed."""
        cp = self.load_checkpoint()
        if not cp:
            return False
        stage = cp.get("stage", "")
        # Cannot resume if already completed or cleaned up
        return stage not in ("completed", "aborted", "cleaned_up")

    def resume(self) -> Dict:
        """Resume scan from last checkpoint.

        Returns the checkpoint data, or empty dict if none available.
        """
        cp = self.load_checkpoint()
        if not cp:
            logger.warning(f"No checkpoint found for scan {self.scan_id}")
            return {}

        self.append_journal({
            "event": "resume",
            "stage": cp.get("stage"),
            "from_checkpoint": True,
        })
        logger.info(f"Resuming scan {self.scan_id} from stage: {cp.get('stage')}")
        return cp.get("data", {})

    def mark_completed(self, summary: Dict = None) -> None:
        """Mark scan as completed."""
        self.save_checkpoint("completed", summary or {})
        self.append_journal({"event": "completed", "summary": summary or {}})

    def mark_aborted(self, reason: str = "") -> None:
        """Mark scan as aborted."""
        self.save_checkpoint("aborted", {"reason": reason})
        self.append_journal({"event": "aborted", "reason": reason})

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup(self, keep_days: int = 7) -> None:
        """Clean up scan data older than keep_days.

        Removes the state directory if the checkpoint is old enough.
        """
        cp = self.load_checkpoint()
        if not cp:
            return

        try:
            cp_time = datetime.fromisoformat(cp.get("timestamp", ""))
            if datetime.now() - cp_time > timedelta(days=keep_days):
                import shutil
                shutil.rmtree(self.state_dir, ignore_errors=True)
                logger.info(f"Cleaned up scan {self.scan_id} (older than {keep_days}d)")
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

    @staticmethod
    def cleanup_all(state_dir: str = "data/scans", keep_days: int = 7) -> int:
        """Clean up all old scan directories. Returns count of removed scans."""
        base = Path(state_dir)
        if not base.exists():
            return 0

        removed = 0
        cutoff = datetime.now() - timedelta(days=keep_days)
        for scan_dir in base.iterdir():
            if not scan_dir.is_dir():
                continue
            state_file = scan_dir / "state.json"
            if not state_file.exists():
                continue
            try:
                cp = json.loads(state_file.read_text())
                cp_time = datetime.fromisoformat(cp.get("timestamp", ""))
                if cp_time < cutoff:
                    import shutil
                    shutil.rmtree(scan_dir, ignore_errors=True)
                    removed += 1
            except Exception:
                pass
        return removed

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        cp = self.load_checkpoint()
        stage = cp.get("stage", "none") if cp else "none"
        return f"ScanState(id={self.scan_id}, stage={stage})"
