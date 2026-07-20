"""Memory Consolidation - Automatic compression and importance filtering."""

from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from ..episodic import EpisodicMemory
from ...brain.router import ModelRouter
from ...utils.logger import logger


class MemoryConsolidator:
    """Consolidates episodic memories into long-term storage automatically."""

    # Importance threshold: memories below this get compressed/merged
    LOW_IMPORTANCE = 0.3
    # Memories above this threshold are preserved verbatim
    HIGH_IMPORTANCE = 0.7
    # Maximum memories to keep in short-term buffer
    SHORT_TERM_LIMIT = 100

    def __init__(self, router: ModelRouter, episodic_memory: EpisodicMemory):
        self.router = router
        self.episodic = episodic_memory
        self.consolidation_log: List[Dict] = []
        self.long_term_store: List[Dict] = []  # compressed summaries

    def consolidate(self) -> Dict[str, Any]:
        """Run memory consolidation - compress low-importance, preserve high-importance."""
        logger.info("[bold magenta]Starting memory consolidation...[/bold magenta]")

        all_memories = self.episodic.get_recent(self.SHORT_TERM_LIMIT * 2)
        if not all_memories:
            return {"status": "no_memories", "processed": 0}

        high_importance = []
        low_importance = []

        for mem in all_memories:
            importance = mem.get("metadata", {}).get("importance", 0.5)
            if importance >= self.HIGH_IMPORTANCE:
                high_importance.append(mem)
            elif importance <= self.LOW_IMPORTANCE:
                low_importance.append(mem)
            else:
                # Medium importance: keep but compress later
                high_importance.append(mem)

        # Compress low-importance memories into summaries
        compressed = []
        if low_importance:
            compressed = self._compress_memories(low_importance)

        # Preserve high-importance memories as-is
        preserved = []
        for mem in high_importance:
            preserved.append({
                "content": mem.get("content", ""),
                "metadata": mem.get("metadata", {}),
                "status": "preserved",
                "consolidated_at": datetime.now().isoformat()
            })

        # Store consolidated results
        self.long_term_store.extend(preserved)
        self.long_term_store.extend(compressed)

        # Remove old low-importance memories from episodic store
        removed = len(low_importance) - len(compressed)

        result = {
            "timestamp": datetime.now().isoformat(),
            "total_processed": len(all_memories),
            "preserved": len(preserved),
            "compressed": len(compressed),
            "removed": removed,
            "long_term_total": len(self.long_term_store)
        }

        self.consolidation_log.append(result)
        logger.info(f"[green]Consolidation complete: {len(preserved)} preserved, {len(compressed)} compressed[/green]")
        return result

    def _compress_memories(self, memories: List[Dict]) -> List[Dict]:
        """Compress multiple low-importance memories into concise summaries."""
        if not memories:
            return []

        # Group memories in chunks of 5 for efficient compression
        chunk_size = 5
        compressed = []

        for i in range(0, len(memories), chunk_size):
            chunk = memories[i:i + chunk_size]
            memories_text = "\n".join([
                f"- {m.get('content', 'Unknown')} (type: {m.get('metadata', {}).get('type', 'general')})"
                for m in chunk
            ])

            prompt = f"""
            Compress these memories into a single concise summary that captures the essential information.
            Remove redundant details, keep key facts and insights.

            Memories:
            {memories_text}

            Return ONLY the compressed summary (2-3 sentences max).
            """

            try:
                summary = self.router.generate(prompt)
                compressed.append({
                    "content": summary,
                    "metadata": {
                        "type": "compressed_summary",
                        "original_count": len(chunk),
                        "importance": 0.5,
                        "compressed_at": datetime.now().isoformat()
                    },
                    "status": "compressed"
                })
            except Exception as e:
                logger.warning(f"Compression failed for chunk: {e}")
                # Keep originals if compression fails
                for m in chunk:
                    compressed.append({
                        "content": m.get("content", ""),
                        "metadata": m.get("metadata", {}),
                        "status": "kept_original"
                    })

        return compressed

    def recall_long_term(self, query: str, n: int = 5) -> List[Dict]:
        """Search long-term consolidated memories."""
        results = []
        query_lower = query.lower()

        for memory in self.long_term_store:
            content = memory.get("content", "").lower()
            # Simple keyword matching (can be enhanced with embeddings)
            if any(word in content for word in query_lower.split()):
                results.append(memory)

        return results[:n]

    def get_stats(self) -> Dict[str, Any]:
        """Get consolidation statistics."""
        return {
            "long_term_memories": len(self.long_term_store),
            "consolidations_run": len(self.consolidation_log),
            "last_consolidation": (
                self.consolidation_log[-1] if self.consolidation_log else None
            )
        }

    def should_consolidate(self) -> bool:
        """Check if consolidation should run (based on memory count)."""
        all_memories = self.episodic.get_recent(self.SHORT_TERM_LIMIT)
        return len(all_memories) >= self.SHORT_TERM_LIMIT * 0.8  # 80% full
