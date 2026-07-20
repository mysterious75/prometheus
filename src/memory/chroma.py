"""ChromaDB Vector Memory for Project Prometheus."""

import os
from typing import Optional, Dict, Any, List
from pathlib import Path

try:
    import chromadb
    from chromadb.config import Settings
    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False

from ..utils.logger import logger


class VectorMemory:
    """Vector-based memory using ChromaDB."""

    def __init__(self, host: str = "localhost", port: int = 8000):
        if not CHROMA_AVAILABLE:
            logger.warning("[yellow]ChromaDB not installed. Using in-memory fallback.[/yellow]")
            self.client = chromadb.Client()
        else:
            try:
                self.client = chromadb.HttpClient(host=host, port=port)
                logger.info(f"[green]Connected to ChromaDB at {host}:{port}[/green]")
            except Exception:
                logger.warning("[yellow]ChromaDB server not available. Using in-memory.[/yellow]")
                self.client = chromadb.Client()

        # Create collections
        self.memories = self.client.get_or_create_collection(
            name="prometheus_memories",
            metadata={"hnsw:space": "cosine"}
        )
        self.episodic = self.client.get_or_create_collection(
            name="episodic_memory",
            metadata={"hnsw:space": "cosine"}
        )
        self.semantic = self.client.get_or_create_collection(
            name="semantic_memory",
            metadata={"hnsw:space": "cosine"}
        )

    def store(self, content: str, metadata: Optional[Dict] = None, collection: str = "memories") -> str:
        """Store a memory."""
        col = getattr(self, collection, self.memories)
        doc_id = f"mem_{len(col.get()['ids']) + 1}"

        col.add(
            documents=[content],
            metadatas=[metadata or {}],
            ids=[doc_id]
        )

        logger.info(f"Stored memory: {doc_id}")
        return doc_id

    def search(self, query: str, n_results: int = 5, collection: str = "memories") -> List[Dict]:
        """Search memories."""
        col = getattr(self, collection, self.memories)

        results = col.query(
            query_texts=[query],
            n_results=n_results
        )

        formatted = []
        for i in range(len(results["ids"][0])):
            formatted.append({
                "id": results["ids"][0][i],
                "content": results["documents"][0][i],
                "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                "distance": results["distances"][0][i] if results["distances"] else None
            })

        return formatted

    def get_all(self, collection: str = "memories") -> List[Dict]:
        """Get all memories."""
        col = getattr(self, collection, self.memories)
        results = col.get()

        formatted = []
        for i in range(len(results["ids"])):
            formatted.append({
                "id": results["ids"][i],
                "content": results["documents"][i],
                "metadata": results["metadatas"][i] if results["metadatas"] else {}
            })

        return formatted

    def delete(self, doc_id: str, collection: str = "memories") -> bool:
        """Delete a memory."""
        try:
            col = getattr(self, collection, self.memories)
            col.delete(ids=[doc_id])
            return True
        except Exception as e:
            logger.error(f"Failed to delete memory: {e}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get memory statistics."""
        return {
            "total_memories": len(self.memories.get()["ids"]),
            "total_episodic": len(self.episodic.get()["ids"]),
            "total_semantic": len(self.semantic.get()["ids"])
        }
