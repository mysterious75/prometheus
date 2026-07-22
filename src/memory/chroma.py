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
    chromadb = None

from ..utils.logger import logger


class _InMemoryCollection:
    """Minimal in-memory collection fallback when chromadb is not installed."""

    def __init__(self, name: str):
        self.name = name
        self._ids = []
        self._docs = []
        self._metas = []

    def add(self, documents=None, metadatas=None, ids=None):
        for i, doc in enumerate(documents or []):
            self._ids.append(ids[i] if ids else f"mem_{len(self._ids)+1}")
            self._docs.append(doc)
            self._metas.append((metadatas or [{}])[i] if metadatas else {})

    def get(self, ids=None):
        return {"ids": list(self._ids), "documents": list(self._docs), "metadatas": list(self._metas)}

    def query(self, query_texts=None, n_results=5):
        n = min(n_results, len(self._ids))
        return {
            "ids": [self._ids[:n]],
            "documents": [self._docs[:n]],
            "metadatas": [self._metas[:n]],
            "distances": [[0.0] * n],
        }

    def delete(self, ids=None):
        for fid in (ids or []):
            if fid in self._ids:
                idx = self._ids.index(fid)
                self._ids.pop(idx)
                self._docs.pop(idx)
                self._metas.pop(idx)


class _InMemoryClient:
    """Minimal in-memory client fallback."""

    def get_or_create_collection(self, name, metadata=None):
        return _InMemoryCollection(name)


class VectorMemory:
    """Vector-based memory using ChromaDB."""

    def __init__(self, host: str = "localhost", port: int = 8000):
        if not CHROMA_AVAILABLE:
            logger.warning("[yellow]ChromaDB not installed. Using in-memory fallback.[/yellow]")
            self.client = _InMemoryClient()
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
