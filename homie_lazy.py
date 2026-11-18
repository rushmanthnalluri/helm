"""homie_lazy.py - Lazy module loader and background pre-warming engine for Homie.

Slashes Python cold-start latency from multi-second C-extension initialization
by deferring module imports until first actual attribute access and preloading
heavy dependencies in a prioritized background worker thread once the UI is displayed.
"""

from __future__ import annotations

import importlib
import logging
import queue
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("homie.lazy")


class LazyModule:
    """A proxy object that defers importing a heavy Python module until an attribute is accessed."""

    def __init__(self, name: str):
        self._name = name
        self._mod = None

    def __getattr__(self, attr: str) -> Any:
        if self._mod is None:
            import importlib
            self._mod = importlib.import_module(self._name)
        try:
            return getattr(self._mod, attr)
        except AttributeError:
            # Handle subpackages/submodules (e.g., cryptography.hazmat, winrt.windows.ui)
            try:
                submod = importlib.import_module(f"{self._name}.{attr}")
                return submod
            except (ImportError, ModuleNotFoundError):
                raise AttributeError(f"module '{self._name}' has no attribute '{attr}'")

    def __repr__(self) -> str:
        status = "loaded" if self._mod is not None else "deferred"
        return f"<LazyModule '{self._name}' ({status})>"

    def __dir__(self) -> List[str]:
        if self._mod is None:
            import importlib
            self._mod = importlib.import_module(self._name)
        return dir(self._mod)

    @property
    def is_loaded(self) -> bool:
        """Returns True if the underlying module has already been imported."""
        return self._mod is not None


# Exported lazy stubs for heavy C-extensions and third-party packages
torch = LazyModule("torch")
sentence_transformers = LazyModule("sentence_transformers")
faster_whisper = LazyModule("faster_whisper")
winrt = LazyModule("winrt")
cryptography = LazyModule("cryptography")
openpyxl = LazyModule("openpyxl")
ctranslate2 = LazyModule("ctranslate2")
pyautogui = LazyModule("pyautogui")
pyperclip = LazyModule("pyperclip")
PIL = LazyModule("PIL")


# Background Preloader with Priority Queue
_preload_thread: Optional[threading.Thread] = None
_preload_lock = threading.Lock()
_preload_status: Dict[str, Dict[str, Any]] = {}


def preload_in_background(
    modules: Optional[List[str]] = None,
    priority_order: Optional[List[Tuple[int, str]]] = None,
    on_complete: Optional[Callable[[], None]] = None,
    force: bool = False,
) -> threading.Thread:
    """Spins up a background daemon thread that imports heavy modules using a priority queue.

    Priority ordering:
      1. faster_whisper (highest priority - gates hold-to-talk voice pipeline)
      2. torch (ML foundation)
      3. sentence_transformers (semantic memory embeddings)
      4. cryptography (security / vault verification)
      5. winrt (Windows Runtime native integration)
      6. openpyxl (document processing)
      7. ctranslate2 (inference acceleration)
    """
    global _preload_thread
    with _preload_lock:
        if not force and _preload_thread is not None and _preload_thread.is_alive():
            return _preload_thread
    if priority_order is None:
        if modules:
            priority_order = [(idx + 1, m) for idx, m in enumerate(modules)]
        else:
            priority_order = [
                (1, "faster_whisper"),
                (2, "torch"),
                (3, "sentence_transformers"),
                (4, "cryptography"),
                (5, "winrt"),
                (6, "openpyxl"),
                (7, "ctranslate2"),
            ]

    pq: queue.PriorityQueue[Tuple[int, str]] = queue.PriorityQueue()
    for item in priority_order:
        pq.put(item)

    def _worker():
        while not pq.empty():
            try:
                priority, mod_name = pq.get_nowait()
            except queue.Empty:
                break
            t0 = time.perf_counter()
            try:
                mod = importlib.import_module(mod_name)
                elapsed = time.perf_counter() - t0
                _preload_status[mod_name] = {"ok": True, "time": elapsed, "priority": priority}
                stub = globals().get(mod_name)
                if isinstance(stub, LazyModule) and stub._mod is None:
                    stub._mod = mod
                logger.debug("[homie_lazy] Preloaded %s in %.3fs (priority %d)", mod_name, elapsed, priority)
            except Exception as e:
                elapsed = time.perf_counter() - t0
                _preload_status[mod_name] = {"ok": False, "error": str(e), "time": elapsed, "priority": priority}
                logger.debug("[homie_lazy] Failed to preload %s: %s", mod_name, e)
            finally:
                pq.task_done()
        if on_complete:
            try:
                on_complete()
            except Exception as e:
                logger.debug("[homie_lazy] on_complete callback failed: %s", e)

    with _preload_lock:
        thread = threading.Thread(
            target=_worker,
            name="HomiePreloadWorker",
            daemon=True
        )
        _preload_thread = thread
        thread.start()
        return thread


def get_preload_status() -> Dict[str, Dict[str, Any]]:
    """Returns the current preload status dictionary."""
    return dict(_preload_status)


def is_preloading() -> bool:
    """Returns True if the background preload thread is currently active."""
    with _preload_lock:
        return _preload_thread is not None and _preload_thread.is_alive()
