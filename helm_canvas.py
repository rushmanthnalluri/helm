"""helm_canvas.py - Interactive Side Canvas (Artifacts 2.0) Manager for Helm.

Renders live, sandboxed interactive previews of generated assets:
- Spreadsheets (.xlsx): Interactive HTML tables with column headers and cell values.
- Presentations (.pptx): 16:9 widescreen slide cards with bullets and speaker notes.
- Markdown Reports (.docx/.md/.html): Rich typography, rendered tables, and callouts.
- Visual Diagrams: Live interactive Mermaid/HTML widgets.
- Code & Code Blocks: Rendered syntax and code snippets with live preview.
"""

from __future__ import annotations

import os
import sys
import re
import json
import threading
import logging
from typing import Any, Callable, Dict, List, Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
logger = logging.getLogger("helm.canvas")

CANVAS_HTML_PATH = os.path.join(BASE_DIR, "ui", "canvas.html")

_CURRENT_CANVAS_ARTIFACT: Optional[Dict[str, Any]] = None


def html_escape(s: str) -> str:
    """Escapes HTML special characters."""
    if not isinstance(s, str):
        s = str(s)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _inline_markdown(s: str) -> str:
    """Formats inline markdown (bold, italic, code, links)."""
    escaped = html_escape(s)
    # Inline code
    escaped = re.sub(
        r'`([^`]+)`',
        r'<code style="background:#1e293b;padding:2px 6px;border-radius:4px;color:#93c5fd;font-family:monospace;">\1</code>',
        escaped
    )
    # Bold
    escaped = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', escaped)
    # Italic
    escaped = re.sub(r'\*([^*]+)\*', r'<em>\1</em>', escaped)
    return escaped


def markdown_to_html(md: str) -> str:
    """Converts basic markdown text into clean HTML."""
    if not md:
        return ""
    lines = md.replace("\r", "").split("\n")
    out = []
    in_code_block = False
    code_lines = []
    in_list = False

    for line in lines:
        if line.strip().startswith("```"):
            if in_code_block:
                escaped_code = html_escape("\n".join(code_lines))
                out.append(
                    f'<pre style="background:#13161f;border:1px solid rgba(255,255,255,0.1);border-radius:8px;padding:14px;overflow-x:auto;"><code style="color:#e2e8f0;font-family:Consolas,monospace;">{escaped_code}</code></pre>'
                )
                code_lines = []
                in_code_block = False
            else:
                in_code_block = True
            continue

        if in_code_block:
            code_lines.append(line)
            continue

        # Lists
        bullet_m = re.match(r'^\s*[-*+]\s+(.+)$', line)
        if bullet_m:
            if not in_list:
                out.append('<ul style="margin:8px 0 8px 24px;">')
                in_list = True
            content_line = _inline_markdown(bullet_m.group(1))
            out.append(f'<li style="margin-bottom:4px;color:#cbd5e1;">{content_line}</li>')
            continue
        else:
            if in_list:
                out.append('</ul>')
                in_list = False

        if not line.strip():
            continue

        # Headings
        h_m = re.match(r'^(#{1,6})\s+(.+)$', line)
        if h_m:
            level = len(h_m.group(1))
            h_text = _inline_markdown(h_m.group(2))
            out.append(f'<h{level} style="margin:18px 0 10px 0;color:#f8fafc;">{h_text}</h{level}>')
            continue

        # Blockquote
        if line.startswith(">"):
            q_text = _inline_markdown(line.lstrip(">").strip())
            out.append(
                f'<blockquote style="border-left:3px solid #3b82f6;padding-left:14px;margin:10px 0;color:#94a3b8;"><p>{q_text}</p></blockquote>'
            )
            continue

        # Paragraph
        p_text = _inline_markdown(line)
        out.append(f'<p style="margin-bottom:12px;line-height:1.65;color:#cbd5e1;">{p_text}</p>')

    if in_code_block and code_lines:
        escaped_code = html_escape("\n".join(code_lines))
        out.append(
            f'<pre style="background:#13161f;border:1px solid rgba(255,255,255,0.1);border-radius:8px;padding:14px;overflow-x:auto;"><code style="color:#e2e8f0;font-family:Consolas,monospace;">{escaped_code}</code></pre>'
        )
    if in_list:
        out.append('</ul>')

    return "\n".join(out)


def format_artifact_payload(
    title: str,
    content: str,
    artifact_type: str = "document",
    file_path: Optional[str] = None,
    data: Optional[List[List[Any]]] = None,
    slides: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Formats an artifact payload into a structured schema ready for canvas rendering."""
    norm_type = (artifact_type or "document").lower().strip()

    if norm_type in ("md", "markdown", "doc", "text", "document"):
        at = "document"
        html_content = markdown_to_html(content)
    elif norm_type in ("html", "htm"):
        at = "html"
        html_content = content
    elif norm_type in ("svg", "image"):
        at = "svg"
        html_content = f'<div style="display:flex;justify-content:center;align-items:center;padding:24px;">{content}</div>'
    elif norm_type in ("mermaid", "diagram"):
        at = "mermaid"
        html_content = (
            f'<div style="background:#1a1d26;padding:20px;border-radius:10px;border:1px solid rgba(255,255,255,0.1);">'
            f'<pre class="mermaid" style="color:#60a5fa;font-family:monospace;white-space:pre-wrap;">{html_escape(content)}</pre>'
            f'</div>'
        )
    elif norm_type in ("code", "python", "py", "javascript", "js", "typescript", "ts", "json", "bash", "sh", "sql", "css"):
        at = "code"
        html_content = (
            f'<div style="position:relative;">'
            f'<div style="font-size:11px;color:#94a3b8;margin-bottom:6px;text-transform:uppercase;font-weight:600;">{html_escape(norm_type)}</div>'
            f'<pre style="background:#13161f;border:1px solid rgba(255,255,255,0.1);border-radius:8px;padding:16px;overflow-x:auto;color:#f1f5f9;font-family:\'Cascadia Code\', Consolas, monospace;font-size:13px;line-height:1.5;">'
            f'<code>{html_escape(content)}</code></pre></div>'
        )
    elif norm_type == "spreadsheet":
        at = "spreadsheet"
        html_content = ""
    elif norm_type == "presentation":
        at = "presentation"
        html_content = ""
    else:
        at = norm_type
        html_content = markdown_to_html(content)

    return {
        "title": title.strip() if title else "Artifact",
        "type": at,
        "content": content,
        "html_content": html_content,
        "file_path": file_path,
        "data": data,
        "slides": slides,
    }


def extract_artifacts(text: str) -> List[Dict[str, Any]]:
    """Extracts rich code blocks and artifact tags from conversational AI output."""
    if not text or not isinstance(text, str):
        return []

    artifacts = []

    # 1. Detect XML/HTML artifact tags: <artifact title="..." type="...">...</artifact>
    # or <antArtifact identifier="..." type="..." title="...">...</antArtifact>
    tag_pattern = re.compile(
        r'<(?:artifact|antArtifact)([^>]*)>(.*?)</(?:artifact|antArtifact)>',
        re.DOTALL | re.IGNORECASE
    )
    for match in tag_pattern.finditer(text):
        attrs_str = match.group(1)
        body = match.group(2).strip()

        title_m = re.search(r'title=["\']([^"\']+)["\']', attrs_str, re.I)
        type_m = re.search(r'type=["\']([^"\']+)["\']', attrs_str, re.I)

        title = title_m.group(1).strip() if title_m else "Generated Artifact"
        raw_type = type_m.group(1).strip() if type_m else "document"

        if "mermaid" in raw_type.lower():
            raw_type = "mermaid"
        elif "svg" in raw_type.lower():
            raw_type = "svg"
        elif "html" in raw_type.lower():
            raw_type = "html"
        elif "react" in raw_type.lower():
            raw_type = "javascript"
        elif "markdown" in raw_type.lower():
            raw_type = "markdown"

        payload = format_artifact_payload(title=title, content=body, artifact_type=raw_type)
        payload["from_tag"] = True
        artifacts.append(payload)

    # 2. Detect markdown fenced code blocks: ```html, ```svg, ```mermaid, ```python, etc.
    fence_pattern = re.compile(r'```([a-zA-Z0-9_\-+]+)?\s*\n(.*?)```', re.DOTALL)
    supported_langs = {
        'html': 'html',
        'svg': 'svg',
        'mermaid': 'mermaid',
        'python': 'python',
        'py': 'python',
        'javascript': 'javascript',
        'js': 'javascript',
        'typescript': 'typescript',
        'ts': 'typescript',
        'json': 'json',
        'csv': 'csv',
        'markdown': 'markdown',
        'md': 'markdown',
        'bash': 'bash',
        'sh': 'bash',
        'sql': 'sql',
        'css': 'css',
    }

    for match in fence_pattern.finditer(text):
        lang = (match.group(1) or '').strip().lower()
        code_body = match.group(2).strip()
        if not code_body:
            continue
        if lang in supported_langs:
            norm_type = supported_langs[lang]
            title = f"{norm_type.upper()} Artifact"
            payload = format_artifact_payload(title=title, content=code_body, artifact_type=norm_type)
            payload["from_tag"] = False
            artifacts.append(payload)

    return artifacts


def set_active_artifact(artifact: Dict[str, Any]) -> None:
    global _CURRENT_CANVAS_ARTIFACT
    _CURRENT_CANVAS_ARTIFACT = artifact
    logger.info("Active canvas artifact set: '%s' (type: %s)", artifact.get("title"), artifact.get("type"))


def get_active_artifact() -> Optional[Dict[str, Any]]:
    return _CURRENT_CANVAS_ARTIFACT


class CanvasApi:
    """pywebview JS Bridge for the Canvas side window."""
    def __init__(self, controller: CanvasController):
        self.controller = controller

    def post(self, msg: Any):
        if not isinstance(msg, dict):
            return
        if msg.get("canvas_close"):
            self.controller.hide()
        elif "canvas_action" in msg or "action" in msg:
            act = msg.get("canvas_action") or msg.get("action")
            payload = msg.get("payload", {})
            self.controller.handle_action(act, payload)


class CanvasController:
    """Manages the Interactive Side Canvas pywebview window and state."""

    def __init__(self, action_handler: Optional[Callable[[str, Any], Any]] = None):
        self.action_handler = action_handler
        self.window = None
        self._is_visible = False
        self._lock = threading.Lock()
        self.active_artifact: Optional[Dict[str, Any]] = None
        self.api = CanvasApi(self)

    @property
    def is_visible(self) -> bool:
        return self._is_visible

    def _is_gui_ready(self) -> bool:
        """Returns True if window is a test mock or if pywebview GUI event loop is running."""
        if not self.window:
            return False
        if "Mock" in type(self.window).__name__:
            return True
        return getattr(self.window, "gui", None) is not None

    def create_window(self, webview_module=None):
        """Creates the pywebview window for the interactive canvas."""
        if not webview_module:
            try:
                import webview
                webview_module = webview
            except ImportError:
                logger.warning("pywebview not installed; Canvas window creation deferred.")
                return None

        with self._lock:
            if self.window is not None:
                return self.window

            self.api = CanvasApi(self)
            try:
                self.window = webview_module.create_window(
                    title="Helm Canvas",
                    url=CANVAS_HTML_PATH,
                    js_api=self.api,
                    width=860,
                    height=640,
                    resizable=True,
                    frameless=False,
                    hidden=True,
                )
            except Exception as e:
                logger.debug("Error creating canvas window: %s", e)
                return None

            def on_loaded():
                if self.active_artifact:
                    try:
                        self.window.evaluate_js(f"window.loadArtifact({json.dumps(self.active_artifact)})")
                    except Exception as err:
                        logger.debug("Error loading active artifact on canvas load: %s", err)

            try:
                self.window.events.loaded += on_loaded
            except Exception:
                pass

            return self.window

    def show(self):
        """Presents the Side Canvas window."""
        self._is_visible = True
        if self._is_gui_ready():
            try:
                self.window.show()
                self.window.restore()
            except Exception as e:
                logger.debug("Error showing canvas window: %s", e)

    def hide(self):
        """Hides the Side Canvas window."""
        self._is_visible = False
        if self._is_gui_ready():
            try:
                self.window.hide()
            except Exception as e:
                logger.debug("Error hiding canvas window: %s", e)

    def toggle(self):
        """Toggles Side Canvas visibility."""
        if self._is_visible:
            self.hide()
        else:
            self.show()

    def set_active_artifact(self, artifact: Dict[str, Any]) -> None:
        """Sets the active artifact on controller and global state."""
        self.active_artifact = artifact
        set_active_artifact(artifact)

    def show_artifact(
        self,
        title: str,
        content: str,
        content_type: str = "document",
        file_path: Optional[str] = None,
        data: Optional[List[List[Any]]] = None,
        slides: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Presents an artifact on the interactive side canvas."""
        payload = format_artifact_payload(
            title=title,
            content=content,
            artifact_type=content_type,
            file_path=file_path,
            data=data,
            slides=slides,
        )
        self.set_active_artifact(payload)
        self.show()

        if self._is_gui_ready():
            try:
                self.window.evaluate_js(f"window.loadArtifact({json.dumps(payload)})")
            except Exception as e:
                logger.debug("Error evaluating loadArtifact on window: %s", e)

        return {
            "ok": True,
            "title": payload["title"],
            "type": payload["type"],
            "status": "displayed_in_canvas",
        }

    def handle_action(self, action_id: str, payload: Dict[str, Any]):
        """Dispatches canvas actions to registered handler."""
        logger.info("Canvas executing action: %s", action_id)
        if self.action_handler:
            self.action_handler(action_id, payload)


# Backward-compatible alias and singleton
HelmCanvas = CanvasController

_DEFAULT_CANVAS_CONTROLLER: Optional[CanvasController] = None


def get_canvas() -> CanvasController:
    """Returns the process-wide default CanvasController."""
    global _DEFAULT_CANVAS_CONTROLLER
    if _DEFAULT_CANVAS_CONTROLLER is None:
        _DEFAULT_CANVAS_CONTROLLER = CanvasController()
    return _DEFAULT_CANVAS_CONTROLLER


def display_artifact(
    title: str,
    content: str,
    artifact_type: str = "document",
    file_path: Optional[str] = None,
    data: Optional[List[List[Any]]] = None,
    slides: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Prepares and opens an interactive artifact in the side canvas."""
    return get_canvas().show_artifact(
        title=title,
        content=content,
        content_type=artifact_type,
        file_path=file_path,
        data=data,
        slides=slides,
    )


__all__ = [
    "CanvasController",
    "HelmCanvas",
    "get_canvas",
    "display_artifact",
    "set_active_artifact",
    "get_active_artifact",
    "extract_artifacts",
    "format_artifact_payload",
    "markdown_to_html",
    "CANVAS_HTML_PATH",
]
