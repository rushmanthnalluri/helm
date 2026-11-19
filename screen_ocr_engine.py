"""Windows Hardware OCR Engine for Helm Screen Memory & Recall.
Provides native Windows 10/11 OCR using Windows.Media.Ocr via winrt or winsdk,
with robust fallbacks to pytesseract and image/UI heuristics:
- Windows.Media.Ocr: Hardware-accelerated, language-aware, zero-network, local offline OCR
- Fallback chain: winrt -> winsdk -> pytesseract -> window text heuristics
- capture_and_extract_text(): Screen grab + OCR pipeline for desktop windows
"""

import os
import sys
import io
import time
import logging
import asyncio
import concurrent.futures
from pathlib import Path
from typing import Optional, Union, Tuple, List, Any
from PIL import Image, ImageGrab

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    import windows_tools
except ImportError:
    windows_tools = None

logger = logging.getLogger("helm.screen_ocr_engine")


def _run_async(coro, timeout: float = 15.0):
    """Executes a WinRT async coroutine safely across sync and existing async loops."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=timeout)
    else:
        return asyncio.run(coro)


class WindowsOCREngine:
    """Hardware-accelerated Windows OCR engine wrapping Windows.Media.Ocr.OcrEngine,
    with fallbacks to winsdk, pytesseract, or heuristic window text extraction.
    """

    def __init__(self, language: Optional[str] = None):
        self.language_tag = language or "en-US"
        self.backend = "none"
        self._engine = None
        self._winrt_ocr = None
        self._winrt_imaging = None
        self._winrt_streams = None
        self._pytesseract = None

        self._initialize_engine()

    def _initialize_engine(self):
        """Attempts initialization through the fallback hierarchy: winrt -> winsdk -> pytesseract -> heuristic."""
        # 1. Try winrt.windows.media.ocr
        try:
            import winrt.windows.media.ocr as w_ocr
            import winrt.windows.graphics.imaging as w_imaging
            import winrt.windows.storage.streams as w_streams
            import winrt.windows.globalization as w_glob

            engine = None
            if self.language_tag:
                try:
                    lang = w_glob.Language(self.language_tag)
                    if w_ocr.OcrEngine.is_language_supported(lang):
                        engine = w_ocr.OcrEngine.try_create_from_language(lang)
                except Exception:
                    pass

            if engine is None:
                engine = w_ocr.OcrEngine.try_create_from_user_profile_languages()

            if engine is not None:
                self._engine = engine
                self._winrt_ocr = w_ocr
                self._winrt_imaging = w_imaging
                self._winrt_streams = w_streams
                self.backend = "winrt"
                logger.info("Initialized native WinRT OcrEngine (language: %s)", getattr(engine.recognizer_language, "language_tag", "default"))
                return
        except Exception as e:
            logger.debug("WinRT OCR init failed or unavailable: %s", e)

        # 2. Try winsdk.windows.media.ocr
        try:
            import winsdk.windows.media.ocr as ws_ocr
            import winsdk.windows.graphics.imaging as ws_imaging
            import winsdk.windows.storage.streams as ws_streams
            import winsdk.windows.globalization as ws_glob

            engine = None
            if self.language_tag:
                try:
                    lang = ws_glob.Language(self.language_tag)
                    if ws_ocr.OcrEngine.is_language_supported(lang):
                        engine = ws_ocr.OcrEngine.try_create_from_language(lang)
                except Exception:
                    pass

            if engine is None:
                engine = ws_ocr.OcrEngine.try_create_from_user_profile_languages()

            if engine is not None:
                self._engine = engine
                self._winrt_ocr = ws_ocr
                self._winrt_imaging = ws_imaging
                self._winrt_streams = ws_streams
                self.backend = "winsdk"
                logger.info("Initialized native WinSDK OcrEngine")
                return
        except Exception as e:
            logger.debug("WinSDK OCR init failed or unavailable: %s", e)

        # 3. Try pytesseract
        try:
            import pytesseract
            pytesseract.get_tesseract_version()
            self._pytesseract = pytesseract
            self.backend = "pytesseract"
            logger.info("Initialized pytesseract OCR fallback")
            return
        except Exception as e:
            logger.debug("pytesseract init failed or unavailable: %s", e)

        # 4. Fallback to heuristics
        self.backend = "heuristic"
        logger.info("Using heuristic / UI text extraction fallback for OCR")

    def is_available(self) -> bool:
        """Returns True if any OCR backend is active."""
        return self.backend in ("winrt", "winsdk", "pytesseract", "heuristic")

    async def _recognize_winrt_async(self, pil_image: Image.Image) -> str:
        """Asynchronously runs Windows.Media.Ocr on a PIL Image."""
        # Enforce max image dimension limit
        max_dim = 9000
        if pil_image.width > max_dim or pil_image.height > max_dim:
            pil_image = pil_image.copy()
            pil_image.thumbnail((max_dim, max_dim))

        # Convert image to RGB/BMP bytes in memory
        if pil_image.mode not in ("RGB", "RGBA"):
            pil_image = pil_image.convert("RGB")

        byte_buf = io.BytesIO()
        pil_image.save(byte_buf, format="BMP")
        raw_bytes = byte_buf.getvalue()

        # Write to Windows InMemoryRandomAccessStream
        stream = self._winrt_streams.InMemoryRandomAccessStream()
        writer = self._winrt_streams.DataWriter(stream)
        writer.write_bytes(raw_bytes)
        await writer.store_async()
        await writer.flush_async()
        writer.detach_stream()
        stream.seek(0)

        # Decode to SoftwareBitmap
        decoder = await self._winrt_imaging.BitmapDecoder.create_async(stream)
        bitmap = await decoder.get_software_bitmap_async()

        # Run OCR
        ocr_result = await self._engine.recognize_async(bitmap)
        if hasattr(ocr_result, "text") and ocr_result.text:
            return ocr_result.text
        if hasattr(ocr_result, "lines"):
            return "\n".join(line.text for line in ocr_result.lines if hasattr(line, "text"))
        return ""

    def extract_text(self, image: Union[Image.Image, bytes, str, Path]) -> str:
        """Extracts text from an image (PIL Image, image file path, or raw bytes)."""
        # Load image if needed
        pil_img = None
        if isinstance(image, Image.Image):
            pil_img = image
        elif isinstance(image, (str, Path)):
            pil_img = Image.open(str(image))
        elif isinstance(image, (bytes, bytearray)):
            pil_img = Image.open(io.BytesIO(image))
        else:
            raise TypeError(f"Unsupported image type: {type(image)}")

        if self.backend in ("winrt", "winsdk"):
            try:
                return _run_async(self._recognize_winrt_async(pil_img))
            except Exception as e:
                logger.warning("Native Windows OCR execution failed (%s), attempting secondary fallback", e)

        if self._pytesseract is not None:
            try:
                return self._pytesseract.image_to_string(pil_img)
            except Exception as e:
                logger.warning("pytesseract execution failed: %s", e)

        # Heuristic fallback: if window handle or desktop active window can be read
        if windows_tools:
            try:
                fg = windows_tools.get_foreground_window()
                if fg and fg.get("hwnd"):
                    return windows_tools.read_window_text(fg["hwnd"]) or ""
            except Exception:
                pass

        return ""

    def extract_text_from_image(self, image: Union[Image.Image, bytes, str, Path]) -> str:
        """Alias for extract_text."""
        return self.extract_text(image)

    def recognize(self, image: Union[Image.Image, bytes, str, Path]) -> str:
        """Alias for extract_text."""
        return self.extract_text(image)


_GLOBAL_OCR_ENGINE: Optional[WindowsOCREngine] = None

# Hardware-Accelerated Frame Diffing & Perceptual Hashing Cache
_LAST_FRAME_HASH: Optional[int] = None
_LAST_EXTRACTED_TEXT: str = ""
_DIFF_LOCK = concurrent.futures.thread.threading.Lock() if hasattr(concurrent.futures, "thread") else None


def compute_frame_hash(img: Image.Image) -> int:
    """Compute 64-bit average hash (aHash) for fast frame deduplication.
    Enables instant skipping of unchanged screens without burning OCR cycles.
    """
    try:
        resized = img.resize((8, 8), Image.Resampling.BILINEAR).convert("L")
        pixels = list(resized.getdata())
        avg = sum(pixels) / max(1, len(pixels))
        diff = 0
        for i, p in enumerate(pixels):
            if p > avg:
                diff |= (1 << i)
        return diff
    except Exception:
        return 0


def frame_hamming_distance(h1: int, h2: int) -> int:
    """Return bit difference count between two perceptual hashes."""
    return bin((h1 ^ h2) & 0xFFFFFFFFFFFFFFFF).count("1")


def get_ocr_engine(language: Optional[str] = None) -> WindowsOCREngine:
    """Returns a singleton or cached instance of WindowsOCREngine."""
    global _GLOBAL_OCR_ENGINE
    if _GLOBAL_OCR_ENGINE is None:
        _GLOBAL_OCR_ENGINE = WindowsOCREngine(language=language)
    return _GLOBAL_OCR_ENGINE


def capture_and_extract_text(
    bbox: Optional[Tuple[int, int, int, int]] = None,
    hwnd: Optional[int] = None,
    engine: Optional[WindowsOCREngine] = None,
    skip_if_unchanged: bool = True
) -> Optional[str]:
    """Captures the active screen or specified window/bounding box and extracts text via OCR.
    Includes frame diffing with perceptual hashing to bypass duplicate OCR processing.

    Args:
        bbox: Optional (left, top, right, bottom) pixel coordinates.
        hwnd: Optional Windows window handle to capture bounding rect of.
        engine: Optional WindowsOCREngine instance.
        skip_if_unchanged: If True, uses perceptual hashing to skip unchanged frames.

    Returns:
        Extracted text string, or None if screen capture failed.
    """
    if windows_tools:
        try:
            windows_tools.ensure_desktop_attached()
        except Exception:
            pass

    if hwnd and not bbox:
        try:
            import win32gui
            if win32gui.IsWindow(hwnd):
                rect = win32gui.GetWindowRect(hwnd)  # (left, top, right, bottom)
                if rect[2] > rect[0] and rect[3] > rect[1]:
                    bbox = rect
        except Exception:
            pass

    img = None
    try:
        if bbox:
            img = ImageGrab.grab(bbox=bbox, all_screens=True)
        else:
            img = ImageGrab.grab(all_screens=True)
    except Exception as e:
        logger.debug("Primary ImageGrab failed (%s); trying fallback grab", e)
        try:
            img = ImageGrab.grab(bbox=bbox)
        except Exception as e2:
            logger.warning("Screen capture failed: %s", e2)
            return None

    if img is None:
        return None

    global _LAST_FRAME_HASH, _LAST_EXTRACTED_TEXT
    if skip_if_unchanged:
        current_hash = compute_frame_hash(img)
        if _LAST_FRAME_HASH is not None and frame_hamming_distance(_LAST_FRAME_HASH, current_hash) <= 1:
            logger.debug("[ScreenOCR] Frame unchanged (aHash diff <= 1), reusing cached OCR result")
            return _LAST_EXTRACTED_TEXT

    ocr = engine or get_ocr_engine()
    try:
        text = ocr.extract_text(img)
        result = text.strip() if text else ""
        if skip_if_unchanged:
            _LAST_FRAME_HASH = compute_frame_hash(img)
            _LAST_EXTRACTED_TEXT = result
        return result
    except Exception as e:
        logger.error("OCR extraction failed on screen capture: %s", e)
        return None
