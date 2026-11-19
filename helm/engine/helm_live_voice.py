"""
helm_live_voice.py - Full-Duplex Real-Time Conversational Voice Engine.

Priority 5 Implementation:
1. Full-Duplex Audio Pipeline: Continuous microphone capture simultaneous with
   streaming audio playback.
2. Silero VAD Barge-In & Interruption: Sub-50ms instant cancellation and mute of
   ongoing TTS playback when user speaks, immediate queue draining, and seamless
   transition to capturing the user's interruption prompt.
3. Pluggable Streaming TTS Chunker: Sub-150ms time-to-first-audio (TTFA) delivery
   supporting Kokoro, Piper, custom generators, and mock adapters.
4. Thread-Safe State Machine:
   IDLE -> LISTENING -> PROCESSING -> SPEAKING -> INTERRUPTED.
5. Reactive Callbacks: Audio frames, speech start/end, interruption events,
   state changes, and TTS streaming chunks.
6. Mockable Audio Backend: In-memory mock audio backend for automated tests and
   headless environments without physical soundcards.
"""

from __future__ import annotations

import os
import re
import sys
import time
import math
import queue
import struct
import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple, Union

logger = logging.getLogger(__name__)

# Preload numpy and torch safely to avoid cold-start DLL loading overhead during real-time streaming
try:
    import numpy as np
except ImportError:
    np = None

try:
    import torch
except ImportError:
    torch = None


# ---------------------------------------------------------------------------
# State Machine & Events
# ---------------------------------------------------------------------------

class VoiceState(str, Enum):
    """Clean thread-safe state machine states for full-duplex conversational voice."""
    IDLE = "IDLE"
    LISTENING = "LISTENING"
    PROCESSING = "PROCESSING"
    SPEAKING = "SPEAKING"
    INTERRUPTED = "INTERRUPTED"

    def __str__(self) -> str:
        return self.value


@dataclass
class InterruptionEvent:
    """Carries diagnostic and timing metrics about a barge-in interruption."""
    timestamp: float
    latency_ms: float
    active_state_prior: VoiceState
    discarded_chunks_count: int
    discarded_bytes_count: int
    interruption_reason: str = "user_speech_detected"
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LiveVoiceConfig:
    """Configuration for full-duplex voice engine."""
    sample_rate: int = 16000                # Mic input sample rate (Hz)
    channels: int = 1                       # Mono
    chunk_size: int = 512                   # 512 samples = 32ms at 16kHz (optimal for Silero VAD)
    vad_threshold: float = 0.5              # Neural VAD probability threshold
    energy_fallback_threshold: float = 500.0# RMS threshold for energy VAD fallback
    silence_frames_threshold: int = 15      # Number of consecutive silence frames (~480ms) for speech end
    playback_sample_rate: int = 24000       # Default playback sample rate (Hz)
    max_queue_size: int = 100               # Max queued audio playback chunks
    speech_friendly_cleanup: bool = True    # Clean markdown and formatting from text


# ---------------------------------------------------------------------------
# Text Chunker for Low-Latency Streaming TTS (<150ms TTFA)
# ---------------------------------------------------------------------------

class StreamingTextChunker:
    """
    Splits text streams into conversational speech chunks on sentence and clause
    boundaries so synthesis begins immediately on the first phrase without waiting
    for complete sentences or paragraphs.
    """

    # Boundaries: sentence ends (.?!), newlines, and clause breaks (,;:-)
    CLAUSE_PUNCTUATION = re.compile(r"([.?!]+(?:\s+|\Z)|[\n\r]+|[,;:]\s+)")

    def __init__(self, min_words_per_chunk: int = 2, max_words_per_chunk: int = 14):
        self.min_words_per_chunk = min_words_per_chunk
        self.max_words_per_chunk = max_words_per_chunk

    def chunk_text(self, text: Union[str, Iterator[str]]) -> Iterator[str]:
        """
        Yields small speech-ready text units as soon as boundary is detected.
        Supports both static strings and streaming token generators.
        """
        if isinstance(text, str):
            token_iter = iter([text])
        else:
            token_iter = text

        buffer = ""
        for token in token_iter:
            if not token:
                continue
            buffer += token

            # Split buffer on boundaries
            while True:
                match = self.CLAUSE_PUNCTUATION.search(buffer)
                if not match:
                    # If buffer is getting too long without punctuation, force split
                    words = buffer.strip().split()
                    if len(words) >= self.max_words_per_chunk:
                        chunk = " ".join(words[:self.max_words_per_chunk])
                        buffer = " ".join(words[self.max_words_per_chunk:])
                        clean = self._clean(chunk)
                        if clean:
                            yield clean
                    break

                end_pos = match.end()
                candidate = buffer[:end_pos]
                words = candidate.strip().split()

                if len(words) >= self.min_words_per_chunk or match.group(1).startswith((".", "!", "?", "\n")):
                    chunk = buffer[:end_pos]
                    buffer = buffer[end_pos:]
                    clean = self._clean(chunk)
                    if clean:
                        yield clean
                else:
                    # Too short for a clause break (like "e.g.,"); keep accumulating
                    break

        # Flush remainder
        clean_rem = self._clean(buffer)
        if clean_rem:
            yield clean_rem

    @staticmethod
    def _clean(text: str) -> str:
        """Strip markdown markers and excessive whitespace for natural speech."""
        if not text:
            return ""
        # Strip code blocks, bold/italic asterisks, backticks, URLs
        cleaned = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
        cleaned = re.sub(r"`.*?`", "", cleaned)
        cleaned = re.sub(r"\*\*|__|\*|_", "", cleaned)
        cleaned = re.sub(r"https?://\S+", "", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        return cleaned


# ---------------------------------------------------------------------------
# Silero VAD Neural Engine with Energy Fallback
# ---------------------------------------------------------------------------

class SileroVADEngine:
    """
    Voice Activity Detection using Silero VAD v5 neural network with
    transparent energy-based RMS fallback when PyTorch or models are unavailable,
    or when explicit energy mode is requested.
    """

    def __init__(
        self,
        threshold: float = 0.5,
        energy_threshold: float = 500.0,
        use_neural: bool = True
    ):
        self.threshold = threshold
        self.energy_threshold = energy_threshold
        self.use_neural = use_neural
        self._model = None
        self._initialized = False
        self._is_neural = False
        self._lock = threading.Lock()

    def initialize(self) -> bool:
        """Loads Silero VAD model if PyTorch is available and use_neural is True."""
        with self._lock:
            if self._initialized:
                return self._is_neural
            self._initialized = True

            if not self.use_neural:
                self._is_neural = False
                return False

            # 1. Try silero_vad package
            try:
                from silero_vad import load_silero_vad
                self._model = load_silero_vad()
                self._is_neural = True
                self._warmup()
                logger.info("[SileroVAD] Loaded via silero_vad package")
                return True
            except (ImportError, Exception):
                pass

            # 2. Try torch.hub
            try:
                import torch
                try:
                    loaded = torch.hub.load(
                        "snakers4/silero-vad",
                        "silero_vad",
                        force_reload=False,
                        trust_repo=True
                    )
                except TypeError:
                    loaded = torch.hub.load(
                        "snakers4/silero-vad",
                        "silero_vad",
                        force_reload=False
                    )

                if isinstance(loaded, tuple):
                    self._model = loaded[0]
                else:
                    self._model = loaded

                if hasattr(self._model, "eval"):
                    self._model.eval()
                self._is_neural = True
                self._warmup()
                logger.info("[SileroVAD] Loaded v5 via torch.hub")
                return True
            except Exception as hub_err:
                logger.debug(f"[SileroVAD] Neural load skipped ({hub_err}), using energy fallback")
                self._model = None
                self._is_neural = False
                return False

    def _warmup(self) -> None:
        """Warms up PyTorch model on dummy input to eliminate cold-start inference latency."""
        if self._model is not None:
            try:
                import torch
                dummy = torch.zeros(512, dtype=torch.float32)
                with torch.no_grad():
                    self._model(dummy, 16000)
            except Exception:
                pass

    @property
    def is_neural(self) -> bool:
        return self._is_neural

    def detect_voice(
        self,
        pcm_bytes: bytes,
        sample_rate: int = 16000,
        threshold: Optional[float] = None
    ) -> bool:
        """
        Detects if PCM audio chunk contains speech.
        Uses Silero VAD on 512-sample slices, or RMS energy fallback.
        """
        if not pcm_bytes:
            return False

        if not self._initialized:
            self.initialize()

        thresh = threshold if threshold is not None else self.threshold

        if self._is_neural and self._model is not None:
            try:
                import torch
                import numpy as np

                # Convert 16-bit PCM bytes to float32 tensor in [-1.0, 1.0]
                audio_np = np.frombuffer(pcm_bytes, dtype=np.int16).astype(np.float32) / 32768.0
                if len(audio_np) == 0:
                    return False

                audio_tensor = torch.from_numpy(audio_np)
                chunk_len = 512 if sample_rate >= 16000 else 256

                with torch.no_grad():
                    if len(audio_tensor) < chunk_len:
                        padded = torch.zeros(chunk_len, dtype=torch.float32)
                        padded[:len(audio_tensor)] = audio_tensor
                        prob = self._model(padded, sample_rate)
                        val = prob.item() if hasattr(prob, "item") else float(prob)
                        return val > thresh

                    for idx in range(0, len(audio_tensor) - chunk_len + 1, chunk_len):
                        chunk = audio_tensor[idx:idx + chunk_len]
                        prob = self._model(chunk, sample_rate)
                        val = prob.item() if hasattr(prob, "item") else float(prob)
                        if val > thresh:
                            return True

                    rem = len(audio_tensor) % chunk_len
                    if rem > 0 and len(audio_tensor) > chunk_len:
                        last_chunk = audio_tensor[-chunk_len:]
                        prob = self._model(last_chunk, sample_rate)
                        val = prob.item() if hasattr(prob, "item") else float(prob)
                        if val > thresh:
                            return True

                return False
            except Exception as e:
                logger.debug(f"[SileroVAD] Neural inference error ({e}), using energy fallback")
                return self.energy_vad(pcm_bytes)
        else:
            return self.energy_vad(pcm_bytes)

    def energy_vad(self, pcm_bytes: bytes, threshold: Optional[float] = None) -> bool:
        """Fast RMS energy VAD fallback (<0.01ms)."""
        if not pcm_bytes:
            return False
        thresh = threshold if threshold is not None else self.energy_threshold
        num_samples = len(pcm_bytes) // 2
        if num_samples == 0:
            return False
        samples = struct.unpack(f"<{num_samples}h", pcm_bytes[:num_samples * 2])
        sum_sq = sum(s * s for s in samples)
        rms = (sum_sq / len(samples)) ** 0.5
        return rms > thresh

    def reset_states(self) -> None:
        """Resets hidden RNN state between conversations."""
        if self._model is not None and hasattr(self._model, "reset_states"):
            try:
                self._model.reset_states()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Audio Backend Abstractions (Mockable for CI & Headless Testing)
# ---------------------------------------------------------------------------

class AudioBackend(ABC):
    """Abstract interface for audio capture and playback."""

    @abstractmethod
    def start_input(
        self,
        sample_rate: int,
        channels: int,
        chunk_size: int,
        callback: Callable[[bytes], None]
    ) -> bool:
        """Starts continuous microphone listening, calling callback with PCM frames."""
        pass

    @abstractmethod
    def stop_input(self) -> None:
        """Stops continuous microphone listening."""
        pass

    @abstractmethod
    def is_input_active(self) -> bool:
        """Returns True if microphone input stream is active."""
        pass

    @abstractmethod
    def play_chunk(self, pcm_bytes: bytes, sample_rate: int) -> None:
        """Plays an audio PCM chunk synchronously or via buffer."""
        pass

    @abstractmethod
    def stop_playback(self) -> float:
        """
        Instantly cancels/mutes ongoing audio playback.
        Returns cancellation elapsed time in milliseconds.
        """
        pass

    @abstractmethod
    def is_playing(self) -> bool:
        """Returns True if audio playback is currently playing."""
        pass

    @abstractmethod
    def clear_playback(self) -> int:
        """Clears pending playback buffers and returns number of cleared items."""
        pass

    @abstractmethod
    def wait_playback_complete(self, timeout: Optional[float] = None) -> bool:
        """Waits until all pending audio finishes playing."""
        pass


class MockAudioBackend(AudioBackend):
    """
    In-memory mock audio backend for automated tests and headless environments.
    Guarantees sub-50ms instant barge-in cancellation and full event tracing.
    """

    def __init__(self, simulate_realtime: bool = False, playback_speed_multiplier: float = 1.0):
        self.simulate_realtime = simulate_realtime
        self.playback_speed_multiplier = playback_speed_multiplier
        self._input_active = False
        self._input_callback: Optional[Callable[[bytes], None]] = None
        self._playback_queue: queue.Queue[Tuple[bytes, int]] = queue.Queue()
        self._played_chunks: List[bytes] = []
        self._is_playing_flag = False
        self._cancel_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self.last_cancellation_latency_ms: float = 0.0
        self.interruption_count: int = 0
        self._last_discarded_chunks: int = 0
        self._last_discarded_bytes: int = 0

    def start_input(
        self,
        sample_rate: int,
        channels: int,
        chunk_size: int,
        callback: Callable[[bytes], None]
    ) -> bool:
        with self._lock:
            self._input_active = True
            self._input_callback = callback
            self._cancel_event.clear()
            if not self._worker_thread or not self._worker_thread.is_alive():
                self._worker_thread = threading.Thread(
                    target=self._playback_worker,
                    daemon=True,
                    name="MockAudioPlaybackWorker"
                )
                self._worker_thread.start()
            return True

    def stop_input(self) -> None:
        with self._lock:
            self._input_active = False
            self._input_callback = None

    def is_input_active(self) -> bool:
        with self._lock:
            return self._input_active

    def inject_input(self, pcm_bytes: bytes) -> None:
        """Test helper: Injects a simulated microphone frame into the pipeline."""
        cb = self._input_callback
        if cb and self._input_active:
            cb(pcm_bytes)

    def play_chunk(self, pcm_bytes: bytes, sample_rate: int) -> None:
        if not pcm_bytes:
            return
        with self._lock:
            self._cancel_event.clear()
            self._is_playing_flag = True
            self._playback_queue.put((pcm_bytes, sample_rate))

    def _playback_worker(self) -> None:
        while True:
            try:
                chunk, srate = self._playback_queue.get(timeout=0.05)
            except queue.Empty:
                with self._lock:
                    if self._playback_queue.empty():
                        self._is_playing_flag = False
                continue

            if self._cancel_event.is_set():
                with self._lock:
                    self._is_playing_flag = False
                continue

            with self._lock:
                self._is_playing_flag = True
                self._played_chunks.append(chunk)

            # Optional simulated duration
            if self.simulate_realtime and srate > 0:
                duration = (len(chunk) / 2) / float(srate)
                scaled_dur = duration / max(0.1, self.playback_speed_multiplier)
                # Sleep in small slices to remain interruptible
                slice_time = 0.005
                elapsed = 0.0
                while elapsed < scaled_dur and not self._cancel_event.is_set():
                    time.sleep(min(slice_time, scaled_dur - elapsed))
                    elapsed += slice_time

    def _drain_playback_queue(self) -> Tuple[int, int]:
        cleared_count = 0
        cleared_bytes = 0
        while not self._playback_queue.empty():
            try:
                chunk, _ = self._playback_queue.get_nowait()
                cleared_count += 1
                cleared_bytes += len(chunk)
            except queue.Empty:
                break
        return (cleared_count, cleared_bytes)

    def stop_playback(self) -> float:
        """
        Instantly halts playback in < 5ms, clearing queue and signaling cancellation.
        """
        t0 = time.perf_counter()
        with self._lock:
            self._cancel_event.set()
            cleared_chunks, cleared_bytes = self._drain_playback_queue()
            self._last_discarded_chunks = cleared_chunks
            self._last_discarded_bytes = cleared_bytes
            self._is_playing_flag = False
            self.interruption_count += 1
        t1 = time.perf_counter()
        elapsed_ms = (t1 - t0) * 1000.0
        self.last_cancellation_latency_ms = elapsed_ms
        return elapsed_ms

    def is_playing(self) -> bool:
        with self._lock:
            return self._is_playing_flag or not self._playback_queue.empty()

    def clear_playback(self) -> int:
        with self._lock:
            cleared_count, cleared_bytes = self._drain_playback_queue()
            self._last_discarded_chunks = cleared_count
            self._last_discarded_bytes = cleared_bytes
            self._is_playing_flag = False
            return cleared_count

    def wait_playback_complete(self, timeout: Optional[float] = None) -> bool:
        start = time.time()
        while self.is_playing():
            if timeout and (time.time() - start) > timeout:
                return False
            time.sleep(0.01)
        return True

    @property
    def played_chunks(self) -> List[bytes]:
        with self._lock:
            return list(self._played_chunks)

    def reset(self) -> None:
        with self._lock:
            self.clear_playback()
            self._played_chunks.clear()
            self._cancel_event.clear()
            self._is_playing_flag = False
            self.last_cancellation_latency_ms = 0.0
            self._last_discarded_chunks = 0
            self._last_discarded_bytes = 0


class SoundDeviceAudioBackend(AudioBackend):
    """
    Hardware audio backend using sounddevice RawInputStream & RawOutputStream.
    Gracefully handles missing audio devices, falling back to a quiet no-op mode.
    """

    def __init__(self, input_device: Optional[int] = None, output_device: Optional[int] = None):
        self.input_device = input_device
        self.output_device = output_device
        self._input_stream: Any = None
        self._output_stream: Any = None
        self._is_input_running = False
        self._is_playing_flag = False
        self._lock = threading.RLock()
        self._playback_queue: queue.Queue[bytes] = queue.Queue()
        self._cancel_event = threading.Event()
        self._player_thread: Optional[threading.Thread] = None
        self._last_discarded_chunks: int = 0
        self._last_discarded_bytes: int = 0

    def start_input(
        self,
        sample_rate: int,
        channels: int,
        chunk_size: int,
        callback: Callable[[bytes], None]
    ) -> bool:
        with self._lock:
            if self._is_input_running:
                return True
            try:
                import sounddevice as sd

                def _stream_cb(indata, frames, time_info, status):
                    if not self._is_input_running:
                        raise sd.CallbackStop()
                    if status:
                        logger.warning(f"[SoundDeviceAudioBackend] Status: {status}")
                    callback(bytes(indata))

                self._input_stream = sd.RawInputStream(
                    samplerate=sample_rate,
                    blocksize=chunk_size,
                    device=self.input_device,
                    dtype="int16",
                    channels=channels,
                    callback=_stream_cb
                )
                self._input_stream.start()
                self._is_input_running = True
                return True
            except Exception as e:
                logger.warning(f"[SoundDeviceAudioBackend] Cannot open microphone: {e}")
                self._is_input_running = False
                return False

    def stop_input(self) -> None:
        with self._lock:
            self._is_input_running = False
            if self._input_stream:
                try:
                    self._input_stream.stop()
                    self._input_stream.close()
                except Exception:
                    pass
                self._input_stream = None

    def is_input_active(self) -> bool:
        with self._lock:
            return self._is_input_running

    def play_chunk(self, pcm_bytes: bytes, sample_rate: int) -> None:
        with self._lock:
            self._is_playing_flag = True
            try:
                import sounddevice as sd
                import numpy as np
                audio_np = np.frombuffer(pcm_bytes, dtype=np.int16)
                sd.play(audio_np, samplerate=sample_rate)
            except Exception as e:
                logger.debug(f"[SoundDeviceAudioBackend] Play error: {e}")

    def stop_playback(self) -> float:
        t0 = time.perf_counter()
        with self._lock:
            try:
                import sounddevice as sd
                sd.stop()
            except Exception:
                pass
            self._is_playing_flag = False
            self.clear_playback()
        t1 = time.perf_counter()
        return (t1 - t0) * 1000.0

    def is_playing(self) -> bool:
        with self._lock:
            if self._is_playing_flag:
                try:
                    import sounddevice as sd
                    stream = sd.get_stream()
                    if stream and stream.active:
                        return True
                except Exception:
                    pass
            return self._is_playing_flag

    def clear_playback(self) -> int:
        with self._lock:
            cleared = 0
            while not self._playback_queue.empty():
                try:
                    self._playback_queue.get_nowait()
                    cleared += 1
                except queue.Empty:
                    break
            self._last_discarded_chunks = cleared
            self._is_playing_flag = False
            return cleared

    def wait_playback_complete(self, timeout: Optional[float] = None) -> bool:
        try:
            import sounddevice as sd
            sd.wait()
            return True
        except Exception:
            return True


# ---------------------------------------------------------------------------
# Pluggable Streaming TTS Synthesizer Adapters (<150ms TTFA)
# ---------------------------------------------------------------------------

class BaseTTSAdapter(ABC):
    """Abstract interface for pluggable streaming neural TTS synthesizers."""

    @abstractmethod
    def synthesize_stream(
        self,
        text_or_stream: Union[str, Iterator[str]],
        cancel_event: threading.Event
    ) -> Iterator[Tuple[bytes, int]]:
        """
        Synthesizes speech in real-time chunks.
        Yields (pcm_chunk_bytes, sample_rate).
        Must terminate immediately if cancel_event.is_set().
        """
        pass


class KokoroTTSAdapter(BaseTTSAdapter):
    """Streaming adapter for Kokoro ONNX neural TTS (24kHz)."""

    def __init__(self, voice: str = "af_heart", speed: float = 1.0):
        self.voice = voice
        self.speed = speed
        self._pipeline = None
        self._chunker = StreamingTextChunker()

    def _ensure_pipeline(self):
        if self._pipeline is None:
            from kokoro import KPipeline
            self._pipeline = KPipeline(lang_code="a")

    def synthesize_stream(
        self,
        text_or_stream: Union[str, Iterator[str]],
        cancel_event: threading.Event
    ) -> Iterator[Tuple[bytes, int]]:
        self._ensure_pipeline()
        import numpy as np

        for text_chunk in self._chunker.chunk_text(text_or_stream):
            if cancel_event.is_set():
                break
            for _, _, audio in self._pipeline(text_chunk, voice=self.voice, speed=self.speed):
                if cancel_event.is_set():
                    break
                if audio is None:
                    continue
                if hasattr(audio, "cpu"):
                    audio = audio.cpu().numpy()
                elif hasattr(audio, "numpy"):
                    audio = audio.numpy()

                if audio.dtype == np.float32:
                    pcm = (np.clip(audio, -1.0, 1.0) * 32767.0).astype(np.int16).tobytes()
                else:
                    pcm = audio.astype(np.int16).tobytes()
                yield (pcm, 24000)


class PiperTTSAdapter(BaseTTSAdapter):
    """Streaming adapter for Piper ONNX neural TTS."""

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or os.getenv("HELM_PIPER_MODEL", "en_US-lessac-medium.onnx")
        self._voice = None
        self._chunker = StreamingTextChunker()

    def _ensure_voice(self):
        if self._voice is None:
            import piper
            self._voice = piper.PiperVoice.load(self.model_path)

    def synthesize_stream(
        self,
        text_or_stream: Union[str, Iterator[str]],
        cancel_event: threading.Event
    ) -> Iterator[Tuple[bytes, int]]:
        self._ensure_voice()
        import io, wave

        for text_chunk in self._chunker.chunk_text(text_or_stream):
            if cancel_event.is_set():
                break
            buf = io.BytesIO()
            with wave.open(buf, "wb") as wf:
                self._voice.synthesize(text_chunk, wf)
            buf.seek(0)
            with wave.open(buf, "rb") as wf:
                sample_rate = wf.getframerate()
                n_frames = wf.getnframes()
                pcm = wf.readframes(n_frames)
            if cancel_event.is_set():
                break
            if pcm:
                yield (pcm, sample_rate)


class CustomGeneratorTTSAdapter(BaseTTSAdapter):
    """Wraps any custom generator callable for streaming audio generation."""

    def __init__(
        self,
        generator_func: Callable[[Union[str, Iterator[str]], threading.Event], Iterator[Tuple[bytes, int]]]
    ):
        self.generator_func = generator_func

    def synthesize_stream(
        self,
        text_or_stream: Union[str, Iterator[str]],
        cancel_event: threading.Event
    ) -> Iterator[Tuple[bytes, int]]:
        return self.generator_func(text_or_stream, cancel_event)


class MockTTSAdapter(BaseTTSAdapter):
    """
    Deterministic mock TTS synthesizer generating valid 16-bit PCM chunks
    with sub-150ms TTFA delivery and instantaneous barge-in aborting.
    """

    def __init__(
        self,
        sample_rate: int = 24000,
        chunk_duration_sec: float = 0.05,
        first_chunk_delay_sec: float = 0.01
    ):
        self.sample_rate = sample_rate
        self.chunk_duration_sec = chunk_duration_sec
        self.first_chunk_delay_sec = first_chunk_delay_sec
        self._chunker = StreamingTextChunker()
        self.chunks_generated: int = 0
        self.was_cancelled: bool = False

    def synthesize_stream(
        self,
        text_or_stream: Union[str, Iterator[str]],
        cancel_event: threading.Event
    ) -> Iterator[Tuple[bytes, int]]:
        self.chunks_generated = 0
        self.was_cancelled = False
        samples_per_chunk = int(self.sample_rate * self.chunk_duration_sec)

        first = True
        for chunk_idx, text_chunk in enumerate(self._chunker.chunk_text(text_or_stream)):
            if cancel_event.is_set():
                self.was_cancelled = True
                break

            if first and self.first_chunk_delay_sec > 0:
                time.sleep(self.first_chunk_delay_sec)
                first = False

            # Synthesize 440Hz audible sine wave in 16-bit PCM
            freq = 440.0 + (chunk_idx * 50.0)
            raw_samples = [
                int(12000 * math.sin(2 * math.pi * freq * i / self.sample_rate))
                for i in range(samples_per_chunk)
            ]
            pcm = struct.pack(f"<{len(raw_samples)}h", *raw_samples)

            if cancel_event.is_set():
                self.was_cancelled = True
                break

            self.chunks_generated += 1
            yield (pcm, self.sample_rate)


# ---------------------------------------------------------------------------
# Full-Duplex Conversational Voice Pipeline
# ---------------------------------------------------------------------------

class HelmLiveVoicePipeline:
    """
    Priority 5 Full-Duplex Real-Time Conversational Voice Engine.
    
    Coordinates:
    - Continuous microphone capture listening loop
    - Concurrent streaming audio playback
    - Silero VAD barge-in with instantaneous (<50ms) interruption cancellation
    - Queue draining and speech transition
    - Pluggable streaming TTS chunker (<150ms TTFA)
    - Thread-safe state machine: IDLE, LISTENING, PROCESSING, SPEAKING, INTERRUPTED
    - Event callbacks for frames, speech, interruptions, and state changes
    """

    def __init__(
        self,
        config: Optional[LiveVoiceConfig] = None,
        backend: Optional[AudioBackend] = None,
        tts_adapter: Optional[BaseTTSAdapter] = None,
        vad_engine: Optional[SileroVADEngine] = None,
        on_audio_frame: Optional[Callable[[bytes], None]] = None,
        on_speech_start: Optional[Callable[[], None]] = None,
        on_speech_end: Optional[Callable[[bytes, int], None]] = None,
        on_interruption: Optional[Callable[[InterruptionEvent], None]] = None,
        on_state_change: Optional[Callable[[VoiceState, VoiceState], None]] = None,
        on_tts_chunk: Optional[Callable[[bytes, int], None]] = None,
    ):
        self.config = config or LiveVoiceConfig()
        self.backend = backend or MockAudioBackend()
        self.tts_adapter = tts_adapter or MockTTSAdapter(sample_rate=self.config.playback_sample_rate)
        self.vad = vad_engine or SileroVADEngine(
            threshold=self.config.vad_threshold,
            energy_threshold=self.config.energy_fallback_threshold
        )

        # Callbacks
        self.on_audio_frame = on_audio_frame
        self.on_speech_start = on_speech_start
        self.on_speech_end = on_speech_end
        self.on_interruption = on_interruption
        self.on_state_change = on_state_change
        self.on_tts_chunk = on_tts_chunk

        # State machine
        self._state = VoiceState.IDLE
        self._state_lock = threading.RLock()

        # Speech accumulation & VAD
        self._speech_buffer: List[bytes] = []
        self._user_speaking = False
        self._silence_frames = 0

        # Streaming TTS playback coordination
        self._tts_queue: queue.Queue[Tuple[bytes, int]] = queue.Queue(maxsize=self.config.max_queue_size)
        self._tts_cancel_event = threading.Event()
        self._tts_thread: Optional[threading.Thread] = None
        self._tts_chunk_index = 0

        # Performance & telemetry metrics
        self.total_barge_in_count = 0
        self.last_barge_in_latency_ms: float = 0.0
        self.last_time_to_first_chunk_ms: float = 0.0
        self.total_speech_turns = 0

    # -----------------------------------------------------------------------
    # State Management
    # -----------------------------------------------------------------------

    @property
    def state(self) -> VoiceState:
        with self._state_lock:
            return self._state

    def _transition_state(self, new_state: VoiceState, reason: str = "") -> None:
        """Atomically transitions state and notifies listeners."""
        with self._state_lock:
            old_state = self._state
            if old_state == new_state:
                return
            self._state = new_state
            logger.debug(f"[LiveVoice] State change: {old_state} -> {new_state} ({reason})")

        if self.on_state_change:
            try:
                self.on_state_change(old_state, new_state)
            except Exception as e:
                logger.error(f"[LiveVoice] Error in on_state_change callback: {e}")

    # -----------------------------------------------------------------------
    # Lifecycle Control
    # -----------------------------------------------------------------------

    def start(self) -> bool:
        """Starts continuous microphone listening in full-duplex mode."""
        with self._state_lock:
            if self._state != VoiceState.IDLE:
                return True

            self.vad.initialize()
            started = self.backend.start_input(
                sample_rate=self.config.sample_rate,
                channels=self.config.channels,
                chunk_size=self.config.chunk_size,
                callback=self.push_audio_frame
            )
            if not started:
                logger.warning("[LiveVoice] AudioBackend failed to start input stream")
                return False

            self._transition_state(VoiceState.LISTENING, "pipeline_started")
            return True

    def stop(self) -> None:
        """Stops the pipeline, cancels any active playback, and resets to IDLE."""
        with self._state_lock:
            self._cancel_ongoing_speech(reason="pipeline_stopped")
            self.backend.stop_input()
            self._transition_state(VoiceState.IDLE, "pipeline_stopped")
            self._speech_buffer.clear()
            self._user_speaking = False
            self._silence_frames = 0

    # -----------------------------------------------------------------------
    # Continuous Input & Barge-In Detection Loop
    # -----------------------------------------------------------------------

    def push_audio_frame(self, pcm_bytes: bytes, sample_rate: Optional[int] = None) -> None:
        """
        Processes an incoming PCM frame from microphone.
        Evaluates Silero VAD, triggers instant barge-in if AI is speaking,
        and accumulates user utterance.
        """
        if not pcm_bytes:
            return

        rate = sample_rate or self.config.sample_rate

        # 1. Fire raw frame callback
        if self.on_audio_frame:
            try:
                self.on_audio_frame(pcm_bytes)
            except Exception as e:
                logger.error(f"[LiveVoice] Error in on_audio_frame: {e}")

        # 2. Evaluate VAD
        has_voice = self.vad.detect_voice(pcm_bytes, sample_rate=rate)

        with self._state_lock:
            current = self._state

            # Handle Barge-In Interruption
            if has_voice and current in (VoiceState.SPEAKING, VoiceState.PROCESSING):
                # User spoke while TTS was playing or processing!
                t_detect = time.perf_counter()
                interruption_event = self._cancel_ongoing_speech(reason="barge_in_user_speech")
                t_cancelled = time.perf_counter()
                interruption_event.latency_ms = (t_cancelled - t_detect) * 1000.0
                self.last_barge_in_latency_ms = interruption_event.latency_ms
                self.total_barge_in_count += 1

                # Enter INTERRUPTED state briefly
                self._transition_state(VoiceState.INTERRUPTED, "barge_in_detected")
                if self.on_interruption:
                    try:
                        self.on_interruption(interruption_event)
                    except Exception as e:
                        logger.error(f"[LiveVoice] Error in on_interruption callback: {e}")

                # Transition immediately to capturing the interruption prompt
                self._transition_state(VoiceState.LISTENING, "capturing_interruption_prompt")
                self._user_speaking = True
                self._silence_frames = 0
                self._speech_buffer = [pcm_bytes]
                if self.on_speech_start:
                    try:
                        self.on_speech_start()
                    except Exception as e:
                        logger.error(f"[LiveVoice] Error in on_speech_start: {e}")
                return

            # Normal listening turn logic
            if has_voice:
                if not self._user_speaking:
                    self._user_speaking = True
                    self._silence_frames = 0
                    self._speech_buffer = [pcm_bytes]
                    if self.on_speech_start:
                        try:
                            self.on_speech_start()
                        except Exception as e:
                            logger.error(f"[LiveVoice] Error in on_speech_start: {e}")
                else:
                    self._silence_frames = 0
                    self._speech_buffer.append(pcm_bytes)
            else:
                # Silence frame
                if self._user_speaking:
                    self._silence_frames += 1
                    self._speech_buffer.append(pcm_bytes)

                    # Silence threshold reached -> Speech end
                    if self._silence_frames >= self.config.silence_frames_threshold:
                        self._user_speaking = False
                        self._silence_frames = 0
                        captured_audio = b"".join(self._speech_buffer)
                        self._speech_buffer = []
                        self.vad.reset_states()
                        self.total_speech_turns += 1

                        self._transition_state(VoiceState.PROCESSING, "user_speech_complete")

                        if self.on_speech_end:
                            try:
                                self.on_speech_end(captured_audio, rate)
                            except Exception as e:
                                logger.error(f"[LiveVoice] Error in on_speech_end: {e}")

    # -----------------------------------------------------------------------
    # Streaming Speech Synthesis & Playback (<150ms TTFA)
    # -----------------------------------------------------------------------

    def speak(self, text: str, blocking: bool = False) -> None:
        """
        Synthesizes and speaks text using streaming chunker with <150ms TTFA.
        """
        self.speak_stream(iter([text]), blocking=blocking)

    def speak_stream(
        self,
        text_stream: Union[str, Iterator[str]],
        blocking: bool = False
    ) -> None:
        """
        Streams synthesized audio chunks to playback backend.
        Delivers first audio chunk in <150ms.
        """
        with self._state_lock:
            # Cancel any previous speech playback
            self._cancel_ongoing_speech(reason="new_speech_command")
            self._tts_cancel_event.clear()
            self._tts_chunk_index = 0
            self._transition_state(VoiceState.SPEAKING, "tts_playback_started")

        def _synthesize_and_play():
            t_start = time.perf_counter()
            first_chunk = True

            try:
                chunk_gen = self.tts_adapter.synthesize_stream(
                    text_stream,
                    cancel_event=self._tts_cancel_event
                )

                for pcm_chunk, sample_rate in chunk_gen:
                    if self._tts_cancel_event.is_set():
                        break

                    if first_chunk:
                        first_chunk = False
                        t_first = time.perf_counter()
                        self.last_time_to_first_chunk_ms = (t_first - t_start) * 1000.0
                        logger.debug(
                            f"[LiveVoice] Time-to-first-audio (TTFA): "
                            f"{self.last_time_to_first_chunk_ms:.2f}ms"
                        )

                    self._tts_chunk_index += 1
                    if self.on_tts_chunk:
                        try:
                            self.on_tts_chunk(pcm_chunk, self._tts_chunk_index)
                        except Exception as e:
                            logger.error(f"[LiveVoice] on_tts_chunk error: {e}")

                    # Play chunk
                    self.backend.play_chunk(pcm_chunk, sample_rate)

                # Wait for playback to finish if not interrupted
                if not self._tts_cancel_event.is_set():
                    self.backend.wait_playback_complete(timeout=5.0)

            except Exception as e:
                logger.error(f"[LiveVoice] Speech stream error: {e}")
            finally:
                with self._state_lock:
                    if self._state == VoiceState.SPEAKING and not self._tts_cancel_event.is_set():
                        self._transition_state(VoiceState.LISTENING, "speech_completed_naturally")

        self._tts_thread = threading.Thread(
            target=_synthesize_and_play,
            daemon=True,
            name="LiveVoiceSynthesizer"
        )
        self._tts_thread.start()

        if blocking:
            self._tts_thread.join()

    # -----------------------------------------------------------------------
    # Barge-In & Instant Cancellation Mechanics (<50ms)
    # -----------------------------------------------------------------------

    def _cancel_ongoing_speech(self, reason: str = "") -> InterruptionEvent:
        """
        Instantly halts TTS generation, flushes pending playback queues,
        and mutes soundcard output in < 50ms.
        """
        t0 = time.perf_counter()

        # 1. Signal synthesis generator abort
        self._tts_cancel_event.set()

        # 2. Stop audio backend output
        backend_latency = self.backend.stop_playback()
        backend_cleared_chunks = getattr(self.backend, "_last_discarded_chunks", 0)
        backend_cleared_bytes = getattr(self.backend, "_last_discarded_bytes", 0)

        # 3. Drain pending chunks in pipeline TTS queue if any
        discarded_count = backend_cleared_chunks
        discarded_bytes = backend_cleared_bytes
        while not self._tts_queue.empty():
            try:
                chunk, _ = self._tts_queue.get_nowait()
                discarded_count += 1
                discarded_bytes += len(chunk)
            except queue.Empty:
                break

        t1 = time.perf_counter()
        total_latency_ms = (t1 - t0) * 1000.0

        event = InterruptionEvent(
            timestamp=time.time(),
            latency_ms=total_latency_ms,
            active_state_prior=self._state,
            discarded_chunks_count=discarded_count,
            discarded_bytes_count=discarded_bytes,
            interruption_reason=reason,
            details={"backend_latency_ms": backend_latency}
        )
        return event

    def interrupt(self, reason: str = "manual_barge_in") -> InterruptionEvent:
        """Explicitly triggers barge-in interruption."""
        with self._state_lock:
            event = self._cancel_ongoing_speech(reason=reason)
            self._transition_state(VoiceState.INTERRUPTED, reason)
            if self.on_interruption:
                try:
                    self.on_interruption(event)
                except Exception as e:
                    logger.error(f"[LiveVoice] Error in on_interruption: {e}")
            self._transition_state(VoiceState.LISTENING, "ready_after_interruption")
            return event


# ---------------------------------------------------------------------------
# Factory & Helper Functions
# ---------------------------------------------------------------------------

def create_live_voice_pipeline(
    mock_mode: bool = False,
    config: Optional[LiveVoiceConfig] = None,
    backend: Optional[AudioBackend] = None,
    tts_adapter: Optional[BaseTTSAdapter] = None,
    vad_engine: Optional[SileroVADEngine] = None,
    **callbacks
) -> HelmLiveVoicePipeline:
    """
    Factory function to create and configure a HelmLiveVoicePipeline.
    If mock_mode is True, uses in-memory mock backend, mock TTS adapter,
    and fast energy VAD.
    """
    cfg = config or LiveVoiceConfig()

    if mock_mode or os.getenv("HELM_VOICE_MOCK") == "1":
        actual_backend = backend or MockAudioBackend(simulate_realtime=False)
        actual_tts = tts_adapter or MockTTSAdapter(sample_rate=cfg.playback_sample_rate)
        actual_vad = vad_engine or SileroVADEngine(
            threshold=cfg.vad_threshold,
            energy_threshold=cfg.energy_fallback_threshold,
            use_neural=False
        )
    else:
        actual_backend = backend or SoundDeviceAudioBackend()
        actual_vad = vad_engine or SileroVADEngine(
            threshold=cfg.vad_threshold,
            energy_threshold=cfg.energy_fallback_threshold,
            use_neural=True
        )
        # Auto-detect best TTS adapter
        if tts_adapter is not None:
            actual_tts = tts_adapter
        else:
            try:
                import kokoro
                actual_tts = KokoroTTSAdapter()
            except ImportError:
                try:
                    import piper
                    actual_tts = PiperTTSAdapter()
                except ImportError:
                    actual_tts = MockTTSAdapter(sample_rate=cfg.playback_sample_rate)

    pipeline = HelmLiveVoicePipeline(
        config=cfg,
        backend=actual_backend,
        tts_adapter=actual_tts,
        vad_engine=actual_vad,
        **callbacks
    )
    return pipeline
