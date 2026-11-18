"""
Homie Streaming Voice Pipeline — Sub-400ms latency voice I/O.
Replaces the batch record → transcribe → respond → speak loop.
Upgraded with Silero VAD v5 neural voice detection, regex filler-word filtering,
and local neural TTS (Kokoro / Piper / SAPI5 fallback).
"""
import threading
import queue
import time
import logging
import re
from typing import Callable, Optional, Sequence

logger = logging.getLogger(__name__)


class FillerWordFilter:
    """
    Regex post-processor that strips conversational filler words from transcripts.
    Removes common filler words like 'um', 'uh', 'ah', 'like', 'you know'
    from Whisper output while cleaning up whitespace and punctuation.
    """
    DEFAULT_FILLERS = ("um", "uh", "ah", "like", "you know")

    def __init__(self, fillers: Optional[Sequence[str]] = None):
        self.fillers = tuple(fillers) if fillers is not None else self.DEFAULT_FILLERS
        self._regex = self._build_regex(self.fillers)

    @classmethod
    def _build_regex(cls, fillers: Sequence[str]) -> re.Pattern:
        # Sort descending by length so multi-word fillers match before subwords
        sorted_fillers = sorted(fillers, key=len, reverse=True)
        escaped_fillers = []
        for f in sorted_fillers:
            clean_f = f.strip()
            if " " in clean_f:
                subwords = [re.escape(w) for w in clean_f.split()]
                escaped_fillers.append(r"\s+".join(subwords))
            else:
                if clean_f.lower() in ("um", "uh", "ah"):
                    escaped_fillers.append(re.escape(clean_f) + r"+")
                else:
                    escaped_fillers.append(re.escape(clean_f))

        inner = "|".join(escaped_fillers)
        # Match filler with optional surrounding commas and whitespace
        pattern_str = rf"(?:,\s*)?\b(?:{inner})\b(?:\s*,)?"
        return re.compile(pattern_str, re.IGNORECASE)

    def filter(self, text: str) -> str:
        """Strip filler words and tidy surrounding punctuation and spacing."""
        if not text:
            return ""

        orig_was_capitalized = text[0].isupper() if text else False
        cleaned = self._regex.sub(" ", text)

        # Cleanup punctuation and repeated spaces
        cleaned = re.sub(r"\s+,", ",", cleaned)
        cleaned = re.sub(r",\s*,+", ",", cleaned)
        cleaned = re.sub(r"^\s*[,.:;?!]\s*", "", cleaned)
        cleaned = re.sub(r"\s*,\s*$", "", cleaned)
        cleaned = re.sub(r"\s{2,}", " ", cleaned).strip()

        # Preserve sentence capitalization if first word was stripped
        if cleaned and orig_was_capitalized and cleaned[0].islower():
            cleaned = cleaned[0].upper() + cleaned[1:]

        return cleaned

    def strip(self, text: str) -> str:
        """Alias for filter()."""
        return self.filter(text)

    def __call__(self, text: str) -> str:
        return self.filter(text)


class StreamingVoicePipeline:
    """
    Streaming VAD+STT+TTS pipeline with GPU acceleration detection.
    
    Flow:
    1. Audio chunks stream in via push_audio_chunk()
    2. Silero VAD v5 (or simple energy VAD fallback) detects end-of-speech
    3. faster-whisper transcribes on GPU (CUDA) → DirectML → CPU fallback
    4. FillerWordFilter removes speech fillers ('um', 'uh', 'like', etc.)
    5. on_transcript callback fires immediately
    6. LLM response streams back token by token
    7. Each sentence fires to neural TTS as it arrives (first-sentence latency ~400ms)
    """

    def __init__(self, on_transcript: Callable[[str], None], 
                 whisper_model: str = "base", language: str = "en",
                 filler_filter: Optional[Callable[[str], str]] = None,
                 vad_threshold: float = 0.5):
        self.on_transcript = on_transcript
        self.whisper_model_name = whisper_model
        self.language = language
        self.filler_filter = filler_filter if filler_filter is not None else FillerWordFilter()
        self.vad_threshold = vad_threshold

        self._model = None
        self._device = None
        self._vad_model = None
        self._vad_initialized = False

        self._audio_buffer = []
        self._vad_active = False
        self._silence_frames = 0
        self._SILENCE_THRESHOLD = 15  # ~300ms at 16kHz/20ms chunks
        self._lock = threading.Lock()
        self._transcript_queue = queue.Queue()

    def _detect_device(self):
        """Detect best available compute device for whisper."""
        try:
            import torch
            if torch.cuda.is_available():
                logger.info("[VoicePipeline] Device: CUDA (GPU)")
                return "cuda", "float16"
        except (ImportError, Exception):
            pass
        logger.info("[VoicePipeline] Device: CPU (INT8)")
        return "cpu", "int8"

    def _init_silero_vad(self) -> bool:
        """
        Load Silero VAD v5 using torch.hub or silero-vad package.
        Falls back cleanly to energy VAD if torch or network is unavailable.
        """
        if self._vad_initialized:
            return self._vad_model is not None
        self._vad_initialized = True

        try:
            import torch
            # 1. Try silero_vad package if available
            try:
                from silero_vad import load_silero_vad
                self._vad_model = load_silero_vad()
                logger.info("[VoicePipeline] Silero VAD loaded via silero_vad package")
                return True
            except (ImportError, Exception):
                pass

            # 2. Use torch.hub: torch.hub.load('snakers4/silero-vad', 'silero_vad', force_reload=False)
            try:
                try:
                    loaded = torch.hub.load('snakers4/silero-vad', 'silero_vad', force_reload=False, trust_repo=True)
                except TypeError:
                    loaded = torch.hub.load('snakers4/silero-vad', 'silero_vad', force_reload=False)

                if isinstance(loaded, tuple):
                    self._vad_model = loaded[0]
                else:
                    self._vad_model = loaded
                if hasattr(self._vad_model, 'eval'):
                    self._vad_model.eval()
                logger.info("[VoicePipeline] Silero VAD v5 loaded via torch.hub")
                return True
            except Exception as hub_err:
                logger.warning(f"[VoicePipeline] torch.hub Silero VAD load failed: {hub_err}")
                self._vad_model = None
                return False
        except (ImportError, Exception) as torch_err:
            logger.info(f"[VoicePipeline] PyTorch not available for Silero VAD: {torch_err}")
            self._vad_model = None
            return False

    def initialize(self):
        """Load faster-whisper model and Silero VAD on best available device."""
        self._init_silero_vad()
        try:
            from faster_whisper import WhisperModel
            self._device, compute_type = self._detect_device()
            try:
                self._model = WhisperModel(
                    self.whisper_model_name, 
                    device=self._device, 
                    compute_type=compute_type
                )
            except Exception as device_exc:
                if self._device != "cpu":
                    logger.warning(f"[VoicePipeline] Failed on {self._device}, falling back to CPU: {device_exc}")
                    self._device = "cpu"
                    compute_type = "int8"
                    self._model = WhisperModel(
                        self.whisper_model_name,
                        device=self._device,
                        compute_type=compute_type
                    )
                else:
                    raise device_exc
            logger.info(f"[VoicePipeline] faster-whisper loaded on {self._device}")
            return True
        except Exception as e:
            logger.error(f"[VoicePipeline] Failed to load model: {e}")
            return False

    def _energy_vad(self, pcm_bytes: bytes, threshold: float = 500.0) -> bool:
        """Simple energy-based VAD as fallback when Silero unavailable."""
        import struct
        if not pcm_bytes:
            return False
        num_samples = len(pcm_bytes) // 2
        if num_samples == 0:
            return False
        samples = struct.unpack(f"<{num_samples}h", pcm_bytes[:num_samples*2])
        rms = (sum(s*s for s in samples) / len(samples)) ** 0.5
        return rms > threshold

    def detect_voice(self, pcm_bytes: bytes, sample_rate: int = 16000, threshold: Optional[float] = None) -> bool:
        """
        Detect voice activity in PCM chunk (16-bit mono).
        Uses Silero VAD v5 on 512-sample chunks at 16kHz;
        falls back to RMS energy-based VAD if Silero is unavailable.
        """
        if not pcm_bytes:
            return False

        if not self._vad_initialized:
            self._init_silero_vad()

        thresh = threshold if threshold is not None else self.vad_threshold

        if self._vad_model is not None:
            try:
                import torch
                import numpy as np

                # Convert 16-bit PCM bytes to float32 tensor normalized between -1.0 and 1.0
                audio_np = np.frombuffer(pcm_bytes, dtype=np.int16).astype(np.float32) / 32768.0
                if len(audio_np) == 0:
                    return False

                audio_tensor = torch.from_numpy(audio_np)
                # Silero VAD v5 expects 512 samples at 16kHz, 256 at 8kHz
                chunk_len = 512 if sample_rate >= 16000 else 256

                with torch.no_grad():
                    if len(audio_tensor) < chunk_len:
                        padded = torch.zeros(chunk_len, dtype=torch.float32)
                        padded[:len(audio_tensor)] = audio_tensor
                        prob = self._vad_model(padded, sample_rate)
                        val = prob.item() if hasattr(prob, 'item') else float(prob)
                        return val > thresh

                    # Process in 512-sample chunks
                    for idx in range(0, len(audio_tensor) - chunk_len + 1, chunk_len):
                        chunk = audio_tensor[idx : idx + chunk_len]
                        prob = self._vad_model(chunk, sample_rate)
                        val = prob.item() if hasattr(prob, 'item') else float(prob)
                        if val > thresh:
                            return True

                    # Check trailing remainder if audio length is not an exact multiple of 512
                    rem = len(audio_tensor) % chunk_len
                    if rem > 0 and len(audio_tensor) > chunk_len:
                        last_chunk = audio_tensor[-chunk_len:]
                        prob = self._vad_model(last_chunk, sample_rate)
                        val = prob.item() if hasattr(prob, 'item') else float(prob)
                        if val > thresh:
                            return True

                return False
            except Exception as e:
                logger.warning(f"[VoicePipeline] Silero VAD inference failed ({e}), using energy fallback")
                return self._energy_vad(pcm_bytes)
        else:
            return self._energy_vad(pcm_bytes)

    def push_audio_chunk(self, pcm_bytes: bytes, sample_rate: int = 16000):
        """
        Feed a raw PCM chunk (16-bit mono) into the pipeline.
        Automatically detects end-of-speech using Silero VAD and triggers transcription.
        """
        with self._lock:
            has_voice = self.detect_voice(pcm_bytes, sample_rate=sample_rate)
            if has_voice:
                self._vad_active = True
                self._silence_frames = 0
                self._audio_buffer.append(pcm_bytes)
            elif self._vad_active:
                self._silence_frames += 1
                self._audio_buffer.append(pcm_bytes)
                if self._silence_frames >= self._SILENCE_THRESHOLD:
                    # End of speech detected — transcribe
                    audio_data = b"".join(self._audio_buffer)
                    self._audio_buffer = []
                    self._vad_active = False
                    self._silence_frames = 0
                    if self._vad_model is not None and hasattr(self._vad_model, 'reset_states'):
                        try:
                            self._vad_model.reset_states()
                        except Exception:
                            pass
                    threading.Thread(
                        target=self._transcribe_and_fire,
                        args=(audio_data, sample_rate),
                        daemon=True
                    ).start()

    def transcribe_buffer(self, audio_bytes: bytes, sample_rate: int = 16000) -> str:
        """Transcribe a complete audio buffer (for push-to-talk mode)."""
        if self._model is None:
            return ""
        return self._run_whisper(audio_bytes, sample_rate)

    def _transcribe_and_fire(self, audio_bytes: bytes, sample_rate: int):
        text = self._run_whisper(audio_bytes, sample_rate)
        if text.strip():
            self.on_transcript(text.strip())

    def _run_whisper(self, audio_bytes: bytes, sample_rate: int) -> str:
        """Run faster-whisper on audio bytes and filter filler words."""
        if self._model is None:
            return ""
        try:
            import numpy as np
            import io, wave
            buf = io.BytesIO()
            with wave.open(buf, 'wb') as wf:
                wf.setnchannels(1)
                wf.setsampwidth(2)
                wf.setframerate(sample_rate)
                wf.writeframes(audio_bytes)
            buf.seek(0)
            segments, _ = self._model.transcribe(buf, language=self.language, beam_size=1)
            raw_text = " ".join(seg.text for seg in segments).strip()
            if self.filler_filter:
                return self.filler_filter(raw_text)
            return raw_text
        except Exception as e:
            logger.error(f"[VoicePipeline] Transcription error: {e}")
            return ""

    def speak(self, text: str, blocking: bool = False) -> None:
        """
        Speak response text using NeuralTTS (Kokoro -> Piper -> SAPI5).
        Replaces legacy SAPI/pyttsx3 calls.
        """
        from homie_tts import NeuralTTS
        NeuralTTS.instance().speak(text, blocking=blocking)

    def stop_speaking(self) -> None:
        """Stop any active speech playback."""
        from homie_tts import NeuralTTS
        NeuralTTS.instance().stop()


def speak_text(text: str, blocking: bool = False) -> None:
    """Module-level helper to speak text using NeuralTTS."""
    from homie_tts import NeuralTTS
    NeuralTTS.instance().speak(text, blocking=blocking)


def stop_speaking() -> None:
    """Module-level helper to stop speech playback."""
    from homie_tts import NeuralTTS
    NeuralTTS.instance().stop()


def create_pipeline(on_transcript: Callable[[str], None], **kwargs) -> StreamingVoicePipeline:
    """Factory — creates and initializes the pipeline."""
    p = StreamingVoicePipeline(on_transcript=on_transcript, **kwargs)
    p.initialize()
    return p
