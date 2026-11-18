"""
Homie Neural TTS Engine — Local low-latency neural speech synthesis.
Prioritizes Kokoro (24kHz natural neural) -> Piper (ONNX) -> pyttsx3 / Windows SAPI5 fallback.
"""
import os
import io
import wave
import time
import logging
import threading
from typing import Optional, Any

logger = logging.getLogger(__name__)

BACKEND_KOKORO = "kokoro"
BACKEND_PIPER = "piper"
BACKEND_PYTTSX3 = "pyttsx3"
BACKEND_SAPI5 = "sapi5"


class NeuralTTS:
    """
    Thread-safe singleton Neural TTS synthesizer.
    
    Backend Priority:
    1. Kokoro neural TTS (af_heart voice, 24kHz)
    2. Piper ONNX neural TTS (en_US-lessac-medium)
    3. pyttsx3 / Windows SAPI5 (zero-dependency fallback)
    """
    _instance: Optional["NeuralTTS"] = None
    _singleton_lock = threading.Lock()

    def __init__(self):
        self._lock = threading.Lock()
        self._backend: Optional[str] = None
        self._model: Any = None
        self._is_speaking_flag = False
        self._initialized = False
        self._current_thread: Optional[threading.Thread] = None

    @classmethod
    def instance(cls) -> "NeuralTTS":
        """Get or create the singleton NeuralTTS instance."""
        if cls._instance is None:
            with cls._singleton_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance (primarily for tests)."""
        with cls._singleton_lock:
            if cls._instance is not None:
                cls._instance.stop()
            cls._instance = None

    @property
    def backend(self) -> Optional[str]:
        """Return the active synthesis backend."""
        if not self._initialized:
            self._lazy_init()
        return self._backend

    def _lazy_init(self) -> None:
        """Initialize best available TTS backend on first use."""
        with self._lock:
            if self._initialized:
                return

            # 1. Primary: Kokoro
            try:
                from kokoro import KPipeline
                self._model = KPipeline(lang_code='a')
                self._backend = BACKEND_KOKORO
                self._initialized = True
                logger.info("[NeuralTTS] Loaded primary backend: Kokoro (lang=a, 24kHz)")
                return
            except (ImportError, Exception) as k_err:
                logger.debug(f"[NeuralTTS] Kokoro unavailable ({k_err}), checking Piper")

            # 2. Fallback: Piper
            try:
                import piper
                model_path = os.getenv("HOMIE_PIPER_MODEL", "en_US-lessac-medium.onnx")
                self._model = piper.PiperVoice.load(model_path)
                self._backend = BACKEND_PIPER
                self._initialized = True
                logger.info(f"[NeuralTTS] Loaded fallback backend: Piper ONNX ({model_path})")
                return
            except (ImportError, Exception) as p_err:
                logger.debug(f"[NeuralTTS] Piper unavailable ({p_err}), checking pyttsx3/SAPI5")

            # 3. Fallback: pyttsx3
            try:
                import pyttsx3
                engine = pyttsx3.init()
                self._model = engine
                self._backend = BACKEND_PYTTSX3
                self._initialized = True
                logger.info("[NeuralTTS] Loaded fallback backend: pyttsx3")
                return
            except (ImportError, Exception) as pyttsx_err:
                logger.debug(f"[NeuralTTS] pyttsx3 unavailable ({pyttsx_err}), checking SAPI5")

            # 4. Native Windows SAPI5 SpVoice fallback
            try:
                import win32com.client
                sp = win32com.client.Dispatch("SAPI.SpVoice")
                self._model = sp
                self._backend = BACKEND_SAPI5
                self._initialized = True
                logger.info("[NeuralTTS] Loaded native Windows SAPI5 SpVoice fallback")
                return
            except Exception as sapi_err:
                logger.error(f"[NeuralTTS] All TTS backends failed to initialize: {sapi_err}")
                self._backend = None
                self._initialized = True

    def is_speaking(self) -> bool:
        """Check if speech synthesis/playback is currently in progress."""
        if self._is_speaking_flag:
            return True
        try:
            import sounddevice as sd
            stream = sd.get_stream()
            if stream and stream.active:
                return True
        except Exception:
            pass
        return False

    def stop(self) -> None:
        """Stop any ongoing speech playback immediately."""
        self._is_speaking_flag = False
        # Stop sounddevice playback
        try:
            import sounddevice as sd
            sd.stop()
        except Exception:
            pass

        # Stop SAPI if running (flag 2 = SVSFPurgeBeforeSpeak)
        if self._backend == BACKEND_SAPI5 and self._model is not None:
            try:
                self._model.Speak("", 2)
            except Exception:
                pass

        # Stop pyttsx3 if running
        if self._backend == BACKEND_PYTTSX3 and self._model is not None:
            try:
                self._model.stop()
            except Exception:
                pass

    def speak(self, text: str, blocking: bool = False) -> None:
        """
        Synthesize and speak text.
        
        Args:
            text: Text string to speak.
            blocking: If True, blocks until speech is finished playing;
                      if False (default), speaks asynchronously in background.
        """
        if not text or not str(text).strip():
            return

        if not self._initialized:
            self._lazy_init()

        if blocking:
            self._do_speak(str(text))
        else:
            t = threading.Thread(target=self._do_speak, args=(str(text),), daemon=True)
            self._current_thread = t
            t.start()

    def _do_speak(self, text: str) -> None:
        """Execute speech synthesis on the active backend."""
        self._is_speaking_flag = True
        try:
            backend = self._backend
            if backend == BACKEND_KOKORO:
                self._speak_kokoro(text)
            elif backend == BACKEND_PIPER:
                self._speak_piper(text)
            elif backend == BACKEND_PYTTSX3:
                self._speak_pyttsx3(text)
            elif backend == BACKEND_SAPI5:
                self._speak_sapi5(text)
            else:
                logger.warning(f"[NeuralTTS] No available backend to speak: {text}")
        except Exception as e:
            logger.error(f"[NeuralTTS] Error during speech synthesis ({self._backend}): {e}")
            if self._backend != BACKEND_SAPI5:
                try:
                    self._speak_sapi5(text)
                except Exception as fallback_err:
                    logger.error(f"[NeuralTTS] SAPI5 emergency fallback failed: {fallback_err}")
        finally:
            self._is_speaking_flag = False

    def _speak_kokoro(self, text: str) -> None:
        """Synthesize using Kokoro KPipeline and play via sounddevice."""
        import sounddevice as sd

        for _, _, audio in self._model(text, voice='af_heart', speed=1.0):
            if not self._is_speaking_flag:
                break
            if audio is None:
                continue
            if hasattr(audio, 'cpu'):
                audio = audio.cpu().numpy()
            elif hasattr(audio, 'numpy'):
                audio = audio.numpy()
            sd.play(audio, samplerate=24000)
            sd.wait()

    def _speak_piper(self, text: str) -> None:
        """Synthesize using Piper and play via sounddevice."""
        import sounddevice as sd
        import io, wave
        import numpy as np

        buf = io.BytesIO()
        with wave.open(buf, 'wb') as wf:
            self._model.synthesize(text, wf)
        buf.seek(0)

        with wave.open(buf, 'rb') as wf:
            sample_rate = wf.getframerate()
            n_frames = wf.getnframes()
            audio_bytes = wf.readframes(n_frames)
            audio = np.frombuffer(audio_bytes, dtype=np.int16)

        if len(audio) > 0 and self._is_speaking_flag:
            sd.play(audio, samplerate=sample_rate)
            sd.wait()

    def _speak_pyttsx3(self, text: str) -> None:
        """Synthesize using pyttsx3."""
        self._model.say(text)
        self._model.runAndWait()

    def _speak_sapi5(self, text: str) -> None:
        """Synthesize using Windows SAPI5 SpVoice."""
        import win32com.client
        if self._model is None:
            self._model = win32com.client.Dispatch("SAPI.SpVoice")
        self._model.Speak(str(text), 0)
