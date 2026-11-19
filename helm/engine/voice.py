"""Voice recording and Speech-to-Text engine for Helm.
Supports hold-to-talk recording, live audio level streaming for UI waveforms,
and fast on-device Whisper transcription (or lightweight fallback).
"""
import os
import io
import re
import wave
import threading
import numpy as np
import sounddevice as sd

# Directory for caching whisper models
CONFIG_DIR = os.environ.get('HELM_DIR') or os.path.join(os.path.expanduser('~'), '.config', 'helm')
WHISPER_DIR = os.path.join(CONFIG_DIR, 'whisper')

class VoiceEngine:
    def __init__(self, model_size="small", language="en"):
        self.sample_rate = 16000
        self.channels = 1
        self.model_size = model_size
        self.language = language
        self.recording = False
        self.frames = []
        self.stream = None
        self.level_callback = None
        self._whisper_model = None
        self._loading_model = False
        self._lock = threading.Lock()

        # Background load model
        threading.Thread(target=self._load_model, daemon=True).start()

    def _load_model(self):
        with self._lock:
            if self._whisper_model is not None or self._loading_model:
                return
            self._loading_model = True

        try:
            from faster_whisper import WhisperModel
            os.makedirs(WHISPER_DIR, exist_ok=True)
            model = None
            for m in (self.model_size, "small", "base", "tiny"):
                try:
                    model = WhisperModel(m, device="cpu", compute_type="int8", download_root=WHISPER_DIR)
                    break
                except Exception:
                    pass
            with self._lock:
                self._whisper_model = model
        except Exception as e:
            print(f"[Voice] Whisper initialization error: {e}")
        finally:
            self._loading_model = False

    def _audio_callback(self, indata, frames, time_info, status):
        """Audio streaming callback that records frames and computes volume."""
        if not self.recording:
            return
        # Store a copy of incoming audio
        data = indata.copy()
        self.frames.append(data)

        # Compute RMS volume level (normalized 0.0 - 1.0)
        if self.level_callback:
            try:
                rms = np.sqrt(np.mean(data**2))
                level = float(min(1.0, rms * 15))  # scale up for UI responsiveness
                self.level_callback(level)
            except Exception:
                pass

    def start_recording(self, level_callback=None):
        """Starts capturing audio from the default input device."""
        if self.recording:
            return True
        self.frames = []
        self.recording = True
        self.level_callback = level_callback

        # Barge-in: immediately silence any active TTS speech
        stop_speaking()

        try:
            self.stream = sd.InputStream(
                samplerate=self.sample_rate,
                channels=self.channels,
                dtype='float32',
                callback=self._audio_callback
            )
            self.stream.start()
            return True
        except Exception as e:
            self.recording = False
            print(f"[Voice] Failed to start audio stream: {e}")
            return False

    def stop_recording(self):
        """Stops capturing audio and returns a numpy float32 array."""
        if not self.recording:
            return np.array([], dtype=np.float32)

        self.recording = False
        if self.stream:
            try:
                self.stream.stop()
                self.stream.close()
            except Exception:
                pass
            self.stream = None

        if not self.frames:
            return np.array([], dtype=np.float32)

        audio = np.concatenate(self.frames, axis=0).flatten()
        return audio

    def transcribe(self, audio_data):
        """Transcribes audio numpy array to text."""
        if audio_data is None or len(audio_data) < self.sample_rate * 0.2:  # < 0.2 sec
            return ""

        # 1. Try local faster-whisper
        if self._whisper_model is None and not self._loading_model:
            self._load_model()

        if self._whisper_model is not None:
            try:
                segments, _ = self._whisper_model.transcribe(
                    audio_data,
                    language=self.language if self.language != "auto" else None,
                    beam_size=5,
                    vad_filter=True
                )
                text = " ".join(s.text.strip() for s in segments).strip()
                if text:
                    return text
            except Exception as e:
                print(f"[Voice] Whisper transcription error: {e}")

        # 2. Fallback to SpeechRecognition (e.g. Google speech API)
        try:
            import speech_recognition as sr
            # Convert float32 [-1, 1] to 16-bit PCM WAV
            pcm16 = (audio_data * 32767).astype(np.int16)
            wav_io = io.BytesIO()
            with wave.open(wav_io, 'wb') as wf:
                wf.setnchannels(1)
                wf.setsampwidth(2)
                wf.setframerate(self.sample_rate)
                wf.writeframes(pcm16.tobytes())
            wav_io.seek(0)

            recognizer = sr.Recognizer()
            with sr.AudioFile(wav_io) as source:
                audio_record = recognizer.record(source)
                text = recognizer.recognize_google(audio_record)
                return text.strip()
        except Exception as e:
            print(f"[Voice] Fallback recognition error: {e}")

        return ""

_sapi_voice = None
_sapi_lock = threading.Lock()

def get_sapi_voice():
    global _sapi_voice
    with _sapi_lock:
        if _sapi_voice is None:
            try:
                import win32com.client
                _sapi_voice = win32com.client.Dispatch("SAPI.SpVoice")
            except Exception as e:
                print(f"[Voice] Could not initialize SAPI.SpVoice: {e}")
        return _sapi_voice

def speak_text_async(text_to_speak, purge=True):
    """Speaks text asynchronously so user can interrupt (barge-in) anytime."""
    voice = get_sapi_voice()
    if not voice:
        return False
    try:
        # First speech chunk purges prior audio; subsequent chunks queue naturally.
        flags = 1 | (2 if purge else 0)  # SVSFlagsAsync | optional SVSFPurgeBeforeSpeak
        voice.Speak(str(text_to_speak), flags)
        return True
    except Exception as e:
        print(f"[Voice] Async speak error: {e}")
        return False


def speech_friendly_text(text):
    """Remove common Markdown decoration before sending text to speech."""
    import html

    clean = html.unescape(str(text or ""))
    clean = re.sub(r"```[^\n]*\n?", " ", clean)
    clean = re.sub(r"`([^`]*)`", r"\1", clean)
    clean = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", clean)
    clean = re.sub(r"(?<=\d)\s*\*\s*(?=\d)", " times ", clean)
    clean = re.sub(r"^\s{0,3}#{1,6}\s*", "", clean, flags=re.MULTILINE)
    clean = re.sub(r"^\s*(?:[-*+•]|\d+[.)])\s+", "", clean, flags=re.MULTILINE)
    clean = clean.replace("**", "").replace("__", "").replace("~~", "")
    clean = clean.replace("*", "").replace("_", "")
    clean = re.sub(r"[|]+", ", ", clean)
    clean = re.sub(r"[ \t]+", " ", clean)
    clean = re.sub(r" *\n+ *", ". ", clean)
    clean = re.sub(r"\s+([,.;:!?])", r"\1", clean)
    clean = re.sub(r"(?:\.\s*){2,}", ". ", clean)
    return clean.strip()


class SentenceSpeechStreamer:
    """Turn model text deltas into interruptible, queued local speech chunks."""

    def __init__(self, enabled=True, speaker=None, on_start=None):
        self.enabled = enabled
        self._speaker = speaker or speak_text_async
        self._on_start = on_start
        self._buffer = ""
        self._first = True
        self._cancelled = False

    def feed(self, text):
        if not self.enabled or self._cancelled or not text:
            return
        self._buffer += str(text)
        while True:
            match = re.search(r"(?<=[.!?])\s+|[\r\n]+", self._buffer)
            if not match:
                return
            sentence = self._buffer[:match.start()].strip()
            self._buffer = self._buffer[match.end():]
            self._speak(sentence)

    def finish(self):
        if not self.enabled or self._cancelled:
            self._buffer = ""
            return
        sentence = self._buffer.strip()
        self._buffer = ""
        self._speak(sentence)

    def cancel(self):
        self._cancelled = True
        self._buffer = ""

    def _speak(self, sentence):
        if not sentence or self._cancelled:
            return
        spoken_text = speech_friendly_text(sentence)
        if not spoken_text:
            return
        started = bool(self._speaker(spoken_text, purge=self._first))
        if started:
            self._first = False
            if self._on_start:
                self._on_start()

def stop_speaking():
    """Barge-in: Instantly cancels and purges any active speech output."""
    voice = get_sapi_voice()
    if not voice:
        return False
    try:
        # SVSFPurgeBeforeSpeak = 2
        voice.Speak("", 2)
        return True
    except Exception:
        return False

def synthesize_speech_to_wav(text_to_speak, output_wav_path):
    """Synthesizes text to a WAV audio file using Windows native SAPI SpVoice.
    100% offline, zero external dependencies, ultra-fast (<0.1s).
    """
    import win32com.client
    voice = win32com.client.Dispatch("SAPI.SpVoice")
    file_stream = win32com.client.Dispatch("SAPI.SpFileStream")
    file_stream.Open(output_wav_path, 3) # SSFMCreateForWrite = 3
    voice.AudioOutputStream = file_stream
    voice.Speak(str(text_to_speak))
    file_stream.Close()
    return output_wav_path
