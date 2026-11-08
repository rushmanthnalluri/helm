"""WASAPI Loopback Meeting Intelligence and Notes Recorder for Homie.
Captures system audio (Zoom, Teams, Meet, Discord, YouTube) via WASAPI loopback,
transcribes speech asynchronously with Faster-Whisper, and generates structured meeting briefs.
"""
import os
import time
import queue
import sqlite3
import threading
import contextlib
import numpy as np
import event_log

try:
    import pyaudiowpatch as pyaudio
    PYAUDIO_AVAILABLE = True
except ImportError:
    PYAUDIO_AVAILABLE = False

from db_utils import get_db_connection as get_connection, DEFAULT_DB_PATH, CONFIG_DIR

def init_meetings_db(db_path=None):
    with get_connection(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS meetings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                started_at REAL NOT NULL,
                ended_at REAL NOT NULL,
                duration_seconds REAL NOT NULL,
                transcript TEXT NOT NULL,
                summary TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_meeting_started ON meetings(started_at);
        """)
        conn.commit()

def save_meeting(title, started_at, ended_at, duration_seconds, transcript, summary, db_path=None):
    init_meetings_db(db_path)
    with get_connection(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO meetings (title, started_at, ended_at, duration_seconds, transcript, summary) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (str(title), float(started_at), float(ended_at), float(duration_seconds), str(transcript), str(summary))
        )
        conn.commit()
        return cur.lastrowid

def list_recent_meetings(limit=5, db_path=None):
    init_meetings_db(db_path)
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT id, title, started_at, ended_at, duration_seconds, summary FROM meetings "
            "ORDER BY started_at DESC LIMIT ?",
            (int(limit),)
        ).fetchall()
        return [dict(r) for r in rows]

def get_meeting_by_id(meeting_id, db_path=None):
    init_meetings_db(db_path)
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM meetings WHERE id = ?",
            (int(meeting_id),)
        ).fetchone()
        return dict(row) if row else None

class MeetingSession:
    """Manages active meeting recording, transcription, and summarization."""
    def __init__(self, db_path=None):
        self.db_path = db_path
        self.is_active = False
        self.title = ""
        self.started_at = 0.0
        self.audio_queue = queue.Queue()
        self.transcript_segments = []
        self._pa = None
        self._stream = None
        self._worker_thread = None
        self._lock = threading.Lock()
        self.channels = 2
        self.sample_rate = 48000

    def start_meeting(self, title="Meeting"):
        with self._lock:
            if self.is_active:
                return False, f"A meeting is already being recorded ('{self.title}')."

            if not PYAUDIO_AVAILABLE:
                return False, "pyaudiowpatch is not installed. Loopback recording is unavailable."

            self.title = str(title).strip() or "Meeting"
            self.started_at = time.time()
            self.transcript_segments.clear()
            self.audio_queue = queue.Queue()

            try:
                self._pa = pyaudio.PyAudio()
                dev = self._pa.get_default_wasapi_loopback()
                if not dev:
                    self._pa.terminate()
                    self._pa = None
                    return False, "No WASAPI loopback audio device detected on this system."

                self.channels = dev['maxInputChannels']
                self.sample_rate = int(dev['defaultSampleRate'])

                def _stream_cb(in_data, frame_count, time_info, status):
                    if self.is_active and in_data:
                        self.audio_queue.put(in_data)
                    return (None, pyaudio.paContinue)

                self._stream = self._pa.open(
                    format=pyaudio.paInt16,
                    channels=self.channels,
                    rate=self.sample_rate,
                    input=True,
                    input_device_index=dev['index'],
                    stream_callback=_stream_cb
                )
            except Exception as e:
                if self._pa:
                    try:
                        self._pa.terminate()
                    except Exception:
                        pass
                    self._pa = None
                return False, f"Failed to initialize loopback audio stream: {e}"

            self.is_active = True
            self._worker_thread = threading.Thread(target=self._process_audio_worker, daemon=True)
            self._worker_thread.start()

            event_log.log_event("meeting", f"Started recording meeting notes: '{self.title}'", db_path=self.db_path)
            return True, f"🎙️ Meeting notes recording started for **{self.title}**."

    def _process_audio_worker(self):
        """Worker thread accumulating audio chunks and transcribing periodically."""
        buffer = bytearray()
        bytes_per_sec = self.sample_rate * self.channels * 2 # 16-bit PCM = 2 bytes/sample
        chunk_threshold = bytes_per_sec * 8 # 8 seconds of audio

        while self.is_active:
            try:
                try:
                    data = self.audio_queue.get(timeout=1.0)
                    buffer.extend(data)
                except queue.Empty:
                    data = None

                if len(buffer) >= chunk_threshold:
                    raw_chunk = bytes(buffer[:chunk_threshold])
                    buffer = buffer[chunk_threshold:]
                    self._transcribe_pcm_chunk(raw_chunk)
            except Exception:
                pass

        # Drain leftover audio on meeting end
        if len(buffer) > bytes_per_sec * 2: # At least 2 seconds
            try:
                self._transcribe_pcm_chunk(bytes(buffer))
            except Exception:
                pass

    def _transcribe_pcm_chunk(self, raw_bytes):
        """Converts raw multi-channel PCM to mono 16kHz float32 and transcribes."""
        try:
            # Convert bytes to numpy int16
            audio_int16 = np.frombuffer(raw_bytes, dtype=np.int16)
            if self.channels > 1:
                # Downmix to mono
                audio_int16 = audio_int16.reshape(-1, self.channels).mean(axis=1).astype(np.int16)

            # Convert to float32 normalized [-1.0, 1.0]
            audio_f32 = audio_int16.astype(np.float32) / 32768.0

            # Resample to 16kHz for Whisper
            if self.sample_rate != 16000:
                duration_sec = len(audio_f32) / self.sample_rate
                new_len = int(duration_sec * 16000)
                if new_len > 0:
                    indices = np.linspace(0, len(audio_f32) - 1, new_len)
                    audio_f32 = np.interp(indices, np.arange(len(audio_f32)), audio_f32)

            # Transcribe via shared whisper or fallback
            import telegram_bridge
            whisper = telegram_bridge.get_whisper_model()
            if whisper:
                segments, _ = whisper.transcribe(audio_f32, beam_size=3)
                text = " ".join(s.text.strip() for s in segments if s.text.strip())
                if text:
                    self.transcript_segments.append(text)
        except Exception:
            pass

    def stop_meeting(self):
        with self._lock:
            if not self.is_active:
                return False, "No active meeting recording found."

            self.is_active = False
            ended_at = time.time()
            duration = max(1.0, ended_at - self.started_at)

            # Close stream
            if self._stream:
                try:
                    self._stream.stop_stream()
                    self._stream.close()
                except Exception:
                    pass
                self._stream = None

            if self._pa:
                try:
                    self._pa.terminate()
                except Exception:
                    pass
                self._pa = None

        # Wait for worker thread to finish draining
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=3.0)

        full_transcript = " ".join(self.transcript_segments).strip()
        dur_mins = round(duration / 60.0, 1)

        # Generate meeting summary via AI or structured fallback
        summary = self._generate_summary(self.title, full_transcript, duration)

        row_id = save_meeting(
            title=self.title,
            started_at=self.started_at,
            ended_at=ended_at,
            duration_seconds=duration,
            transcript=full_transcript,
            summary=summary,
            db_path=self.db_path
        )

        event_log.log_event(
            "meeting",
            f"Meeting concluded: '{self.title}' ({dur_mins}m, ID {row_id})",
            db_path=self.db_path
        )

        meeting_data = {
            'id': row_id,
            'title': self.title,
            'duration_seconds': duration,
            'duration_formatted': f"{dur_mins} min",
            'transcript': full_transcript,
            'summary': summary
        }
        return True, meeting_data

    def _generate_summary(self, title, transcript, duration_seconds):
        mins = round(duration_seconds / 60.0, 1)
        if not transcript:
            return (
                f"📝 **Meeting Brief: {title}**\n"
                f"• Duration: {mins} minutes\n"
                f"• Status: Recording concluded without detected spoken dialogue."
            )

        prompt = (
            f"You are an executive assistant. Generate a crisp, structured meeting summary from this audio transcript.\n"
            f"Meeting Title: {title}\n"
            f"Duration: {mins} minutes\n\n"
            f"Transcript:\n\"\"\"\n{transcript[:3000]}\n\"\"\"\n\n"
            f"Format with sections:\n"
            f"• 📌 **Executive Summary** (2 sentences)\n"
            f"• 🔑 **Key Discussion Points** (bullet points)\n"
            f"• ✅ **Decisions & Action Items** (who / what)"
        )

        try:
            import ai_engine
            import homie
            prefs = homie.get_prefs()
            res = ai_engine.run_query(prompt, prefs)
            if res and not res.startswith("Error"):
                return f"📝 **Meeting Brief: {title}** ({mins} min)\n\n{res}"
        except Exception:
            pass

        # Structured fallback if AI is offline
        words = len(transcript.split())
        preview = transcript[:250] + ("..." if len(transcript) > 250 else "")
        return (
            f"📝 **Meeting Summary: {title}** ({mins} min, {words} words):\n\n"
            f"📌 **Transcript Excerpt**:\n\"{preview}\"\n\n"
            f"✅ Saved full meeting recording to Homie history."
        )

# Global active session singleton
_GLOBAL_MEETING_SESSION = None

def get_meeting_session():
    global _GLOBAL_MEETING_SESSION
    if _GLOBAL_MEETING_SESSION is None:
        _GLOBAL_MEETING_SESSION = MeetingSession()
    return _GLOBAL_MEETING_SESSION
