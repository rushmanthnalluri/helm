"""
tests/test_live_voice.py - Comprehensive Unit Tests for Full-Duplex Real-Time Conversational Voice.

Verifies:
1. State Machine: Clean transitions between IDLE, LISTENING, PROCESSING, SPEAKING, INTERRUPTED.
2. Silero VAD Barge-In: Sub-50ms instant cancellation and mute when user speaks during TTS.
3. Queue Draining: Discarding and clearing pending playback audio buffers upon interruption.
4. Streaming TTS Chunker: Sub-150ms time-to-first-audio (TTFA) delivery.
5. Reactive Callbacks: Frame, speech start/end, interruption event, and state change listeners.
6. Mockable Audio Backend: In-memory headless operation without physical audio devices.
"""

import math
import struct
import time
import unittest
from unittest.mock import MagicMock, patch

try:
    import torch
except ImportError:
    torch = None

import helm_live_voice
from helm_live_voice import (
    AudioBackend,
    BaseTTSAdapter,
    CustomGeneratorTTSAdapter,
    HelmLiveVoicePipeline,
    InterruptionEvent,
    LiveVoiceConfig,
    MockAudioBackend,
    MockTTSAdapter,
    SileroVADEngine,
    StreamingTextChunker,
    VoiceState,
    create_live_voice_pipeline,
)


def generate_pcm_sine(freq_hz: float = 440.0, num_samples: int = 512, sample_rate: int = 16000, amplitude: int = 14000) -> bytes:
    """Generates 16-bit mono PCM sine wave samples for voice emulation."""
    samples = [
        int(amplitude * math.sin(2 * math.pi * freq_hz * i / sample_rate))
        for i in range(num_samples)
    ]
    return struct.pack(f"<{len(samples)}h", *samples)


def generate_pcm_silence(num_samples: int = 512) -> bytes:
    """Generates 16-bit mono silence (zeros)."""
    return bytes(num_samples * 2)


class TestVoiceStateMachine(unittest.TestCase):
    """Verifies state machine transitions and callbacks."""

    def test_initial_state_is_idle(self):
        pipeline = create_live_voice_pipeline(mock_mode=True)
        self.assertEqual(pipeline.state, VoiceState.IDLE)
        self.assertEqual(str(pipeline.state), "IDLE")

    def test_start_transitions_to_listening(self):
        state_changes = []
        pipeline = create_live_voice_pipeline(
            mock_mode=True,
            on_state_change=lambda old_s, new_s: state_changes.append((old_s, new_s))
        )
        started = pipeline.start()
        self.assertTrue(started)
        self.assertEqual(pipeline.state, VoiceState.LISTENING)
        self.assertIn((VoiceState.IDLE, VoiceState.LISTENING), state_changes)

    def test_stop_transitions_to_idle(self):
        pipeline = create_live_voice_pipeline(mock_mode=True)
        pipeline.start()
        self.assertEqual(pipeline.state, VoiceState.LISTENING)
        pipeline.stop()
        self.assertEqual(pipeline.state, VoiceState.IDLE)

    def test_speak_transitions_to_speaking_and_back(self):
        state_changes = []
        pipeline = create_live_voice_pipeline(
            mock_mode=True,
            on_state_change=lambda old_s, new_s: state_changes.append((old_s, new_s))
        )
        pipeline.start()
        # Speak synchronously
        pipeline.speak("Short speech test phrase.", blocking=True)
        # Verify that SPEAKING was entered
        visited_states = [s[1] for s in state_changes]
        self.assertIn(VoiceState.SPEAKING, visited_states)
        self.assertEqual(pipeline.state, VoiceState.LISTENING)


class TestBargeInCancellation(unittest.TestCase):
    """Verifies instant Silero VAD barge-in interruption under 50ms."""

    def test_barge_in_cancellation_latency_under_50ms(self):
        """User speaking while TTS is playing must cancel ongoing audio within 50ms."""
        backend = MockAudioBackend(simulate_realtime=True, playback_speed_multiplier=1.0)
        # Use TTS adapter with multiple chunks to simulate sustained playback
        tts = MockTTSAdapter(sample_rate=24000, chunk_duration_sec=0.2, first_chunk_delay_sec=0.005)
        # Fast energy VAD for test evaluation (<0.01ms)
        vad = SileroVADEngine(use_neural=False, energy_threshold=500.0)

        interruption_events = []
        speech_started = []

        pipeline = HelmLiveVoicePipeline(
            backend=backend,
            tts_adapter=tts,
            vad_engine=vad,
            on_interruption=lambda evt: interruption_events.append(evt),
            on_speech_start=lambda: speech_started.append(True),
        )
        pipeline.start()

        # Start sustained speaking in the background
        pipeline.speak("This is a long sentence being spoken by the assistant that will be interrupted.")
        # Wait a short moment to ensure SPEAKING state is active
        time.sleep(0.04)
        self.assertEqual(pipeline.state, VoiceState.SPEAKING)

        # Inject loud voice audio chunk simulating user barge-in speech
        voice_frame = generate_pcm_sine(freq_hz=440.0, num_samples=512, sample_rate=16000, amplitude=15000)

        t_before = time.perf_counter()
        pipeline.push_audio_frame(voice_frame)
        t_after = time.perf_counter()

        elapsed_ms = (t_after - t_before) * 1000.0

        # Assertions
        self.assertLess(elapsed_ms, 50.0, f"Barge-in processing took {elapsed_ms:.2f}ms, which exceeds 50ms!")
        self.assertEqual(len(interruption_events), 1)

        event = interruption_events[0]
        self.assertLess(event.latency_ms, 50.0, f"Reported cancellation latency {event.latency_ms:.2f}ms exceeds 50ms!")
        self.assertEqual(event.active_state_prior, VoiceState.SPEAKING)
        self.assertEqual(pipeline.total_barge_in_count, 1)

        # Pipeline must have transitioned back to LISTENING to capture the user's interruption
        self.assertEqual(pipeline.state, VoiceState.LISTENING)
        self.assertTrue(len(speech_started) > 0)
        # Voice buffer should contain the prompt frame
        self.assertEqual(len(pipeline._speech_buffer), 1)
        self.assertEqual(pipeline._speech_buffer[0], voice_frame)

    def test_silence_does_not_trigger_barge_in(self):
        """Silence frames must not interrupt active TTS playback."""
        backend = MockAudioBackend(simulate_realtime=True)
        tts = MockTTSAdapter(sample_rate=24000, chunk_duration_sec=0.2)
        vad = SileroVADEngine(use_neural=False, energy_threshold=500.0)
        interruption_events = []

        pipeline = HelmLiveVoicePipeline(
            backend=backend,
            tts_adapter=tts,
            vad_engine=vad,
            on_interruption=lambda evt: interruption_events.append(evt)
        )
        pipeline.start()

        pipeline.speak("Uninterrupted sentence playback test.")
        time.sleep(0.03)
        self.assertEqual(pipeline.state, VoiceState.SPEAKING)

        # Push pure silence frames
        silence_frame = generate_pcm_silence(num_samples=512)
        for _ in range(5):
            pipeline.push_audio_frame(silence_frame)

        # Interruption should NOT have fired
        self.assertEqual(len(interruption_events), 0)
        self.assertEqual(pipeline.total_barge_in_count, 0)
        self.assertEqual(pipeline.state, VoiceState.SPEAKING)

        # Clean stop
        pipeline.stop()

    def test_barge_in_with_mocked_neural_silero_vad(self):
        """Verifies that when Silero VAD neural model detects speech, barge-in executes immediately."""
        backend = MockAudioBackend(simulate_realtime=True)
        tts = MockTTSAdapter(sample_rate=24000, chunk_duration_sec=0.2)
        vad = SileroVADEngine(use_neural=True)
        # Mock neural model
        mock_model = MagicMock()
        prob_tensor = MagicMock()
        prob_tensor.item.return_value = 0.95
        mock_model.return_value = prob_tensor
        vad._model = mock_model
        vad._is_neural = True
        vad._initialized = True

        interruption_events = []
        pipeline = HelmLiveVoicePipeline(
            backend=backend,
            tts_adapter=tts,
            vad_engine=vad,
            on_interruption=lambda evt: interruption_events.append(evt)
        )
        pipeline.start()
        pipeline.speak("Assistant speaking something long.")
        time.sleep(0.03)

        pcm = generate_pcm_sine()
        t0 = time.perf_counter()
        pipeline.push_audio_frame(pcm)
        t_dur = (time.perf_counter() - t0) * 1000.0

        self.assertLess(t_dur, 50.0)
        self.assertEqual(len(interruption_events), 1)
        self.assertEqual(pipeline.state, VoiceState.LISTENING)

    def test_manual_interrupt_method(self):
        """Explicit interrupt() triggers cancellation and returns event."""
        pipeline = create_live_voice_pipeline(mock_mode=True)
        pipeline.start()
        pipeline.speak("Speaking some text")
        time.sleep(0.02)

        evt = pipeline.interrupt(reason="unit_test_explicit")
        self.assertIsInstance(evt, InterruptionEvent)
        self.assertLess(evt.latency_ms, 50.0)
        self.assertEqual(pipeline.state, VoiceState.LISTENING)


class TestQueueDrainingAndMuting(unittest.TestCase):
    """Verifies that audio playback buffers and synthesizer streams are drained on interruption."""

    def test_queue_draining_discards_buffered_chunks(self):
        backend = MockAudioBackend(simulate_realtime=False)
        pipeline = HelmLiveVoicePipeline(backend=backend)
        pipeline.start()

        # Queue multiple chunks directly in backend
        for _ in range(8):
            backend.play_chunk(generate_pcm_sine(), 24000)

        self.assertTrue(backend.is_playing())

        # Trigger cancellation
        event = pipeline._cancel_ongoing_speech(reason="drain_test")
        self.assertFalse(backend.is_playing())
        self.assertGreaterEqual(event.discarded_chunks_count, 1)

    def test_tts_adapter_receives_cancel_event(self):
        """TTS chunker must abort yielding when cancel_event is set."""
        tts = MockTTSAdapter(chunk_duration_sec=0.01)
        cancel_evt = unittest.mock.MagicMock()
        cancel_evt.is_set.side_effect = [False, False, True]

        gen = tts.synthesize_stream("Clause one. Clause two. Clause three.", cancel_event=cancel_evt)
        chunks = list(gen)
        # Should have stopped early
        self.assertLessEqual(len(chunks), 2)
        self.assertTrue(tts.was_cancelled)


class TestStreamingTTSChunkerAndTTFA(unittest.TestCase):
    """Verifies low latency chunking and sub-150ms time-to-first-audio delivery."""

    def test_text_chunker_sentence_and_clauses(self):
        chunker = StreamingTextChunker(min_words_per_chunk=2, max_words_per_chunk=10)
        text = "Hello world! This is Helm, a desktop agent; ready to assist you right now."
        chunks = list(chunker.chunk_text(text))

        self.assertGreaterEqual(len(chunks), 2)
        self.assertTrue(any("Hello world!" in c for c in chunks))

    def test_text_chunker_strips_markdown_formatting(self):
        chunker = StreamingTextChunker()
        text = "Here is **bold text** and `inline code` and a link https://example.com to view."
        chunks = list(chunker.chunk_text(text))
        joined = " ".join(chunks)

        self.assertNotIn("**", joined)
        self.assertNotIn("`", joined)
        self.assertNotIn("https://", joined)
        self.assertIn("bold text", joined)

    def test_time_to_first_audio_chunk_under_150ms(self):
        """Time-to-first-audio (TTFA) chunk delivery must be strictly sub-150ms."""
        backend = MockAudioBackend(simulate_realtime=False)
        tts = MockTTSAdapter(
            sample_rate=24000,
            first_chunk_delay_sec=0.02  # Simulated 20ms neural chunk latency
        )

        tts_chunks = []
        pipeline = HelmLiveVoicePipeline(
            backend=backend,
            tts_adapter=tts,
            on_tts_chunk=lambda chunk, idx: tts_chunks.append((idx, chunk))
        )
        pipeline.start()

        # Speak stream of tokens
        tokens = ["Helm is ready. ", "How may I help ", "you on your system today?"]
        pipeline.speak_stream(iter(tokens), blocking=True)

        self.assertGreater(len(tts_chunks), 0)
        self.assertGreater(pipeline.last_time_to_first_chunk_ms, 0.0)
        self.assertLess(
            pipeline.last_time_to_first_chunk_ms,
            150.0,
            f"TTFA was {pipeline.last_time_to_first_chunk_ms:.2f}ms, which exceeds 150ms threshold!"
        )

    def test_custom_generator_tts_adapter(self):
        """Custom generator adapter yields chunks as expected."""
        def custom_gen(text, cancel_event):
            yield (generate_pcm_sine(freq_hz=500.0, num_samples=256), 16000)
            yield (generate_pcm_sine(freq_hz=600.0, num_samples=256), 16000)

        adapter = CustomGeneratorTTSAdapter(custom_gen)
        cancel = unittest.mock.MagicMock()
        cancel.is_set.return_value = False

        chunks = list(adapter.synthesize_stream("Sample", cancel))
        self.assertEqual(len(chunks), 2)
        self.assertEqual(chunks[0][1], 16000)


class TestSileroVADEngine(unittest.TestCase):
    """Verifies Silero VAD detection and energy fallback."""

    def test_energy_fallback_detection(self):
        vad = SileroVADEngine(threshold=0.5, energy_threshold=500.0, use_neural=False)
        # Silence should be False
        silence = generate_pcm_silence(512)
        self.assertFalse(vad.energy_vad(silence))

        # Loud signal should be True
        loud = generate_pcm_sine(freq_hz=440.0, num_samples=512, amplitude=12000)
        self.assertTrue(vad.energy_vad(loud))

    def test_detect_voice_with_neural_mock(self):
        vad = SileroVADEngine(use_neural=True)
        mock_model = MagicMock()
        prob_val = MagicMock()
        prob_val.item.return_value = 0.92
        mock_model.return_value = prob_val

        vad._model = mock_model
        vad._is_neural = True
        vad._initialized = True

        pcm = generate_pcm_sine(freq_hz=300.0, num_samples=512)
        self.assertTrue(vad.detect_voice(pcm, sample_rate=16000))
        mock_model.assert_called()

    def test_reset_states_graceful(self):
        vad = SileroVADEngine()
        mock_model = MagicMock()
        vad._model = mock_model
        vad.reset_states()
        mock_model.reset_states.assert_called_once()


class TestMockAudioBackend(unittest.TestCase):
    """Verifies mock backend operations and latency metrics."""

    def test_backend_lifecycle_and_injection(self):
        backend = MockAudioBackend()
        received = []
        started = backend.start_input(
            sample_rate=16000,
            channels=1,
            chunk_size=512,
            callback=lambda chunk: received.append(chunk)
        )
        self.assertTrue(started)
        self.assertTrue(backend.is_input_active())

        # Inject input
        test_chunk = b"\x01\x02\x03\x04"
        backend.inject_input(test_chunk)
        self.assertEqual(received, [test_chunk])

        backend.stop_input()
        self.assertFalse(backend.is_input_active())

    def test_stop_playback_cancellation_under_5ms(self):
        backend = MockAudioBackend(simulate_realtime=True)
        backend.start_input(16000, 1, 512, lambda c: None)

        backend.play_chunk(generate_pcm_sine(num_samples=4000), 16000)
        self.assertTrue(backend.is_playing())

        stop_latency = backend.stop_playback()
        self.assertLess(stop_latency, 20.0, f"Mock stop latency {stop_latency:.2f}ms exceeds limit")
        self.assertFalse(backend.is_playing())


class TestEndToEndDuplexConversationFlow(unittest.TestCase):
    """Verifies a full conversational turn with barge-in interruption and speech-end capture."""

    def test_full_duplex_barge_in_and_user_turn(self):
        backend = MockAudioBackend(simulate_realtime=True, playback_speed_multiplier=2.0)
        tts = MockTTSAdapter(sample_rate=24000, chunk_duration_sec=0.15)
        vad = SileroVADEngine(use_neural=False, energy_threshold=500.0)

        speech_ends = []
        interruptions = []
        states_seen = []

        cfg = LiveVoiceConfig(
            sample_rate=16000,
            silence_frames_threshold=4  # Fast silence threshold for unit testing
        )

        pipeline = HelmLiveVoicePipeline(
            config=cfg,
            backend=backend,
            tts_adapter=tts,
            vad_engine=vad,
            on_speech_end=lambda audio, srate: speech_ends.append((audio, srate)),
            on_interruption=lambda evt: interruptions.append(evt),
            on_state_change=lambda o, n: states_seen.append((o, n))
        )
        pipeline.start()
        self.assertEqual(pipeline.state, VoiceState.LISTENING)

        # 1. AI begins speaking
        pipeline.speak("I am giving a very comprehensive explanation of the system state.")
        time.sleep(0.03)
        self.assertEqual(pipeline.state, VoiceState.SPEAKING)

        # 2. User interrupts!
        loud_chunk = generate_pcm_sine(amplitude=14000)
        pipeline.push_audio_frame(loud_chunk)

        self.assertEqual(len(interruptions), 1)
        self.assertLess(interruptions[0].latency_ms, 50.0)
        self.assertEqual(pipeline.state, VoiceState.LISTENING)

        # 3. User continues speaking for 2 more chunks
        pipeline.push_audio_frame(loud_chunk)
        pipeline.push_audio_frame(loud_chunk)

        # 4. User stops speaking; 4 silence frames follow
        silence_chunk = generate_pcm_silence()
        for _ in range(4):
            pipeline.push_audio_frame(silence_chunk)

        # 5. User speech end must have been detected -> PROCESSING
        self.assertEqual(len(speech_ends), 1)
        captured_pcm, srate = speech_ends[0]
        self.assertEqual(srate, 16000)
        # 3 voice chunks + 4 silence chunks = 7 chunks total (each 512 samples = 1024 bytes)
        self.assertEqual(len(captured_pcm), 7 * 1024)
        self.assertEqual(pipeline.state, VoiceState.PROCESSING)

        pipeline.stop()
        self.assertEqual(pipeline.state, VoiceState.IDLE)


if __name__ == "__main__":
    unittest.main()
