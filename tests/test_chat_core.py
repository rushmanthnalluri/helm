"""Acceptance checks for the text-first conversation and streaming seam."""

import json
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import chat_core


class FakeResponse:
    def __init__(self, lines=(), status_code=200):
        self._lines = lines
        self.status_code = status_code

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_lines(self, decode_unicode=True):
        yield from self._lines

    def close(self):
        pass


class TestChatCore(unittest.TestCase):
    def test_history_is_passed_each_turn_and_reply_is_appended(self):
        received = []

        def fake_provider(messages, system_prompt, prefs, tools, on_delta):
            received.append((messages.copy(), system_prompt))
            text = f"Remembered {messages[0]['content']}"
            on_delta(text)
            return text

        core = chat_core.AgentCore("mission prompt", {}, provider_call=fake_provider)
        streamed = []
        core.turn("My color is amber", streamed.append)
        core.turn("What color did I say?", streamed.append)

        self.assertEqual(streamed[0], "Remembered My color is amber")
        self.assertEqual(len(received[1][0]), 3)
        self.assertEqual(received[1][0][0], {"role": "user", "content": "My color is amber"})
        self.assertEqual(received[1][0][1]["role"], "assistant")
        self.assertEqual(received[1][0][2]["content"], "What color did I say?")
        self.assertEqual(received[1][1], "mission prompt")

    def test_provider_failure_rolls_back_unanswered_turn(self):
        def fail(*args):
            raise chat_core.ProviderError("offline")

        core = chat_core.AgentCore("mission", {}, provider_call=fail)
        with self.assertRaises(chat_core.ProviderError):
            core.turn("hello", lambda _: None)
        self.assertEqual(core.messages, [])

    @patch("chat_core.ai_engine.get_active_provider")
    @patch("chat_core.requests.post")
    def test_openai_compatible_response_streams_and_sends_history(self, post, get_provider):
        get_provider.return_value = {
            "provider": "groq",
            "name": "Groq",
            "base_url": "https://api.example.test/v1",
            "model": "test-model",
            "api_key": "test-secret",
        }
        post.return_value = FakeResponse([
            b'data: {"choices":[{"delta":{"content":"Hello "}}]}',
            b'data: {"choices":[{"delta":{"content":"there."}}]}',
            b"data: [DONE]",
        ])
        chunks = []
        messages = [{"role": "user", "content": "Hi"}, {"role": "assistant", "content": "Hey"}]

        result = chat_core.stream_provider_turn(messages, "You are Homie.", {}, [], chunks.append)

        self.assertEqual(result.text, "Hello there.")
        self.assertEqual(chunks, ["Hello ", "there."])
        payload = post.call_args.kwargs["json"]
        self.assertTrue(payload["stream"])
        self.assertEqual(payload["messages"][1:], messages)
        self.assertNotIn("test-secret", json.dumps(payload))

    @patch("chat_core.ai_engine.get_active_provider")
    @patch("chat_core.requests.post")
    def test_gemini_history_roles_and_stream_chunks(self, post, get_provider):
        get_provider.return_value = {
            "provider": "gemini",
            "name": "Gemini",
            "base_url": "https://generativelanguage.googleapis.com",
            "model": "test-model",
            "api_key": "test-secret",
        }
        post.return_value = FakeResponse([
            'data: {"candidates":[{"content":{"parts":[{"text":"Amber"}]}}]}',
        ])
        chunks = []
        messages = [
            {"role": "user", "content": "My color is amber."},
            {"role": "assistant", "content": "Noted."},
        ]

        result = chat_core.stream_provider_turn(messages, "System prompt", {}, [], chunks.append)

        self.assertEqual(result.text, "Amber")
        payload = post.call_args.kwargs["json"]
        self.assertEqual([item["role"] for item in payload["contents"]], ["user", "model"])
        self.assertEqual(payload["systemInstruction"]["parts"][0]["text"], "System prompt")

    @patch("chat_core.ai_engine.get_active_provider")
    @patch("chat_core.requests.post")
    def test_gemini_function_call_preserves_thought_signature_for_followup(self, post, get_provider):
        get_provider.return_value = {
            "provider": "gemini", "name": "Gemini",
            "base_url": "https://generativelanguage.googleapis.com",
            "model": "test-model", "api_key": "secret",
        }
        provider_part = {
            "functionCall": {"name": "homie_get_vitals", "args": {}},
            "thoughtSignature": "signature-placeholder",
        }
        post.return_value = FakeResponse([
            "data: " + json.dumps({"candidates": [{"content": {"parts": [provider_part]}}]}),
        ])
        tools = [{"type": "function", "function": {
            "name": "homie_get_vitals", "description": "Read PC health.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        }}]

        result = chat_core.stream_provider_turn(
            [{"role": "user", "content": "Read PC health"}], "system", {}, tools, lambda _: None
        )

        self.assertEqual(result.tool_calls[0].provider_payload, provider_part)
        self.assertEqual(post.call_args.kwargs["json"]["tools"][0]["functionDeclarations"][0]["parameters"]["type"], "OBJECT")
        followup = chat_core._gemini_contents([
            {"role": "user", "content": "Read PC health"},
            {"role": "assistant", "content": None, "tool_calls": [{
                "id": result.tool_calls[0].call_id,
                "name": result.tool_calls[0].name,
                "arguments": result.tool_calls[0].arguments,
                "gemini_part": result.tool_calls[0].provider_payload,
            }]},
            {"role": "tool", "name": "homie_get_vitals", "content": '{"ok":true}'},
        ])
        self.assertEqual(followup[1]["parts"][0], provider_part)
        self.assertEqual(followup[2]["parts"][0]["functionResponse"]["name"], "homie_get_vitals")

    @patch("chat_core.ai_engine.get_active_provider")
    @patch("chat_core.requests.post")
    def test_rate_limit_has_clear_recoverable_error(self, post, get_provider):
        get_provider.return_value = {
            "provider": "groq", "name": "Groq", "base_url": "https://api.example.test/v1",
            "model": "test-model", "api_key": "secret",
        }
        post.return_value = FakeResponse(status_code=429)

        with self.assertRaisesRegex(chat_core.ProviderError, "rate-limiting"):
            chat_core.stream_provider_turn([{"role": "user", "content": "Hi"}], "system", {}, [], lambda _: None)

    @patch("chat_core.ai_engine.get_active_provider")
    @patch("chat_core.requests.post")
    def test_openai_tool_call_arguments_are_streamed_and_parsed(self, post, get_provider):
        get_provider.return_value = {
            "provider": "groq", "name": "Groq", "base_url": "https://api.example.test/v1",
            "model": "test-model", "api_key": "secret",
        }
        post.return_value = FakeResponse([
            b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call-1","type":"function","function":{"name":"homie_list_downloads","arguments":"{\\"limit\\":"}}]}}]}',
            b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"3}"}}]}}]}',
            b"data: [DONE]",
        ])
        tools = [{"type": "function", "function": {
            "name": "homie_list_downloads", "description": "List files.",
            "parameters": {"type": "object", "properties": {"limit": {"type": "integer"}}},
        }}]

        result = chat_core.stream_provider_turn(
            [{"role": "user", "content": "Show recent downloads"}], "system", {}, tools, lambda _: None
        )

        self.assertEqual(result.text, "")
        self.assertEqual(result.tool_calls[0].call_id, "call-1")
        self.assertEqual(result.tool_calls[0].name, "homie_list_downloads")
        self.assertEqual(result.tool_calls[0].arguments, '{"limit":3}')
        self.assertEqual(post.call_args.kwargs["json"]["tools"], tools)

    def test_model_tool_calls_execute_sequentially_and_results_return_to_model(self):
        class FakeRegistry:
            def __init__(self):
                self.executed = []

            def schemas(self):
                return [{"type": "function", "function": {"name": "read_one"}}]

            def execute(self, name, args, caller_id):
                self.executed.append((name, args, caller_id))
                return {"ok": True, "data": f"result-{name}"}

        registry = FakeRegistry()
        seen = []

        def fake_provider(messages, system_prompt, prefs, tools, on_delta):
            seen.append((messages.copy(), tools))
            if len(seen) == 1:
                return chat_core.ModelTurn(tool_calls=[
                    chat_core.ToolCall("call-1", "read_one", '{"id": 1}'),
                    chat_core.ToolCall("call-2", "read_two", '{"id": 2}'),
                ])
            return chat_core.ModelTurn("Both read-only results are ready.")

        core = chat_core.AgentCore("system", {}, tool_registry=registry, provider_call=fake_provider)
        reply = core.turn("Read both sources", lambda _: None)

        self.assertEqual(reply, "Both read-only results are ready.")
        self.assertEqual(registry.executed, [
            ("read_one", {"id": 1}, "ai_text_agent"),
            ("read_two", {"id": 2}, "ai_text_agent"),
        ])
        self.assertEqual(len(seen[1][0]), 4)
        self.assertEqual([message["role"] for message in seen[1][0]], ["user", "assistant", "tool", "tool"])
        self.assertEqual(seen[1][0][2]["content"], '{"ok": true, "data": "result-read_one"}')

    def test_tool_loop_is_bounded_and_failed_turn_is_removed(self):
        class FakeRegistry:
            def schemas(self):
                return []

            def execute(self, *args, **kwargs):
                return {"ok": True}

        def endless_tool_call(*args):
            return chat_core.ModelTurn(tool_calls=[chat_core.ToolCall("id", "unknown", "{}")])

        core = chat_core.AgentCore("system", {}, tool_registry=FakeRegistry(), provider_call=endless_tool_call,
                                   max_tool_rounds=1)
        with self.assertRaisesRegex(chat_core.ProviderError, "tool-call limit"):
            core.turn("Keep calling", lambda _: None)
        self.assertEqual(core.messages, [])

    def test_failed_tool_result_is_returned_to_model_for_recovery(self):
        class FailingRegistry:
            def schemas(self):
                return [{"type": "function", "function": {"name": "read_one"}}]

            def execute(self, name, args, caller_id):
                return {"ok": False, "error": "The read timed out."}

        requests = []

        def provider(messages, system_prompt, prefs, tools, on_delta):
            requests.append(messages.copy())
            if len(requests) == 1:
                return chat_core.ModelTurn(tool_calls=[chat_core.ToolCall("call", "read_one", "{}")])
            return chat_core.ModelTurn("I could not read that value because the tool timed out.")

        core = chat_core.AgentCore("system", {}, tool_registry=FailingRegistry(), provider_call=provider)
        reply = core.turn("Read the value", lambda _: None)

        self.assertIn("timed out", reply)
        tool_result = json.loads(requests[1][-1]["content"])
        self.assertEqual(tool_result, {"ok": False, "error": "The read timed out."})

    def test_local_fast_action_uses_the_same_turn_history(self):
        core = chat_core.AgentCore("system", {}, provider_call=lambda *args: self.fail("provider should not run"))
        streamed = []
        handled = []

        reply = core.turn(
            "What time is it?",
            streamed.append,
            caller_id="desktop_voice",
            quick_action_handler=lambda text, caller_id: handled.append((text, caller_id)) or (True, "It is noon."),
        )

        self.assertEqual(reply, "It is noon.")
        self.assertEqual(streamed, ["It is noon."])
        self.assertEqual(handled, [("What time is it?", "desktop_voice")])
        self.assertEqual([message["role"] for message in core.messages], ["user", "assistant"])

    def test_turn_cancel_signal_stops_provider_and_rolls_back_history(self):
        entered = threading.Event()
        cancel_event = threading.Event()

        def waiting_provider(messages, system_prompt, prefs, tools, on_delta, cancel_event=None):
            entered.set()
            cancel_event.wait(timeout=2)
            raise chat_core.TurnCancelled("Turn interrupted.")

        core = chat_core.AgentCore("system", {}, provider_call=waiting_provider)
        error = []

        def run_turn():
            try:
                core.turn("Interrupt me", lambda _: None, cancel_event=cancel_event)
            except Exception as exc:
                error.append(exc)

        worker = threading.Thread(target=run_turn)
        worker.start()
        self.assertTrue(entered.wait(timeout=1))
        cancel_event.set()
        worker.join(timeout=2)

        self.assertFalse(worker.is_alive())
        self.assertIsInstance(error[0], chat_core.TurnCancelled)
        self.assertEqual(core.messages, [])

    @patch("chat_core.ai_engine.get_active_provider")
    @patch("chat_core.requests.post")
    def test_cancel_closes_an_open_stream_and_returns_promptly(self, post, get_provider):
        class BlockingResponse(FakeResponse):
            def __init__(self):
                super().__init__()
                self.reading = threading.Event()
                self.closed = threading.Event()

            def iter_lines(self, decode_unicode=True):
                self.reading.set()
                self.closed.wait(timeout=2)
                if False:
                    yield ""

            def close(self):
                self.closed.set()

        response = BlockingResponse()
        get_provider.return_value = {
            "provider": "groq", "name": "Groq", "base_url": "https://api.example.test/v1",
            "model": "test-model", "api_key": "secret",
        }
        post.return_value = response
        cancel_event = threading.Event()
        errors = []

        def request():
            try:
                chat_core.stream_provider_turn(
                    [{"role": "user", "content": "Wait"}], "system", {}, [], lambda _: None,
                    cancel_event=cancel_event,
                )
            except Exception as exc:
                errors.append(exc)

        worker = threading.Thread(target=request)
        worker.start()
        self.assertTrue(response.reading.wait(timeout=1))
        cancel_event.set()
        worker.join(timeout=1)

        self.assertFalse(worker.is_alive())
        self.assertTrue(response.closed.is_set())
        self.assertIsInstance(errors[0], chat_core.TurnCancelled)


if __name__ == "__main__":
    unittest.main()
