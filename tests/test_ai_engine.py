"""
Tests for AIEngine — mocked HTTP calls, retry logic, JSON parsing, truncation.
"""
import json
from unittest.mock import MagicMock, patch, Mock

import pytest

from userhunt.ai.engine import AIEngine, AIResponse
from userhunt.config import Config


class TestAIEngine:
    def setup_method(self):
        self.config = Config()
        self.config.ai.api_key = "test-key-12345"
        self.config.ai.enabled = True
        self.config.ai.base_url = "https://test.api.com/v1"
        self.config.ai.model = "test-model"
        self.config.ai.calls_made = 0

    def test_unavailable_without_key(self):
        config = Config()
        config.ai.api_key = ""
        engine = AIEngine(config)
        resp = engine._call([{"role": "user", "content": "test"}])
        assert resp.error == "unavailable"

    def test_no_call_cap(self):
        """No call limits — unlimited calls allowed."""
        self.config.ai.max_calls_per_round = 0  # 0 = unlimited
        self.config.ai.calls_made = 999999
        engine = AIEngine(self.config)
        # Should NOT error with 'cap' — it should try the request
        # (will fail with connection error since test.api.com doesn't exist, but not 'cap')
        resp = engine._call([{"role": "user", "content": "test"}])
        assert resp.error != "cap"  # No cap error

    @patch("userhunt.ai.engine.requests.post")
    def test_successful_call(self, mock_post):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "[]"}}],
            "model": "test-model",
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        engine = AIEngine(self.config)
        resp = engine._call([{"role": "user", "content": "test"}])
        assert resp.content == "[]"
        assert resp.error is None
        assert self.config.ai.calls_made == 1

    @patch("userhunt.ai.engine.requests.post")
    def test_retry_on_429(self, mock_post):
        # First call returns 429, second succeeds
        resp_429 = Mock()
        resp_429.status_code = 429

        resp_ok = Mock()
        resp_ok.status_code = 200
        resp_ok.json.return_value = {"choices": [{"message": {"content": "ok"}}], "model": "m"}
        resp_ok.raise_for_status = MagicMock()

        mock_post.side_effect = [resp_429, resp_ok]

        engine = AIEngine(self.config)
        with patch("userhunt.ai.engine.time.sleep"):
            resp = engine._call([{"role": "user", "content": "test"}])
        assert resp.content == "ok"

    @patch("userhunt.ai.engine.requests.post")
    def test_retry_on_500(self, mock_post):
        resp_500 = Mock()
        resp_500.status_code = 500

        resp_ok = Mock()
        resp_ok.status_code = 200
        resp_ok.json.return_value = {"choices": [{"message": {"content": "recovered"}}], "model": "m"}
        resp_ok.raise_for_status = MagicMock()

        mock_post.side_effect = [resp_500, resp_ok]

        engine = AIEngine(self.config)
        with patch("userhunt.ai.engine.time.sleep"):
            resp = engine._call([{"role": "user", "content": "test"}])
        assert resp.content == "recovered"

    @patch("userhunt.ai.engine.requests.post")
    def test_400_removes_response_format(self, mock_post):
        resp_400 = Mock()
        resp_400.status_code = 400

        resp_ok = Mock()
        resp_ok.status_code = 200
        resp_ok.json.return_value = {"choices": [{"message": {"content": "fixed"}}], "model": "m"}
        resp_ok.raise_for_status = MagicMock()

        mock_post.side_effect = [resp_400, resp_ok]

        engine = AIEngine(self.config)
        resp = engine._call([{"role": "user", "content": "test"}])
        assert resp.content == "fixed"

    def test_extract_json_array(self):
        text = '```json\n[{"action": "queue_username", "value": "test"}]\n```'
        result = AIEngine._extract_json(text)
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["action"] == "queue_username"

    def test_extract_json_object(self):
        text = '{"key": "value"}'
        result = AIEngine._extract_json(text)
        assert isinstance(result, dict)
        assert result["key"] == "value"

    def test_extract_json_failure(self):
        text = "No JSON here at all"
        result = AIEngine._extract_json(text)
        assert result == []

    def test_extract_json_with_surrounding_text(self):
        text = 'Here is the result:\n[{"action": "note"}]\nDone.'
        result = AIEngine._extract_json(text)
        assert isinstance(result, list)
        assert len(result) == 1

    def test_reset_round(self):
        self.config.ai.calls_made = 15
        engine = AIEngine(self.config)
        engine.reset_round()
        assert self.config.ai.calls_made == 0

    @patch("userhunt.ai.engine.requests.post")
    def test_message_truncation(self, mock_post):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": [{"message": {"content": "ok"}}], "model": "m"}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        engine = AIEngine(self.config)
        long_text = "x" * 20000
        engine._call([{"role": "user", "content": long_text}], max_chars=12000)

        # Check that the request was made with truncated content
        call_args = mock_post.call_args
        payload = call_args[1]["json"] if "json" in call_args[1] else call_args[0][1]
        # The content should be truncated
        assert len(payload["messages"][0]["content"]) <= 12020  # +20 for "...[truncated]" and rounding

    def test_log_once(self):
        config = Config()
        config.ai.api_key = ""
        engine = AIEngine(config)
        # Should not raise
        engine._log_once("Test message")
        engine._log_once("Test message 2")  # should be skipped


class TestAIResponse:
    def test_defaults(self):
        resp = AIResponse()
        assert resp.content == ""
        assert resp.model == ""
        assert resp.calls_made == 0
        assert resp.error is None

    def test_with_values(self):
        resp = AIResponse(content="test", model="gpt-4", calls_made=1, error="err")
        assert resp.content == "test"
        assert resp.error == "err"
