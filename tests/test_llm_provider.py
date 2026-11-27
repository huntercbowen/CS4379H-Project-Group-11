import json
import unittest

from unittest.mock import patch, MagicMock
from urllib.error import HTTPError

from llm.provider import LLMProviderError
from llm.gemini_provider import GeminiProvider


class TestGeminiProvider(unittest.TestCase):

    def setUp(self):
        self.provider = GeminiProvider(api_key="test-key")
        self.model = "gemini-3.5-flash-lite"

        self.mock_data = {
            "responseId": "test-response",
            "modelVersion": self.model,
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": '{"attack_applicable": true}'
                            }
                        ]
                    },
                    "finishReason": "STOP"
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 100,
                "candidatesTokenCount": 50,
                "totalTokenCount": 150
            }
        }

    def test_parse_response(self):

        response = self.provider.parse_response(
            self.mock_data,
            self.model,
            0.5
        )

        self.assertEqual(response.provider, "google")
        self.assertEqual(response.model, self.model)
        self.assertEqual(response.total_tokens, 150)
        self.assertEqual(response.finish_reason, "STOP")
        self.assertEqual(response.elapsed_seconds, 0.5)

        self.assertEqual(
            response.content,
            '{"attack_applicable": true}'
        )

    @patch("llm.gemini_provider.urlopen")
    def test_generate_response(self, mock_urlopen):

        mock_response = MagicMock()

        mock_response.read.return_value = (
            json.dumps(self.mock_data).encode("utf-8")
        )

        mock_urlopen.return_value.__enter__.return_value = (
            mock_response
        )

        response = self.provider.generate(
            "Test prompt",
            self.model
        )

        self.assertEqual(response.provider, "google")
        self.assertEqual(response.total_tokens, 150)

        mock_urlopen.assert_called_once()

    @patch("llm.gemini_provider.urlopen")
    def test_independent_request(self, mock_urlopen):

        mock_response = MagicMock()

        mock_response.read.return_value = (
            json.dumps(self.mock_data).encode("utf-8")
        )

        mock_urlopen.return_value.__enter__.return_value = (
            mock_response
        )

        self.provider.generate("Test prompt", self.model)

        request = mock_urlopen.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))

        self.assertEqual(
            payload["contents"],
            [
                {
                    "role": "user",
                    "parts": [{"text": "Test prompt"}]
                }
            ]
        )

        self.assertEqual(
            payload["generationConfig"]["temperature"],
            0
        )

        self.assertNotIn("tools", payload)

    def test_unsupported_model(self):

        with self.assertRaises(LLMProviderError):
            self.provider.generate(
                "Test prompt",
                "invalid-model"
            )

    @patch.dict("os.environ", {}, clear=True)
    def test_missing_api_key(self):

        with self.assertRaises(LLMProviderError):
            GeminiProvider()

    def test_invalid_response(self):

        with self.assertRaises(LLMProviderError):
            self.provider.parse_response(
                {},
                self.model,
                0.5
            )

    @patch("llm.gemini_provider.urlopen")
    def test_rate_limit(self, mock_urlopen):

        mock_urlopen.side_effect = HTTPError(
            url="https://example.com",
            code=429,
            msg="Too Many Requests",
            hdrs=None,
            fp=None
        )

        with self.assertRaisesRegex(LLMProviderError, "429"):
            self.provider.generate(
                "Test prompt",
                self.model
            )

    def test_thought_parts_excluded(self):

        data = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": "Internal thought",
                                "thought": True
                            },
                            {
                                "text": "Final answer"
                            }
                        ]
                    }
                }
            ]
        }

        response = self.provider.parse_response(
            data,
            self.model,
            0.5
        )

        self.assertEqual(response.content, "Final answer")


if __name__ == "__main__":
    unittest.main()