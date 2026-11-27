import json
import os
import time

from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from llm.provider import (
    LLMProvider,
    LLMResponse,
    LLMProviderError
)


class GeminiProvider(LLMProvider):
    """Communicates with Google's Gemini API."""

    BASE_URL = (
        "https://generativelanguage.googleapis.com/v1beta/models"
    )

    SUPPORTED_MODELS = (
        "gemini-3.1-flash-lite",
        "gemini-3.5-flash-lite",
        "gemini-3.6-flash",
    )

    def __init__(self, api_key=None, timeout=120):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.timeout = timeout

        if not self.api_key:
            raise LLMProviderError(
                "GEMINI_API_KEY environment variable is not configured."
            )

    def generate(self, prompt: str, model: str) -> LLMResponse:
        """Submit one independent prompt to a Google model."""

        if model not in self.SUPPORTED_MODELS:
            raise LLMProviderError(
                f"Unsupported model: {model}"
            )

        url = f"{self.BASE_URL}/{model}:generateContent"

        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0,
                "maxOutputTokens": 4096
            }
        }

        request = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "x-goog-api-key": self.api_key,
                "Content-Type": "application/json"
            },
            method="POST"
        )

        start_time = time.perf_counter()

        try:
            with urlopen(request, timeout=self.timeout) as response:
                data = json.loads(
                    response.read().decode("utf-8")
                )

        except HTTPError as error:
            detail = error.reason

            try:    
                if error.fp is not None:
                    error_data = json.loads(
                        error.read().decode("utf-8")
                    )

                    detail = error_data.get("error", {}).get(
                        "message",
                        error.reason
                )

            except (ValueError, UnicodeError, AttributeError):
                pass

            finally:
                error.close()
                
            raise LLMProviderError(
                f"Google API returned HTTP {error.code}: {detail}"
            ) from error

        except (URLError, TimeoutError) as error:
            raise LLMProviderError(
                f"Connection failed: {error}"
            ) from error

        except (ValueError, UnicodeError) as error:
            raise LLMProviderError(
                "Google returned an invalid response."
            ) from error

        elapsed = time.perf_counter() - start_time

        return self.parse_response(data, model, elapsed)

    def parse_response(self, data, model, elapsed):
        """Convert Google's response into an LLMResponse."""

        try:
            candidate = data["candidates"][0]

            parts = candidate.get("content", {}).get("parts", [])

            content = "\n".join(
                part["text"]
                for part in parts
                if "text" in part and not part.get("thought", False)
            )

            usage = data.get("usageMetadata") or {}

            return LLMResponse(
                provider="google",
                model=data.get("modelVersion", model),
                content=content,
                elapsed_seconds=elapsed,
                prompt_tokens=usage.get("promptTokenCount", 0),
                completion_tokens=usage.get("candidatesTokenCount", 0),
                total_tokens=usage.get("totalTokenCount", 0),
                finish_reason=candidate.get("finishReason"),
                response_id=data.get("responseId")
            )

        except (KeyError, IndexError, TypeError, ValueError) as error:
            raise LLMProviderError(
                "Google returned an unexpected or blocked response."
            ) from error