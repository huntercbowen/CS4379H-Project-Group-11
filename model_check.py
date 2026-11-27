from llm.gemini_provider import GeminiProvider
from llm.provider import LLMProviderError


def main():

    try:
        provider = GeminiProvider(timeout=30)
    except LLMProviderError as error:
        print(error)
        return

    results = {}

    print("\n--- Google Model Connectivity Test ---")

    for model in provider.SUPPORTED_MODELS:

        print(f"\nTesting {model}...")

        try:
            response = provider.generate(
                "Reply with only the word SUCCESS.",
                model
            )

            success = (
                response.content.strip().upper() == "SUCCESS"
            )

            results[model] = (
                "PASS" if success else "UNEXPECTED RESPONSE"
            )

            print(f"Response: {response.content}")
            print(f"Time: {response.elapsed_seconds:.3f}s")
            print(f"Tokens: {response.total_tokens}")

        except LLMProviderError as error:
            results[model] = "FAIL"
            print(f"Error: {error}")

    print("\n--- Connectivity Summary ---")

    for model, status in results.items():
        print(f"{model:<30} {status}")


if __name__ == "__main__":
    main()