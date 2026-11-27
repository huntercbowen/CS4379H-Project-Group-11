from cli import CLI
from console_ui import ConsoleUI
from benchmark_service import BenchmarkService
from dataset_loader import DatasetLoader
from prompts import PromptBuilder
from llm.gemini_provider import GeminiProvider


def main():
    try:
        dataset_loader = DatasetLoader()

    except (OSError, ValueError, KeyError) as error:
        print(f"Failed to load dataset: {error}")
        return

    benchmark = BenchmarkService(
        dataset_loader=dataset_loader,
        prompt_builder=PromptBuilder(),
        provider_factory=GeminiProvider,
        models=GeminiProvider.SUPPORTED_MODELS
    )

    cli = CLI(
        dataset_loader,
        benchmark,
        ConsoleUI()
    )

    cli.run()


if __name__ == "__main__":
    main()