from app.cli import CLI
from app.console_ui import ConsoleUI
from app.benchmark_service import BenchmarkService
from dataset.dataset_loader import DatasetLoader
from llm.prompts import PromptBuilder
from llm.gemini_provider import GeminiProvider
from experiments.response_store import ResponseStore


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
        models=GeminiProvider.SUPPORTED_MODELS,
        response_store=ResponseStore()
    )

    cli = CLI(
        dataset_loader,
        benchmark,
        ConsoleUI()
    )

    cli.run()


if __name__ == "__main__":
    main()