from cli import CLI
from dataset_loader import DatasetLoader


def main():
    try:
        dataset_loader = DatasetLoader()
    except (OSError, ValueError, KeyError) as error:
        print(f"Failed to load dataset: {error}")
        return

    cli = CLI(dataset_loader)
    cli.run()


if __name__ == "__main__":
    main()