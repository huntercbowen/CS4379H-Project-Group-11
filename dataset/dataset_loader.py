import json
from pathlib import Path
from collections import Counter


class DatasetLoader:
    """Loads and provides access to RSA benchmark cases."""

    DEFAULT_PATH = Path(__file__).resolve().parent.parent / "data" / "cases.json"

    PUBLIC_FIELDS = ("n1", "n2", "e1", "e2", "c1", "c2")

    def __init__(self, file_path=None):
        self.file_path = (
            Path(file_path) if file_path is not None
            else self.DEFAULT_PATH
        )

        self.metadata = {}
        self.cases = []

        self.load()

    def load(self):
        """Load the dataset from a JSON file."""

        with self.file_path.open("r", encoding="utf-8") as file:
            dataset = json.load(file)

        self.metadata = dataset["metadata"]
        self.cases = dataset["cases"]

    def get_all_cases(self):
        """Return all test cases."""

        return self.cases

    def get_case(self, case_id):
        """Retrieve a test case by its unique ID."""

        for case in self.cases:
            if case["case_id"] == case_id:
                return case

        raise KeyError(f"Case not found: {case_id}")

    def get_cases_by_category(self, category):
        """Return all cases belonging to a category."""

        return [
            case for case in self.cases
            if case["category"] == category
        ]

    def get_category_counts(self):
        """Return the number of cases in each category."""

        return dict(Counter(
            case["category"] for case in self.cases
        ))

    def get_public_parameters(self, case_id):
        """Return only the parameters permitted in LLM prompts."""

        case = self.get_case(case_id)

        return {
            field: case[field]
            for field in self.PUBLIC_FIELDS
        }