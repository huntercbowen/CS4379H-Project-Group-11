from dataset_loader import DatasetLoader
from prompts import PromptBuilder, PromptStrategy

from rsa_math import common_modulus_attack

class CLI:
    """Interactive interface for the RSA LLM benchmark."""

    def __init__(self, dataset_loader: DatasetLoader):
        self.dataset_loader = dataset_loader
        self.prompt_builder = PromptBuilder()

        self.actions = {
            "1": self.view_dataset_summary,
            "2": self.list_cases,
            "3": self.inspect_case,
            "4": self.run_reference_solver,
            "5": self.generate_prompt
        }

    def display_menu(self):
        print("\n" + "=" * 45)
        print("RSA COMMON-MODULUS LLM BENCHMARK")
        print("=" * 45)
        print("[1] View dataset summary")
        print("[2] List test cases")
        print("[3] Inspect test case")
        print("[4] Run reference solver")
        print("[5] Generate LLM prompt")
        print("[0] Exit")
        print("=" * 45)

    def run(self):
        """Run the interactive menu."""

        while True:
            self.display_menu()

            choice = input("Select an option: ").strip()

            if choice == "0":
                print("Exiting benchmark.")
                break

            action = self.actions.get(choice)

            if action is None:
                print("Invalid option. Please try again.")
                continue

            action()

    def view_dataset_summary(self):
        """Display dataset information and category counts."""

        cases = self.dataset_loader.get_all_cases()
        counts = self.dataset_loader.get_category_counts()

        print("\n--- Dataset Summary ---")
        print(f"Total cases: {len(cases)}")

        for category, count in counts.items():
            print(f"{category:<28}: {count}")

    def list_cases(self):
        """Display all available test cases."""

        cases = self.dataset_loader.get_all_cases()

        print("\n--- Test Cases ---")
        print(f"{'Case ID':<15}{'Category':<28}")
        print("-" * 43)

        for case in cases:
            print(
                f"{case['case_id']:<15}"
                f"{case['category']:<28}"
            )

    def inspect_case(self):
        """Display the details of an individual test case."""

        case = self.select_case()

        if case is None:
            return

        print("\n--- Test Case Details ---")

        for field, value in case.items():
            print(f"{field}: {value}")

    def select_case(self):
        """Prompt the user to select a test case."""

        case_id = input("Enter case ID: ").strip().upper()

        if case_id.isascii() and case_id.isdigit():
            case_id = f"CASE-{int(case_id):03d}"

        try:
            return self.dataset_loader.get_case(case_id)
        except KeyError:
            print(f"Case not found: {case_id}")
            return None

    def run_reference_solver(self):
        """Run the reference solver on a selected test case."""

        case = self.select_case()

        if case is None:
            return

        parameters = self.dataset_loader.get_public_parameters(
            case["case_id"]
        )

        result = common_modulus_attack(**parameters)

        print("\n--- Reference Solver Results ---")
        print(f"Case ID: {case['case_id']}")
        print(f"Category: {case['category']}")

        print("\n--- Mathematical Results ---")
        print(f"GCD of exponents: {result.gcd_e1_e2}")
        print(f"Bezout coefficient s1: {result.bezout_s1}")
        print(f"Bezout coefficient s2: {result.bezout_s2}")

        print("\n--- Attack Results ---")
        print(f"Attack applicable: {result.applicable}")
        print(f"Recovered plaintext: {result.recovered_m}")
        print(f"Decoded text: {result.recovered_text}")
        print(f"Re-encryption verified: {result.reencryption_verified}")
        print(f"Failure code: {result.failure_code}")
        print(f"Explanation: {result.failure_reason}")

        print("\n--- Ground Truth Comparison ---")

        applicability_match = (
            result.applicable == case["attack_applicable"]
        )

        failure_code_match = (
            result.failure_code == case["expected_failure_code"]
        )

        expected_m = case["expected_m"]

        plaintext_match = (
            result.recovered_m == int(expected_m)
            if expected_m is not None
            else result.recovered_m is None
        )

        print(f"Applicability matches: {applicability_match}")
        print(f"Failure code matches: {failure_code_match}")
        print(f"Plaintext result matches: {plaintext_match}")

        if all([
            applicability_match,
            failure_code_match,
            plaintext_match
        ]):
            print("Overall result: PASS")
        else:
            print("Overall result: FAIL")

    def select_prompt_strategy(self):
        """Allow the user to choose a prompting strategy."""

        print("\n--- Prompt Strategies ---")
        print("[1] Baseline")
        print("[2] Enhanced")

        choice = input("Select strategy: ").strip()

        strategies = {
            "1": PromptStrategy.BASELINE,
            "2": PromptStrategy.ENHANCED
        }

        strategy = strategies.get(choice)

        if strategy is None:
            print("Invalid prompting strategy.")

        return strategy

    def generate_prompt(self):
        """Generate an LLM prompt for a selected case."""

        case = self.select_case()

        if case is None:
            return

        strategy = self.select_prompt_strategy()

        if strategy is None:
            return

        parameters = self.dataset_loader.get_public_parameters(
            case["case_id"]
        )

        prompt = self.prompt_builder.build(
            parameters,
            strategy
        )

        print("\n--- Generated Prompt ---")
        print("=" * 45)
        print(prompt)
        print("=" * 45)