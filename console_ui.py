import json

from prompts import PromptStrategy


class ConsoleUI:
    """Handle terminal input and presentation."""

    def display_menu(self, actions):
        print("\n" + "=" * 45)
        print("RSA COMMON-MODULUS LLM BENCHMARK")
        print("=" * 45)

        for key, (label, _) in actions.items():
            print(f"[{key}] {label}")

        print("[0] Exit")
        print("=" * 45)

    def choose_menu_option(self):
        return input("Select an option: ").strip()

    def select_case_id(self):
        case_id = input("Enter case ID: ").strip().upper()

        if case_id.isascii() and case_id.isdigit():
            case_id = f"CASE-{int(case_id):03d}"

        return case_id

    def select_option(self, title, options):
        print(f"\n--- {title} ---")

        for index, (label, _) in enumerate(options, 1):
            print(f"[{index}] {label}")

        print("[0] Cancel")

        choice = input("Select option: ").strip()

        if choice == "0":
            return None

        try:
            index = int(choice) - 1

            if 0 <= index < len(options):
                return options[index][1]

        except ValueError:
            pass

        print("Invalid selection.")
        return None

    def select_strategy(self):
        return self.select_option(
            "Prompt Strategies",
            [
                ("Baseline", PromptStrategy.BASELINE),
                ("Enhanced", PromptStrategy.ENHANCED)
            ]
        )

    def select_model(self, models):
        return self.select_option(
            "Available Models",
            [(model, model) for model in models]
        )

    def confirm_trial(self, case_id, strategy, model):
        print("\n--- Trial Configuration ---")
        print(f"Case ID: {case_id}")
        print(f"Model: {model}")
        print(f"Prompt strategy: {strategy.value}")

        return input(
            "\nSubmit API request? [y/n]: "
        ).strip().lower() == "y"

    def message(self, text):
        print(text)

    def display_summary(self, cases, counts):
        print("\n--- Dataset Summary ---")
        print(f"Total cases: {len(cases)}")

        for category, count in counts.items():
            print(f"{category:<28}: {count}")

    def display_cases(self, cases):
        print("\n--- Test Cases ---")
        print(f"{'Case ID':<15}{'Category':<28}")
        print("-" * 43)

        for case in cases:
            print(
                f"{case['case_id']:<15}"
                f"{case['category']:<28}"
            )

    def display_case(self, case):
        print("\n--- Test Case Details ---")

        for field, value in case.items():
            print(f"{field}: {value}")

    def display_reference_result(self, case, result, checks):
        print("\n--- Reference Solver Results ---")
        print(f"Case ID: {case['case_id']}")
        print(f"Category: {case['category']}")

        print(f"GCD of exponents: {result.gcd_e1_e2}")
        print(f"Bezout coefficient s1: {result.bezout_s1}")
        print(f"Bezout coefficient s2: {result.bezout_s2}")
        print(f"Attack applicable: {result.applicable}")
        print(f"Recovered plaintext: {result.recovered_m}")
        print(f"Decoded text: {result.recovered_text}")
        print(f"Re-encryption verified: {result.reencryption_verified}")
        print(f"Failure code: {result.failure_code}")
        print(f"Explanation: {result.failure_reason}")

        print("\n--- Ground Truth Comparison ---")

        for label, passed in checks.items():
            print(f"{label}: {passed}")

        print(
            "Overall result:",
            "PASS" if all(checks.values()) else "FAIL"
        )

    def display_prompt(self, prompt):
        print("\n--- Generated Prompt ---")
        print("=" * 45)
        print(prompt)
        print("=" * 45)

    def display_llm_response(self, response):
        print("\n--- LLM Response ---")

        try:
            print(json.dumps(
                json.loads(response.content),
                indent=4
            ))

        except json.JSONDecodeError:
            print(response.content)
            print("\nWarning: Response is not valid JSON.")

        print("\n--- Response Metadata ---")
        print(f"Provider: {response.provider}")
        print(f"Model: {response.model}")
        print(f"Response ID: {response.response_id}")
        print(f"Elapsed time: {response.elapsed_seconds:.3f}s")
        print(f"Prompt tokens: {response.prompt_tokens}")
        print(f"Completion tokens: {response.completion_tokens}")
        print(f"Total tokens: {response.total_tokens}")
        print(f"Finish reason: {response.finish_reason}")

        if response.finish_reason != "STOP":
            print("\nWarning: Generation may be incomplete.")