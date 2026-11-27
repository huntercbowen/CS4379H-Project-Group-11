from llm.provider import LLMProviderError


class CLI:
    """Coordinate user actions and benchmark operations."""

    def __init__(self, dataset_loader, benchmark_service, ui):
        self.dataset_loader = dataset_loader
        self.benchmark = benchmark_service
        self.ui = ui

        self.actions = {
            "1": ("View dataset summary", self.view_dataset_summary),
            "2": ("List test cases", self.list_cases),
            "3": ("Inspect test case", self.inspect_case),
            "4": ("Run reference solver", self.run_reference_solver),
            "5": ("Generate LLM prompt", self.generate_prompt),
            "6": ("Run single LLM trial", self.run_single_trial)
        }

    def run(self):
        while True:
            self.ui.display_menu(self.actions)

            choice = self.ui.choose_menu_option()

            if choice == "0":
                self.ui.message("Exiting benchmark.")
                return

            action = self.actions.get(choice)

            if action is None:
                self.ui.message("Invalid option. Please try again.")
                continue

            _, handler = action
            handler()

    def select_case(self):
        case_id = self.ui.select_case_id()

        try:
            return self.dataset_loader.get_case(case_id)

        except KeyError:
            self.ui.message(f"Case not found: {case_id}")
            return None

    def view_dataset_summary(self):
        self.ui.display_summary(
            self.dataset_loader.get_all_cases(),
            self.dataset_loader.get_category_counts()
        )

    def list_cases(self):
        self.ui.display_cases(
            self.dataset_loader.get_all_cases()
        )

    def inspect_case(self):
        case = self.select_case()

        if case is not None:
            self.ui.display_case(case)

    def run_reference_solver(self):
        case = self.select_case()

        if case is not None:
            result, checks = self.benchmark.solve_case(
                case["case_id"]
            )

            self.ui.display_reference_result(
                case, result, checks
            )

    def generate_prompt(self):
        case = self.select_case()

        if case is None:
            return

        strategy = self.ui.select_strategy()

        if strategy is None:
            return

        prompt = self.benchmark.build_prompt(
            case["case_id"], strategy
        )

        self.ui.display_prompt(prompt)

    def run_single_trial(self):
        case = self.select_case()

        if case is None:
            return

        strategy = self.ui.select_strategy()

        if strategy is None:
            return

        model = self.ui.select_model(self.benchmark.models)

        if model is None:
            return

        case_id = case["case_id"]

        if not self.ui.confirm_trial(case_id, strategy, model):
            self.ui.message("Trial cancelled.")
            return

        prompt = self.benchmark.build_prompt(
            case_id, strategy
        )

        try:
            self.ui.message("\nSubmitting request...")

            response = self.benchmark.run_trial(
                prompt, model
            )

        except LLMProviderError as error:
            self.ui.message(f"\nTrial failed: {error}")
            return

        self.ui.display_llm_response(response)