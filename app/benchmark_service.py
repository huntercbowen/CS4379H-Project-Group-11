from crypto.rsa_math import common_modulus_attack
from experiments.trial import Trial, TrialResult


class BenchmarkService:
    """Perform benchmark operations"""

    def __init__(
        self,
        dataset_loader,
        prompt_builder,
        provider_factory,
        models,
        response_store
    ):
        self.dataset_loader = dataset_loader
        self.prompt_builder = prompt_builder
        self.provider_factory = provider_factory
        self.models = tuple(models)
        self.response_store = response_store

    def solve_case(self, case_id):
        case = self.dataset_loader.get_case(case_id)
        parameters = self.dataset_loader.get_public_parameters(case_id)

        result = common_modulus_attack(**parameters)

        expected_m = case["expected_m"]

        checks = {
            "Applicability matches":
                result.applicable == case["attack_applicable"],

            "Failure code matches":
                result.failure_code == case["expected_failure_code"],

            "Plaintext result matches":
                result.recovered_m == (
                    int(expected_m)
                    if expected_m is not None
                    else None
                )
        }

        return result, checks

    def build_prompt(self, case_id, strategy):
        parameters = self.dataset_loader.get_public_parameters(case_id)

        return self.prompt_builder.build(parameters, strategy)

    def create_trial(self, case_id, strategy, model, trial_number=1):
        """Construct a complete experimental configuration."""

        return Trial(
            case_id=case_id,
            dataset_hash=self.dataset_loader.metadata["cases_sha256"],
            model=model,
            strategy=strategy.value,
            prompt=self.build_prompt(case_id, strategy),
            trial_number=trial_number
        )

    def run_trial(self, trial):
        """Execute and persist one experimental trial."""

        if self.response_store.is_completed(trial):
            raise ValueError("This trial has already been completed.")

        provider = self.provider_factory()

        response = provider.generate(
            trial.prompt,
            trial.model
        )

        result = TrialResult.create(trial, response)

        self.response_store.save(result)

        return result

    def get_saved_results(self):
        """Retrieve completed experimental trials."""

        return self.response_store.load_all()