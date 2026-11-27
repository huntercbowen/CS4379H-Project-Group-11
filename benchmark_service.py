from rsa_math import common_modulus_attack


class BenchmarkService:
    """Perform benchmark operations"""

    def __init__(
        self,
        dataset_loader,
        prompt_builder,
        provider_factory,
        models
    ):
        self.dataset_loader = dataset_loader
        self.prompt_builder = prompt_builder
        self.provider_factory = provider_factory
        self.models = tuple(models)

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

    def run_trial(self, prompt, model):
        provider = self.provider_factory()

        return provider.generate(prompt, model)