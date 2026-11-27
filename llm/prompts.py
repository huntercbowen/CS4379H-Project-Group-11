from enum import Enum


class PromptStrategy(Enum):
    BASELINE = "baseline"
    ENHANCED = "enhanced"


class PromptBuilder:
    """Build standardized prompts for RSA benchmark experiments."""

    PUBLIC_FIELDS = ("n1", "n2", "e1", "e2", "c1", "c2")

    BASE_INSTRUCTIONS = (
        "Determine whether the standard RSA common-modulus "
        "attack can recover a shared plaintext from the "
        "following textbook RSA parameters.\n"
        "If possible, recover the plaintext and explain "
        "your reasoning."
    )

    ENHANCED_INSTRUCTIONS = (
        "\n\nBefore reaching a conclusion:\n"
        "1. Explicitly examine the mathematical assumptions "
        "required by the standard common-modulus attack.\n"
        "2. Distinguish verified facts from assumptions.\n"
        "3. Provide executable Python to support your answer.\n"
        "4. Verify any recovered plaintext against both "
        "original ciphertexts.\n"
        "5. Explain any failed assumptions or limitations."
    )

    RESPONSE_FORMAT = """
Return only a JSON object using the following structure:

{
    "attack_applicable": true,
    "recovered_m": null,
    "failure_code": null,
    "reasoning": "",
    "verification_code": null
}

Requirements:
- attack_applicable: true, false, or null if uncertain.
- recovered_m: decimal integer as a string, or null.
- failure_code: a short description or code for the failure,
  or "ok" if the standard attack succeeds.
- reasoning: explain your conclusion.
- verification_code: Python code as a string, or null.
"""

    def build(self, parameters, strategy):
        """Construct a prompt using public RSA parameters."""

        parameter_text = self.format_parameters(parameters)

        instructions = self.BASE_INSTRUCTIONS

        if strategy == PromptStrategy.ENHANCED:
            instructions += self.ENHANCED_INSTRUCTIONS

        elif strategy != PromptStrategy.BASELINE:
            raise ValueError(f"Unknown prompt strategy: {strategy}")

        return (
            f"{instructions}\n\n"
            f"RSA public parameters:\n"
            f"{parameter_text}\n\n"
            f"{self.RESPONSE_FORMAT}"
        )

    def format_parameters(self, parameters):
        """Include only permitted public RSA fields."""

        return "\n".join(
            f"{field} = {parameters[field]}"
            for field in self.PUBLIC_FIELDS
        )