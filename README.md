# CS4379H-Project-Group-11

# RSA Common-Modulus LLM Benchmark

CS 4379H Cryptography — Group 11

**Members:** Julian Gomez, Hunter Bowen, Nirjal KC

## Project overview

This project investigates whether large language models correctly recognize
the assumptions required for the textbook RSA common-modulus attack.

The application provides a reference solver, a synthetic dataset, baseline
and enhanced prompts, Gemini API integration, saved responses, offline
evaluation, and CSV reporting.

Our project is inspired by AICrypto's evaluation of cryptographic reasoning,
particularly its RSA common-modulus example. It is a focused student
experiment rather than a reproduction of the full AICrypto benchmark.

## Requirements

- Python 3.10 or newer; tested with Python 3.13.7 on macOS
- Git for cloning the repository
- Internet access and a Gemini API key for live model requests

The application and unit tests use Python's standard library. No additional
Python packages are required.

Dataset inspection, reference solving, prompt generation, offline evaluation,
CSV export, and unit tests do not require an API key.

## Clone and run

The completed evaluation functionality and Julian's reporting improvements
are currently available on the `julian-contributions` branch.

```bash
git clone --branch julian-contributions https://github.com/huntercbowen/CS4379H-Project-Group-11.git
cd CS4379H-Project-Group-11
python3 main.py
```

Run commands from the repository root.

## Menu options

| Option | Function |
| --- | --- |
| 1 | View dataset summary |
| 2 | List test cases |
| 3 | Inspect a test case |
| 4 | Run the reference RSA solver |
| 5 | Generate a baseline or enhanced LLM prompt |
| 6 | Submit a single live LLM trial and save its response |
| 7 | Evaluate saved responses offline |
| 8 | Export detailed and summary CSV reports |
| 0 | Exit |

The baseline prompt requests a solution and explanation. The enhanced prompt
also requests explicit assumption checks, executable verification code, and
verification against both ciphertexts.

Both prompts request structured JSON responses.

## Optional Gemini configuration

For live trials, set `GEMINI_API_KEY` in the terminal before launching:

```bash
export GEMINI_API_KEY="YOUR_API_KEY"
python3 main.py
```

Replace the placeholder locally. Never commit an API key.

The provider reads the environment variable directly; creating a `.env` file
alone does not configure it.

Choose option 6 and follow the prompts to select a case, prompt strategy,
and configured model. Live requests depend on API access, model availability,
network connectivity, and quota.

## Included dataset

`data/cases.json` contains 55 synthetic cases.

| Category | Count |
| --- | --- |
| Valid small RSA cases | 10 |
| Valid larger RSA cases | 15 |
| Non-coprime exponent traps | 10 |
| Different-message traps | 10 |
| Broken-setup traps | 10 |

The reference solver checks shared moduli, exponent conditions, ciphertext
ranges, and the inverses required by the attack. Recovered candidates are
checked by re-encryption against both ciphertexts.

Only public RSA parameters are included in generated model prompts; expected
answers and case labels are excluded.

The RSA parameters are for educational experiments, not production encryption.

## Reproduce the included offline demonstration

```bash
python3 -m unittest discover -v
python3 main.py
```

The current test suite contains 50 tests.

In the application:

1. Choose option 1 to inspect the dataset summary.
2. Choose option 7 to evaluate the included saved responses.
3. Choose option 8 to regenerate the CSV reports.
4. Choose option 0 to exit.

The included development responses are stored in:

```text
results/development.jsonl
```

The two saved responses concern `CASE-026`, a non-coprime-exponent trap.
They use one model with baseline and enhanced prompts.

Expected results for these included responses:

- Total evaluated trials: 2
- Valid-case trials: 0
- Trap-case trials: 2
- Correct recovery rate: N/A
- Correct trap rejection rate: 0.0%
- Unsupported claims: 2 out of 2
- Overall reliability: 0.0%

These are development examples, not results for all 55 cases or all models.
Adding live responses changes the evaluation totals.

Option 8 writes:

```text
results/evaluation_details.csv
results/evaluation_summary.csv
```

The repository includes these reports as an example. Regenerating them from
unchanged saved responses should reproduce their evaluation content.

## Interpreting the scores

Recovery rate measures correct recoveries among valid-case trials. Trap
rejection rate measures correct rejections among trap-case trials.

The evaluator's reliability metric combines correct recoveries and justified
caution, including correctly rejected traps. It is not equivalent to plaintext
recovery accuracy.

Percentages with zero denominators are unmeasured and appear as `N/A` in
terminal output and summary CSV files. Measured zero scores remain `0.0%`.

## Working functionality and limitations

Verified locally:

- Dataset loading and reference-solver tests
- Prompt construction and public-parameter filtering tests
- Provider request and response handling using mocked API calls
- Response storage tests
- Offline evaluation and CSV export
- Missing-measurement reporting and regression coverage

Limitations:

- The included response sample is too small for general conclusions about
  model quality or prompt effectiveness.
- Live API behavior is not established by mocked provider tests.
- Generated verification code is not automatically executed by the evaluator.
- A failed standard attack does not prove that the RSA instance is secure
  against other attacks.
- Live model responses may change between runs; saved responses support
  reproducible offline scoring.

## Research lineage and references

### Selected paper

Yu Wang et al.
*AICrypto: Evaluating Cryptography Capabilities of Large Language Models.*
arXiv:2507.09580, initially released in 2025; version 6 dated May 27, 2026.

https://arxiv.org/abs/2507.09580

AICrypto evaluates conceptual knowledge, practical cryptographic challenges,
and proofs. Its RSA common-modulus example motivates our focused experiment.

### Prior research

Andy K. Zhang et al.
*Cybench: A Framework for Evaluating Cybersecurity Capabilities and Risks
of Language Models.*
ICLR 2025; initial arXiv release in 2024.

https://arxiv.org/abs/2408.08926

Cybench provides cybersecurity tasks and an environment in which agents can
execute commands and inspect outputs. AICrypto explicitly cites Cybench in
Section 2.3 when describing its agent-based evaluation framework and compares
the benchmarks in Table 1. This establishes a methodological predecessor.

### Subsequent research

Mayar Elfares, Pascal Reisert, Tilman Dietz, Manpa Barman, Ahmed Zaki,
Ralf Küsters, and Andreas Bulling.
*CryptoQA: A Large-scale Question-answering Dataset for AI-assisted Cryptography.*
arXiv:2512.02625, December 2, 2025.

https://arxiv.org/abs/2512.02625

CryptoQA follows AICrypto's initial 2025 release. Section 2.1 explicitly
discusses AICrypto, with its full citation listed as reference 97. CryptoQA
addresses limitations in benchmark scale through a large cryptography
question-answer dataset and studies evaluation and fine-tuning.

The relationship is an extension of the broader cryptography-evaluation
research direction, not reuse or reproduction of AICrypto's implementation.

## AI assistance and verification

`AI_AUDIT.md` records AI assistance, verification methods, outcomes, and
responsible team members. Entries should be updated as work is completed.
Passing tests does not establish every mathematical claim or validate an
entire AI-generated explanation.