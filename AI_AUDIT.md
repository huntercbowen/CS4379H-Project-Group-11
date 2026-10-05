# AI_AUDIT — Team AI Verification Log

CS 4379H Cryptography, Fall 2026

- Team members: Julian Gomez, Hunter Bowen, Nirjal KC.
- Team name / number: Group 11.
- Paper: Wang et al., *AICrypto: Evaluating Cryptography Capabilities of Large Language Models*, arXiv:2507.09580v6, 27 May 2026.
- Assistant used for this draft: ChatGPT / Codex. Exact displayed model/version: team to record from the session interface; not independently confirmed here.
- Proposed coding assistant: ChatGPT Codex, subject to instructor approval.
- Selected topic origin: AI suggestion in this proposal drafting session; selected for the completed proposal at the user's direction.
- Keep this file in the repository root and commit updates as work happens. This file has been created locally; no repository was provided, and no GitHub commit has been made.

## Current status

The proposal overview predates the separate generated AI review. The three comparison rows are now complete. The review contains no deliberately fabricated claims; the comparison distinguishes accurate claims from an omitted qualification. No software experiment has been run, and no human verifier or GitHub commit is claimed. Preserve the earlier rows as drafting history.

## Logging rules

Log every AI output the team relies on, including claims, citations, code, and adopted ideas, even when incorrect. Preserve exact prompts and full responses in dated files and link them from future rows. Record the reviewer, actual check, outcome, and category. Do not mark a plan as a completed experiment. The assistant's source checks below are not independent human verification; all initial entries await team review.

Categories from the instructor template: **FC** fabricated citation; **NA** nonexistent API/function; **MR** misstated result; **CW** code runs but is wrong; **OC** overclaim; **OK** verified correct. A dash means classification is still pending.

Roles: Reviewer, Archaeologist, Student Researcher, Reproducibility Checker, Quanta Correspondent.

## Log

| # | Date | Role | What the AI claimed or produced | Category | Verified? | How it was checked / next check | Team member |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-10-05 | Reviewer | Paper identity and independent-of-instructor-review overview in proposal page 1. | — | partially | Assistant read supplied PDF and saved overview before inspecting templates; title and version checked on PDF page 1. Team must review and rewrite overview in its own words. | Pending human reviewer |
| 2 | 2026-10-05 | Reviewer | Benchmark includes 135 MCQs, 150 CTF challenges, 30 proofs; 17 evaluated models. | — | partially | Assistant checked Sections 2.2-2.4 and 3.1; team must confirm these passages. | Pending human reviewer |
| 3 | 2026-10-05 | Reviewer | Agent uses execution feedback, a 100-action cap, and three CTF attempts. | — | partially | Assistant checked Sections 2.3 and 3.3; team must distinguish pass@3 from single-attempt accuracy. | Pending human reviewer |
| 4 | 2026-10-05 | Reviewer | Proof grader averages six scores; Pearson correlation is 0.9025 on 306 samples, without guaranteeing individual grading correctness. | — | partially | Assistant checked Section 3.4. Team must verify statistic and interpret correlation separately from proof correctness. | Pending human reviewer |
| 5 | 2026-10-05 | Reviewer | Best MCQ 97.8%, best model CTF 56.0%, human CTF 81.2% on 100-task subset; best model proof 85.4%, human 94.0%. | — | partially | Assistant checked Section 4.2. Team must retain subset qualification and the different task metrics. | Pending human reviewer |
| 6 | 2026-10-05 | Reviewer | Case studies identify computation, mathematical comprehension, and dynamic reasoning failures; contamination mitigation is not proof of absence. | — | partially | Assistant checked Sections 2.2-2.4 and 4.3. Team must review interpretation and avoid treating benchmark performance as a universal conclusion. | Pending human reviewer |
| 7 | 2026-10-05 | Student Researcher | Idea A: compare two prompts on 12 controlled RSA cases; labeled feasible and selected provisionally. | — | no | Scope estimate only: 24 responses, one model, one local tool. Team must approve topic, establish cases, confirm tool approval and time/resources. No experiment run. | Pending human reviewer |
| 8 | 2026-10-05 | Student Researcher | Idea B: present standard common-modulus attack as new; labeled already published. | — | partially | Assistant checked Figures 4-5, which already demonstrate that attack; team must verify before relying on novelty assessment. | Pending human reviewer |
| 9 | 2026-10-05 | Student Researcher | Idea C: prove RSA security from AI failure on samples; labeled technically flawed. | — | no | Logical assessment: finite model failures are not a security proof. Team must compare with course security definitions. | Pending human reviewer |
| 10 | 2026-10-05 | Reproducibility Checker | Proposed solver uses Bezout coefficients and ciphertext products with modular inverses under explicit conditions. | — | no | Design only, no executable solver produced. Team must derive formula, check negative powers, use known plaintext fixtures, and test failed assumptions without claiming all attacks impossible. | Pending human reviewer |
| 11 | 2026-10-05 | Student Researcher | Eight-week schedule, class connections, applications, and small-sample reporting plan. | — | no | Proposed plan only. Confirm actual syllabus coverage, approved assistants, team responsibilities and available resources. | Pending human reviewer |
| 12 | 2026-10-05 | Reviewer | Instructor-review disagreement table remains pending; no actual review claims were supplied or evaluated. | — | no | Historical draft status, superseded by entries 13-16 after the instructor clarification. No review claims were invented in that draft. | Pending human reviewer |

| 13 | 2026-10-05 | Reviewer | Generated separate review; exact prompt and full response saved in AICrypto_AI_Review.md. | — | partially | Generated after the earlier overview. Assistant checked benchmark facts against Sections 2.2-2.4, 3.1, 3.4, and 4.2-4.3. Independent team verification remains pending. | ChatGPT source check; team signoff pending |
| 14 | 2026-10-05 | Reviewer | Comparison 1: benchmark counts are right. | OK | partially | Exact quoted review claim compared with Sections 2.2-2.4 and Figure 1. Counts match 135, 150, and 30. Category describes assistant source-check outcome, not human approval. | ChatGPT source check; team signoff pending |
| 15 | 2026-10-05 | Reviewer | Comparison 2: strong proof-score correlation is right, with a qualification about individual errors. | OK | partially | Section 3.4 reports Pearson 0.9025 and Spearman 0.8973 on 306 samples, averaging six scores. Review itself does not claim error-free grading. | ChatGPT source check; team signoff pending |
| 16 | 2026-10-05 | Reviewer | Comparison 3: human comparison is shallow because conditions differ. | OC | partially | Sections 3.3 and 4.2: model pass@3 over 150 tasks; human CTF baseline from a 100-task subset. OC flags an omitted qualification, not a fabricated or numerically false claim. | ChatGPT source check; team signoff pending |
| 17 | 2026-10-05 | Student Researcher | Updated two-page proposal with the three supplied member names and selected AI-origin topic. | — | partially | Names taken directly from user; selected topic and experiment plan retained. Human review of course links and resources is still required. No experimental results are asserted. | ChatGPT consistency check; team signoff pending |

## Verification before submission and implementation

1. Read the paper and independently confirm the source claims above; record names and outcomes, replacing pending categories only after actual checks.
2. Independently check the completed comparison table against AICrypto_AI_Review.md and the cited paper passages. Julian reported that Professor Rathore clarified the team should generate its own review; this update follows that clarification.
3. Confirm assistant approval and exact model version; add team names and course coverage.
4. Review the AI-assisted overview in your own words; the saved drafting order does not establish that the team wrote an unaided review.
5. Add this file to the repository root. Save and log every later coding response, accepted patch, citation and adopted idea before use; include failed checks.

## Future entry format

| # | Date | Role | What the AI claimed or produced | Category | Verified? | How you checked it | Team member |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Next | YYYY-MM-DD | Role | Summary and link to prompt/response or commit | FC / NA / MR / CW / OC / OK after check | yes / no / partially | Actual source, test, expected and observed result | Actual verifier |

## End-of-semester summary

Complete before the final demo; do not prefill success counts.

- Total AI outputs logged: To be finalized (17 entries currently).
- Verified correct: Pending independent team verification.
- Failed verification: Pending.
- Failure 1: To be recorded from actual experience.
- Failure 2: To be recorded from actual experience.
- Which verification habit saved the most time? To be completed from actual experience.
