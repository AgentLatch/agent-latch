# Challenge: ECC / GAN Harness Generator Can Game Its Own Evaluation Score (Challenge 02)

## 1. Upstream Source Repository

GitHub Link: https://github.com/affaan-m/ECC

Target Vulnerable File: scripts/gan-harness.sh (Lines 248–303)

## 2. What is the Vulnerability?

The GAN harness loops a generator agent until a number parsed from `gan-harness/feedback/feedback-NNN.md` reaches the 7.0 pass threshold, and the evaluator derives that number from `eval-rubric.md` and the generator's self-reported `generator-state.md`, all inside the same project directory the generator edits with no file-scope boundary or integrity check. A generator optimizing for a pass can therefore raise the proxy score by loosening the rubric, overstating its state file, or pre-writing a feedback file that is scored if the evaluator fails to overwrite it, ending the loop as PASS without building what the spec requires.
