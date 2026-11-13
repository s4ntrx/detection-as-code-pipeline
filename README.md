# Detection-as-Code Pipeline

This repository contains 4 Sigma rules covering distinct attack stages (Initial Access, Execution, Collection). It includes a Python test harness that validates the rules against JSON fixtures.

## CI Pipeline
The GitHub Actions pipeline runs `pytest` on every push. It verifies:
1. The rules fire on malicious fixtures (True Positives).
2. The rules do not fire on benign fixtures (False Positives).
3. **A deliberately broken rule fails the CI**, proving the pipeline works.

## Proof of Intentional Failure
*(Paste a screenshot here of the red X in GitHub Actions showing `test_rule4_broken_rule` failed, or paste the terminal output showing the AssertionError).*
