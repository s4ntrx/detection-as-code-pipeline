# Detection-as-Code Pipeline

This repository contains 4 Sigma rules covering distinct attack stages (Initial Access, Execution, Collection). It includes a Python test harness that validates the rules against JSON fixtures.

## CI Pipeline
The GitHub Actions pipeline runs `pytest` on every push. It verifies:
1. The rules fire on malicious fixtures (True Positives).
2. The rules do not fire on benign fixtures (False Positives).
3. A deliberately broken rule (`rule4`) is caught by the harness. The test is marked `xfail(strict=True)`, so CI stays green while the failure is still asserted. Remove the marker on a throwaway branch to see the red X.

## Running locally
```
pip install pyyaml pytest
python -m pytest tests -v
```

## Evaluator limits
`tests/evaluator.py` reads each rule's selections and condition (`and`, `or`, `not`, parentheses, `endswith`/`startswith`/`contains`). Count conditions use a pre-aggregated `Count` field in the fixture; `timeframe` is not enforced.
