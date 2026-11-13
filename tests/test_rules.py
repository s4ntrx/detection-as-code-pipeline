import json
import os

import pytest
import yaml

from evaluator import evaluate_rule

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
RESERVED_KEYS = {"condition", "timeframe"}


def load_rule(name):
    with open(os.path.join(RULES_DIR, name), "r") as rule_file:
        return yaml.safe_load(rule_file)


def load_fixture(name):
    with open(os.path.join(FIXTURES_DIR, name), "r") as fixture_file:
        return json.load(fixture_file)


RULE_FILES = sorted(name for name in os.listdir(RULES_DIR) if name.endswith(".yml"))


@pytest.mark.parametrize("rule_file", RULE_FILES)
def test_rule_has_required_sigma_fields(rule_file):
    rule = load_rule(rule_file)
    assert rule.get("title"), "missing title"
    assert rule.get("logsource"), "missing logsource"
    assert rule.get("detection", {}).get("condition"), "missing detection.condition"


@pytest.mark.parametrize(
    "rule_file, fixture_file",
    [
        ("rule1_bruteforce.yml", "rule1_fail.json"),
        ("rule2_webshell.yml", "rule2_malicious.json"),
        ("rule3_oauth.yml", "rule3_malicious.json"),
    ],
)
def test_rule_fires_on_malicious_fixture(rule_file, fixture_file):
    assert evaluate_rule(load_rule(rule_file), load_fixture(fixture_file)) is True


@pytest.mark.parametrize(
    "rule_file, fixture_file",
    [
        ("rule1_bruteforce.yml", "rule1_success.json"),
        ("rule1_bruteforce.yml", "rule1_fail_low_count.json"),
        ("rule2_webshell.yml", "rule2_benign.json"),
        ("rule3_oauth.yml", "rule3_benign.json"),
    ],
)
def test_rule_stays_silent_on_benign_fixture(rule_file, fixture_file):
    assert evaluate_rule(load_rule(rule_file), load_fixture(fixture_file)) is False


# Deliberately broken rule: looks for 'Success' but the fixture is 'Failed'.
# strict xfail keeps CI green while proving the harness catches a rule that
# does not fire. If someone "fixes" the rule, this test turns red.
# To produce the red-X screenshot, delete the marker on a throwaway branch.
@pytest.mark.xfail(strict=True, reason="DELIBERATE FAILURE: rule 4 looks for 'Success'")
def test_rule4_broken_rule():
    rule = load_rule("rule4_deliberately_broken.yml")
    assert evaluate_rule(rule, load_fixture("rule4_malicious.json")) is True
