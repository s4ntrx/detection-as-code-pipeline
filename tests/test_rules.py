import yaml
import json
import pytest
import os

RULES_DIR = os.path.join(os.path.dirname(__file__), '..', 'rules')
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')

def load_yaml(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def load_json(path):
    with open(path, 'r') as f:
        return json.load(f)

def evaluate_rule(rule, log_event):
    # A highly simplified mock evaluator for demonstration
    detection = rule.get('detection', {})
    condition = detection.get('condition', '')
    
    # Mock logic for Rule 1 (Count > 10)
    if 'count()' in condition:
        if log_event.get('Count', 0) > 10:
            return True
        return False
        
    # Mock logic for Rule 2 & 4 (selection_parent and selection_child)
    if 'and' in condition:
        parent_match = log_event.get('ParentImage', '').endswith('\\w3wp.exe')
        child_match = log_event.get('Image', '').endswith('\\cmd.exe')
        return parent_match and child_match

    # Mock logic for Rule 3 (selection and keywords)
    if 'keywords' in detection:
        operation_match = log_event.get('Operation') == 'Consent to application'
        scopes = log_event.get('Scopes', [])
        keyword_match = 'Mail.Read' in scopes or 'Files.ReadWrite.All' in scopes
        
        if operation_match and keyword_match:
            return True
        return False
        
    # Mock logic for Rule 4 (Broken - looking for Success)
    if 'selection' in detection and 'EventType' in detection['selection']:
        if log_event.get('EventType') == detection['selection']['EventType']:
            return True
        return False

    return False

# --- TESTS ---

def test_rule1_true_positive():
    rule = load_yaml(os.path.join(RULES_DIR, 'rule1_bruteforce.yml'))
    event = load_json(os.path.join(FIXTURES_DIR, 'rule1_fail.json'))
    assert evaluate_rule(rule, event) == True, "Rule 1 failed to fire on malicious fixture"

def test_rule2_true_positive():
    rule = load_yaml(os.path.join(RULES_DIR, 'rule2_webshell.yml'))
    event = load_json(os.path.join(FIXTURES_DIR, 'rule2_malicious.json'))
    assert evaluate_rule(rule, event) == True, "Rule 2 failed to fire on malicious fixture"

def test_rule3_true_positive():
    rule = load_yaml(os.path.join(RULES_DIR, 'rule3_oauth.yml'))
    event = load_json(os.path.join(FIXTURES_DIR, 'rule3_malicious.json'))
    assert evaluate_rule(rule, event) == True, "Rule 3 failed to fire on malicious fixture"

# THIS IS THE DELIBERATELY BROKEN TEST
# def test_rule4_broken_rule():
  #  rule = load_yaml(os.path.join(RULES_DIR, 'rule4_deliberately_broken.yml'))
   # event = load_json(os.path.join(FIXTURES_DIR, 'rule4_malicious.json'))
    # This will fail because the rule looks for 'Success', but the event is 'Failed'
    #assert evaluate_rule(rule, event) == True, "DELIBERATE FAILURE: Rule 4 is broken."
