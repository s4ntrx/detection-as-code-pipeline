"""Minimal Sigma evaluator: reads the rule's own selections and condition."""
import re

RESERVED_KEYS = {"condition", "timeframe"}
TOKEN_PATTERN = re.compile(r"\(|\)|[A-Za-z_][A-Za-z0-9_]*")
AGGREGATION_PATTERN = re.compile(r"^\s*(?P<base>.+?)\s*\|\s*count\(\)\s*by\s+(?P<field>\w+)\s*(?P<op>>=|<=|>|<|==)\s*(?P<threshold>\d+)\s*$")
COMPARATORS = {
    ">": lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "<": lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
}


def _field_matches(event_value, modifier, expected):
    if event_value is None:
        return False
    candidates = event_value if isinstance(event_value, list) else [event_value]
    expected = str(expected).lower()
    for candidate in candidates:
        text = str(candidate).lower()
        if modifier == "endswith" and text.endswith(expected):
            return True
        if modifier == "startswith" and text.startswith(expected):
            return True
        if modifier == "contains" and expected in text:
            return True
        if modifier is None and text == expected:
            return True
    return False


def _selection_matches(selection, event):
    if isinstance(selection, dict):
        for key, expected in selection.items():
            field, _, modifier = key.partition("|")
            expected_values = expected if isinstance(expected, list) else [expected]
            if not any(_field_matches(event.get(field), modifier or None, value) for value in expected_values):
                return False
        return True
    keywords = selection if isinstance(selection, list) else [selection]
    haystack = " ".join(
        str(item) for value in event.values() for item in (value if isinstance(value, list) else [value])
    ).lower()
    return any(str(keyword).lower() in haystack for keyword in keywords)


class _ConditionParser:
    """Grammar: or_expr -> and_expr ('or' and_expr)*; and_expr -> not_expr ('and' not_expr)*."""

    def __init__(self, condition, results):
        self.tokens = TOKEN_PATTERN.findall(condition)
        self.results = results
        self.position = 0

    def _peek(self):
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _advance(self):
        token = self._peek()
        self.position += 1
        return token

    def parse(self):
        value = self._or_expr()
        if self._peek() is not None:
            raise ValueError(f"Unexpected token in condition: {self._peek()}")
        return value

    def _or_expr(self):
        value = self._and_expr()
        while self._peek() == "or":
            self._advance()
            value = self._and_expr() or value
        return value

    def _and_expr(self):
        value = self._not_expr()
        while self._peek() == "and":
            self._advance()
            value = self._not_expr() and value
        return value

    def _not_expr(self):
        if self._peek() == "not":
            self._advance()
            return not self._not_expr()
        return self._atom()

    def _atom(self):
        token = self._advance()
        if token == "(":
            value = self._or_expr()
            if self._advance() != ")":
                raise ValueError("Missing closing parenthesis in condition")
            return value
        if token not in self.results:
            raise ValueError(f"Condition references undefined selection: {token}")
        return self.results[token]


def evaluate_rule(rule, event):
    detection = rule["detection"]
    condition = detection["condition"]

    aggregation = AGGREGATION_PATTERN.match(condition)
    if aggregation:
        condition = aggregation["base"]

    results = {
        name: _selection_matches(selection, event)
        for name, selection in detection.items()
        if name not in RESERVED_KEYS
    }
    base_matched = _ConditionParser(condition, results).parse()

    if not aggregation:
        return base_matched

    # Fixtures carry a pre-aggregated "Count" for the group-by field.
    if not base_matched or aggregation["field"] not in event:
        return False
    compare = COMPARATORS[aggregation["op"]]
    return compare(event.get("Count", 0), int(aggregation["threshold"]))
