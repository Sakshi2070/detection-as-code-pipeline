import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules" / "windows"
EVENTS_DIR = ROOT / "tests" / "events"


def load_rule(filename):
    with open(RULES_DIR / filename, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_event(filename):
    with open(EVENTS_DIR / filename, "r", encoding="utf-8") as f:
        return json.load(f)


def matches_selection(selection, event):
    for field, expected in selection.items():

        field_name, _, modifier = field.partition("|")

        actual = event.get(field_name)

        if actual is None:
            return False

        if not isinstance(expected, list):
            expected = [expected]

        actual = str(actual).lower()

        matched = False

        for value in expected:
            value = str(value).lower()

            if modifier == "contains":
                if value in actual:
                    matched = True

            elif modifier == "endswith":
                if actual.endswith(value):
                    matched = True

            elif "*" in value:
                pattern = value.replace("*", "")
                if pattern in actual:
                    matched = True

            elif actual == value:
                matched = True

        if not matched:
            return False

    return True


def evaluate_rule(rule_file, event_file):
    rule = load_rule(rule_file)
    event = load_event(event_file)

    selection = rule["detection"]["selection"]

    return matches_selection(selection, event)


def test_powershell_positive():
    assert evaluate_rule(
        "windows_powershell_encoded_command.yml",
        "powershell_encoded_positive.json",
    )


def test_powershell_negative():
    assert not evaluate_rule(
        "windows_powershell_encoded_command.yml",
        "powershell_encoded_negative.json",
    )


def test_cmd_positive():
    assert evaluate_rule(
        "windows_suspicious_cmd_execution.yml",
        "suspicious_cmd_positive.json",
    )


def test_cmd_negative():
    assert not evaluate_rule(
        "windows_suspicious_cmd_execution.yml",
        "suspicious_cmd_negative.json",
    )
def test_scheduled_task_positive():
    assert evaluate_rule(
        "windows_scheduled_task_creation.yml",
        "scheduled_task_positive.json",
    )


def test_scheduled_task_negative():
    assert not evaluate_rule(
        "windows_scheduled_task_creation.yml",
        "scheduled_task_negative.json",
    )