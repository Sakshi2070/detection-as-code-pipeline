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
    """
    Evaluate the subset of Sigma selection semantics
    currently used by this project.

    Multiple fields = AND
    Multiple values in the same field = OR
    """

    for field, expected_values in selection.items():

        field_name, _, modifier = field.partition("|")

        actual_value = event.get(field_name)

        if actual_value is None:
            return False

        if not isinstance(expected_values, list):
            expected_values = [expected_values]

        actual_value = str(actual_value).lower()

        field_matched = False

        for expected in expected_values:

            expected = str(expected).lower()

            if modifier == "contains":
                if expected in actual_value:
                    field_matched = True
                    break

            elif modifier == "endswith":
                if actual_value.endswith(expected):
                    field_matched = True
                    break

            elif modifier == "":
                if actual_value == expected:
                    field_matched = True
                    break

        if not field_matched:
            return False

    return True


def evaluate_rule(rule_file, event_file):
    rule = load_rule(rule_file)
    event = load_event(event_file)

    selection = rule["detection"]["selection"]

    return matches_selection(selection, event)


def test_powershell_encoded_positive():
    assert evaluate_rule(
        "windows_powershell_encoded_command.yml",
        "powershell_encoded_positive.json",
    ), "PowerShell encoded command should be detected"

def test_powershell_encoded_positive_pwsh():
    assert evaluate_rule(
        "windows_powershell_encoded_command.yml",
        "powershell_encoded_positive_pwsh.json",
    ), "PowerShell 7 encoded command should be detected"


def test_powershell_encoded_positive_enc():
    assert evaluate_rule(
        "windows_powershell_encoded_command.yml",
        "powershell_encoded_positive_enc.json",
    ), "PowerShell abbreviated encoded command should be detected"


def test_powershell_encoded_negative():
    assert not evaluate_rule(
        "windows_powershell_encoded_command.yml",
        "powershell_encoded_negative.json",
    ), "Normal PowerShell execution should not trigger the detection"


def test_suspicious_cmd_positive():
    assert evaluate_rule(
        "windows_suspicious_cmd_execution.yml",
        "suspicious_cmd_positive.json",
    ), "Suspicious command execution should be detected"

def test_suspicious_cmd_positive_systeminfo():
    assert evaluate_rule(
        "windows_suspicious_cmd_execution.yml",
        "suspicious_cmd_positive_systeminfo.json",
    ), "systeminfo execution should be detected"


def test_suspicious_cmd_positive_net_user():
    assert evaluate_rule(
        "windows_suspicious_cmd_execution.yml",
        "suspicious_cmd_positive_net_user.json",
    ), "net user execution should be detected"


def test_suspicious_cmd_negative():
    assert not evaluate_rule(
        "windows_suspicious_cmd_execution.yml",
        "suspicious_cmd_negative.json",
    ), "Normal command execution should not trigger the detection"

def test_suspicious_cmd_normal_negative_2():
    assert not evaluate_rule(
        "windows_suspicious_cmd_execution.yml",
        "suspicious_cmd_normal_negative_2.json",
    ), "Normal cmd execution should not trigger the detection"

def test_scheduled_task_positive():
    assert evaluate_rule(
        "windows_scheduled_task_creation.yml",
        "scheduled_task_positive.json",
    ), "Scheduled task creation should be detected"


def test_scheduled_task_negative():
    assert not evaluate_rule(
        "windows_scheduled_task_creation.yml",
        "scheduled_task_negative.json",
    ), "Scheduled task query should not trigger the creation detection"

def test_powershell_normal_negative_2():
    assert not evaluate_rule(
        "windows_powershell_encoded_command.yml",
        "powershell_normal_negative_2.json",
    ), "Normal PowerShell command should not trigger the detection"