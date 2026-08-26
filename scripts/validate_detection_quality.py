import sys
from pathlib import Path

import yaml


RULES_DIR = Path("rules/windows")

REQUIRED_FIELDS = [
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "tags",
    "logsource",
    "detection",
    "falsepositives",
    "level",
]


def validate_rule(path):
    errors = []

    with open(path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)

    if not isinstance(rule, dict):
        return [f"{path}: Rule is not a valid YAML object"]

    for field in REQUIRED_FIELDS:
        if field not in rule or rule[field] in (None, "", []):
            errors.append(f"{path}: Missing required field '{field}'")

    tags = rule.get("tags", [])

    if not any(str(tag).lower().startswith("attack.") for tag in tags):
        errors.append(
            f"{path}: Missing MITRE ATT&CK tag (expected tag starting with 'attack.')"
        )

    return errors


def main():
    rule_files = sorted(RULES_DIR.glob("*.yml"))

    if not rule_files:
        print("ERROR: No Sigma rules found.")
        return 1

    all_errors = []

    for rule_file in rule_files:
        errors = validate_rule(rule_file)

        if errors:
            all_errors.extend(errors)
        else:
            print(f"PASS: {rule_file}")

    if all_errors:
        print("\nDetection quality gate FAILED:\n")

        for error in all_errors:
            print(f"- {error}")

        return 1

    print("\nDetection quality gate PASSED.")
    print(f"Validated {len(rule_files)} detection rule(s).")

    return 0


if __name__ == "__main__":
    sys.exit(main())
    