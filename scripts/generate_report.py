import json
import subprocess
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules" / "windows"
EVENTS_DIR = ROOT / "tests" / "events"
REPORT_DIR = ROOT / "reports"


def load_rules():
    rules = []

    for path in sorted(RULES_DIR.glob("*.yml")):
        with open(path, "r", encoding="utf-8") as f:
            rules.append(yaml.safe_load(f))

    return rules


def get_attack_techniques(rules):
    techniques = set()

    for rule in rules:
        for tag in rule.get("tags", []):
            tag = str(tag).lower()

            if tag.startswith("attack.t"):
                techniques.add(tag.replace("attack.", "").upper())

    return sorted(techniques)


def count_tests():
    return len(list(EVENTS_DIR.glob("*.json")))


def run_pytest():
    result = subprocess.run(
        ["pytest", "-q", "tests/test_detections.py"],
        capture_output=True,
        text=True,
    )

    passed = 0

    for line in result.stdout.splitlines():
        if "passed" in line:
            try:
                passed = int(line.split()[0])
            except (ValueError, IndexError):
                pass

    return result.returncode == 0, passed


def run_quality_gate():
    result = subprocess.run(
        ["python", "scripts/validate_detection_quality.py"],
        capture_output=True,
        text=True,
    )

    return result.returncode == 0


def main():
    REPORT_DIR.mkdir(exist_ok=True)

    rules = load_rules()

    attack_techniques = get_attack_techniques(rules)

    total_tests = count_tests()

    tests_passed_successfully, tests_passed = run_pytest()

    quality_gate_passed = run_quality_gate()

    report = {
        "detection_rules": len(rules),
        "attack_techniques": len(attack_techniques),
        "attack_technique_ids": attack_techniques,
        "test_events": total_tests,
        "tests_passed": tests_passed,
        "tests_status": "PASS" if tests_passed_successfully else "FAIL",
        "quality_gate": "PASS" if quality_gate_passed else "FAIL",
    }

    output_file = REPORT_DIR / "detection_report.json"

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\nDetection Engineering Report")
    print("=" * 40)

    print(f"Detection rules:       {len(rules)}")
    print(f"ATT&CK techniques:     {len(attack_techniques)}")
    print(f"Test events:           {total_tests}")
    print(f"Tests passed:          {tests_passed}")
    print(
        f"Test status:           "
        f"{'PASS' if tests_passed_successfully else 'FAIL'}"
    )
    print(
        f"Quality gate:          "
        f"{'PASS' if quality_gate_passed else 'FAIL'}"
    )

    print(f"\nReport written to: {output_file}")


if __name__ == "__main__":
    main()
    