from pathlib import Path
import yaml


RULES_DIR = Path("rules/windows")


def extract_attack_techniques(tags):
    techniques = []

    for tag in tags:
        tag = str(tag).lower()

        if tag.startswith("attack.t"):
            technique = tag.replace("attack.", "").upper()

            if technique not in techniques:
                techniques.append(technique)

    return techniques


def main():
    coverage = {}
    validation_failed = False

    for rule_path in sorted(RULES_DIR.glob("*.yml")):

        with open(rule_path, "r", encoding="utf-8") as f:
            rule = yaml.safe_load(f)

        techniques = extract_attack_techniques(
            rule.get("tags", [])
        )

        coverage[rule["title"]] = techniques

        if not techniques:
            print(
                f"FAIL: {rule_path} has no ATT&CK technique mapping"
            )
            validation_failed = True

    print("\nMITRE ATT&CK Detection Coverage")
    print("=" * 45)

    total_techniques = set()

    for title, techniques in coverage.items():

        print(f"\n{title}")

        for technique in techniques:
            print(f"  ✓ {technique}")
            total_techniques.add(technique)

    print("\n" + "=" * 45)

    print(f"Detection rules: {len(coverage)}")
    print(f"Unique ATT&CK techniques: {len(total_techniques)}")

    if validation_failed:
        print("\nATT&CK coverage validation FAILED.")
        raise SystemExit(1)

    print("\nATT&CK coverage validation PASSED.")


if __name__ == "__main__":
    main()