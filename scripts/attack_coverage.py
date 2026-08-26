from pathlib import Path
import re
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

    for rule_path in sorted(RULES_DIR.glob("*.yml")):
        with open(rule_path, "r", encoding="utf-8") as f:
            rule = yaml.safe_load(f)

        techniques = extract_attack_techniques(rule.get("tags", []))

        coverage[rule["title"]] = techniques

    print("\nMITRE ATT&CK Detection Coverage")
    print("=" * 45)

    total_techniques = set()

    for title, techniques in coverage.items():
        print(f"\n{title}")

        if techniques:
            for technique in techniques:
                print(f"  ✓ {technique}")
                total_techniques.add(technique)
        else:
            print("  ⚠ No ATT&CK technique mapped")

    print("\n" + "=" * 45)
    print(f"Detection rules: {len(coverage)}")
    print(f"Unique ATT&CK techniques: {len(total_techniques)}")

    if total_techniques:
        print("\nTechniques covered:")
        for technique in sorted(total_techniques):
            print(f"  - {technique}")


if __name__ == "__main__":
    main()
    