import subprocess
from pathlib import Path


RULES_DIR = "rules/windows"


def run_git_command(args):
    result = subprocess.run(
        ["git"] + args,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def get_changed_files():
    try:
        output = run_git_command(
            ["diff", "--name-status", "HEAD~1", "HEAD", "--", RULES_DIR]
        )
    except subprocess.CalledProcessError:
        return []

    changes = []

    for line in output.splitlines():
        if not line.strip():
            continue

        status, path = line.split("\t", 1)

        changes.append((status, Path(path).name))

    return changes


def main():
    changes = get_changed_files()

    added = []
    modified = []
    deleted = []

    for status, filename in changes:

        if status == "A":
            added.append(filename)

        elif status == "M":
            modified.append(filename)

        elif status == "D":
            deleted.append(filename)

    print("\nDetection Change Report")
    print("=" * 40)

    print("\nAdded:")

    if added:
        for filename in added:
            print(f"  + {filename}")
    else:
        print("  None")

    print("\nModified:")

    if modified:
        for filename in modified:
            print(f"  ~ {filename}")
    else:
        print("  None")

    print("\nDeleted:")

    if deleted:
        for filename in deleted:
            print(f"  - {filename}")
    else:
        print("  None")


if __name__ == "__main__":
    main()
    