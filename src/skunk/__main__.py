import sys

from skunk.scoring import analyze_file


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python -m skunk path/to/email.eml")
        return

    verdict = analyze_file(sys.argv[1])
    print(f"Risk score: {verdict.score}/100 - {verdict.label}")
    for finding in verdict.findings:
        print(f"  [+{finding.points}] {finding.explanation}")


if __name__ == "__main__":
    main()