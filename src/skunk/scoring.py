from skunk.analyzers.headers import check_headers
from skunk.models import Finding, Verdict
from skunk.parser import parse_eml


def build_verdict(findings: list[Finding]) -> Verdict:
    score = min(100, sum(f.points for f in findings))
    if score >= 60:
        label = "Likely phishing"
    elif score >= 25:
        label = "Suspicious"
    else:
        label = "Low risk"
    return Verdict(score, label, findings)


def analyze_file(path) -> Verdict:
    msg = parse_eml(path)
    return build_verdict(check_headers(msg))