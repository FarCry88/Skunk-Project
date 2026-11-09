from skunk.analyzers.headers import check_headers
from skunk.analyzers.urls import check_urls
from skunk.models import Finding, Verdict
from skunk.parser import get_bodies, parse_eml


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
    text, html = get_bodies(msg)
    findings = check_headers(msg) + check_urls(text, html)
    return build_verdict(findings)