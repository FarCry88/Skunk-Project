from skunk.scoring import analyze_file


def test_spoof_email_is_likely_phishing(fixtures_dir):
    verdict = analyze_file(fixtures_dir / "spoof_email.eml")
    assert verdict.score == 85
    assert verdict.label == "Likely phishing"


def test_safe_email_is_low_risk(fixtures_dir):
    verdict = analyze_file(fixtures_dir / "safe_email.eml")
    assert verdict.score == 0
    assert verdict.label == "Low risk"