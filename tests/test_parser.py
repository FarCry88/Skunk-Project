from skunk.parser import parse_eml


def test_parse_reads_headers(fixtures_dir):
    msg = parse_eml(fixtures_dir / "spoof_email.eml")
    assert "paypa1-security.com" in str(msg["From"])
    assert msg["Subject"] == "Urgent: verify your account"