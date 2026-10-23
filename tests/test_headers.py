from email import message_from_string

from skunk.analyzers.headers import check_headers
from skunk.parser import parse_eml


def finding_names(msg):
    return {f.name for f in check_headers(msg)}


def test_spoof_email_triggers_all_header_checks(fixtures_dir):
    msg = parse_eml(fixtures_dir / "spoof_email.eml")
    expected = {"reply_to_mismatch", "spf_fail", "dkim_fail", "dmarc_fail"}
    assert expected <= finding_names(msg)


def test_safe_email_has_no_findings(fixtures_dir):
    msg = parse_eml(fixtures_dir / "safe_email.eml")
    assert finding_names(msg) == set()


def test_display_name_spoof_is_caught():
    msg = message_from_string('From: "support@paypal.com" <x@evil.com>\n\nhi')
    assert "display_name_spoof" in finding_names(msg)