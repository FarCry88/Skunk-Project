from skunk.analyzers.urls import check_urls, extract_links, registered_domain
from skunk.parser import get_bodies, parse_eml
from skunk.scoring import analyze_file


def names(text="", html=""):
    return {f.name for f in check_urls(text, html)}


def test_registered_domain():
    assert registered_domain("a.b.example.com") == "example.com"
    assert registered_domain("www.bbc.co.uk") == "bbc.co.uk"


def test_extract_links_finds_html_and_plain():
    links = extract_links("see http://x.com/a", '<a href="http://y.com">Y</a>')
    assert ("Y", "http://y.com") in links
    assert ("", "http://x.com/a") in links


def test_link_text_mismatch():
    html = '<a href="http://evil.com/x">www.paypal.com</a>'
    assert "link_text_mismatch" in names(html=html)


def test_matching_link_text_is_clean():
    html = '<a href="https://www.paypal.com/signin">paypal.com</a>'
    assert names(html=html) == set()


def test_lookalike_domains():
    assert "lookalike_domain" in names(text="http://paypa1-security.com/login")
    assert "lookalike_domain" in names(text="http://micros0ft.com")
    assert "lookalike_domain" not in names(text="https://www.paypal.com/home")


def test_ip_punycode_shortener_userinfo():
    assert "ip_address_url" in names(text="http://10.0.0.5/login")
    assert "punycode_domain" in names(text="http://xn--pypal-4ve.com")
    assert "url_shortener" in names(text="http://bit.ly/abc")
    assert "userinfo_in_url" in names(text="http://paypal.com@evil.com/x")


def test_phish_links_fixture(fixtures_dir):
    text, html = get_bodies(parse_eml(fixtures_dir / "phish_links.eml"))
    found = names(text, html)
    assert {"link_text_mismatch", "lookalike_domain", "ip_address_url", "url_shortener"} <= found


def test_phish_links_scores_high(fixtures_dir):
    verdict = analyze_file(fixtures_dir / "phish_links.eml")
    assert verdict.label == "Likely phishing"