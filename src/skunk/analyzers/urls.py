import ipaddress
import re
from functools import cache
from importlib import resources
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from rapidfuzz import fuzz

from skunk.models import Finding

URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
# Common two-part suffixes so "bbc.co.uk" is treated as one registered domain.
TWO_PART_SUFFIXES = {"co.uk", "org.uk", "com.au", "co.jp", "com.br", "co.in"}
LOOKALIKE_SWAPS = str.maketrans({"1": "l", "0": "o", "3": "e", "5": "s", "$": "s"})


@cache
def _load(name: str) -> tuple[str, ...]:
    text = resources.files("skunk.data").joinpath(name).read_text(encoding="utf-8")
    return tuple(line.strip().lower() for line in text.splitlines() if line.strip())


def registered_domain(host: str) -> str:
    """Rough 'example.com' from 'a.b.example.com' (no external library needed)."""
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def extract_links(text: str, html: str) -> list[tuple[str, str]]:
    """Return (anchor_text, url) pairs. Plain-text URLs have empty anchor text."""
    links: list[tuple[str, str]] = []
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            links.append((a.get_text(" ", strip=True), a["href"].strip()))
    seen = {url for _, url in links}
    for source in (text, html):
        for url in URL_RE.findall(source or ""):
            url = url.rstrip(".,;")
            if url not in seen:
                seen.add(url)
                links.append(("", url))
    return links


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _lookalike_brand(host: str) -> str | None:
    """Return the brand this host imitates, or None."""
    domain = registered_domain(host)
    if domain in _load("brands.txt"):
        return None  # it IS the real brand
    label = domain.split(".")[0].translate(LOOKALIKE_SWAPS)
    for brand in _load("brands.txt"):
        name = brand.split(".")[0]
        if len(name) >= 5 and name in label:
            return brand  # e.g. paypal-security.com, paypa1-login.com
        if fuzz.ratio(label, name) >= 85:
            return brand  # e.g. paypall.com, micros0ft.com
    return None


def check_urls(text: str, html: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def add(name: str, points: int, explanation: str, key: str) -> None:
        if (name, key) not in seen:
            seen.add((name, key))
            findings.append(Finding(name, points, explanation))

    for anchor, url in extract_links(text, html):
        host = _host(url)
        if not host:
            continue

        # Link text shows one site, link goes to another
        shown = URL_RE.search(anchor) or re.fullmatch(r"(?:www\.)?[\w-]+(?:\.[\w-]+)+", anchor)
        if anchor and shown:
            shown_host = _host(shown.group(0)) or _host("http://" + anchor)
            if shown_host and registered_domain(shown_host) != registered_domain(host):
                add("link_text_mismatch", 30,
                    f"Link says '{anchor}' but goes to {host}.", host)

        if _is_ip(host):
            add("ip_address_url", 20, f"Link uses a raw IP address: {host}.", host)
        if "xn--" in host:
            add("punycode_domain", 20, f"Link uses a disguised (punycode) domain: {host}.", host)
        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            add("userinfo_in_url", 20, f"Link hides its real host with '@': {url}.", host)
        if registered_domain(host) in _load("shorteners.txt"):
            add("url_shortener", 10, f"Link uses a URL shortener: {host}.", host)

        brand = _lookalike_brand(host)
        if brand:
            add("lookalike_domain", 30, f"{host} imitates {brand}.", host)

    return findings