import re
from email.message import Message
from email.utils import parseaddr

from skunk.models import Finding


def _domain(address: str) -> str:
    return address.rpartition("@")[2].lower().strip("> ")


def check_headers(msg: Message) -> list[Finding]:
    findings: list[Finding] = []
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    _, reply_addr = parseaddr(str(msg.get("Reply-To", "")))

    # 1. Replies go to a different domain than the sender
    if reply_addr and _domain(reply_addr) != _domain(from_addr):
        findings.append(
            Finding(
                "reply_to_mismatch",
                25,
                f"Replies go to {reply_addr}, not {from_addr}.",
            )
        )

    # 2. Display name shows a fake address, e.g. "support@paypal.com" <x@evil.com>
    embedded = re.search(r"@([\w.-]+)", from_name)
    if embedded and embedded.group(1).lower() != _domain(from_addr):
        findings.append(
            Finding(
                "display_name_spoof",
                25,
                f"Sender name '{from_name}' hides the real address {from_addr}.",
            )
        )

    # 3. Email authentication results added by the receiving mail server
    auth = str(msg.get("Authentication-Results", "")).lower()
    for check in ("spf", "dkim", "dmarc"):
        if re.search(rf"{check}=(fail|softfail|none)", auth):
            findings.append(
                Finding(f"{check}_fail", 20, f"{check.upper()} check did not pass.")
            )

    return findings