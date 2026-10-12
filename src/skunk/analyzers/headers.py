import re
from email.message import Message
from email.utils import parseaddr

from skunk.models import Finding

def _domain(address: str)  -> str:
    return address.rpartition("@")[2].lower().strip("> ")

def check_headers(msg: Message) -> list[Finding]:
    findings = []
    from_name, from_addr = parseaddr(msg.get("From", ""))
    _, reply_addr = parseaddr(msg.get("Reply-To", ""))

    if reply_addr and _domain(reply_addr) != _domain(from_addr):
        findings.append(Finding(
            "reply_to_mismatch", 25,
            f"Replies go to {reply_addr}, not {from_addr}."))

        