from email import policy
from email.message import Message
from email.parser import BytesParser


def parse_eml(path) -> Message:
    """Read a saved .eml file and return it as an email Message."""
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)