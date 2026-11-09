from email import policy
from email.message import Message
from email.parser import BytesParser


def parse_eml(path) -> Message:
    """Read a saved .eml file and return it as an email Message."""
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def get_bodies(msg: Message) -> tuple[str, str]:
    """Return (plain_text, html) bodies of a message. Missing parts are ''."""
    text_part = msg.get_body(preferencelist=("plain",))
    html_part = msg.get_body(preferencelist=("html",))
    text = text_part.get_content() if text_part else ""
    html = html_part.get_content() if html_part else ""
    return text, html