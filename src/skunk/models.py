from dataclasses import dataclass, field

@dataclass

class Finding:
    name: str
    points: int
    explanation: str

@dataclass

class Verdict:

    score: int
    label: str
    findings: list[Finding] = field(default_factory=list)