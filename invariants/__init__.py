# Invariant templates for Solidity fuzzing (Echidna / Foundry)

from pathlib import Path

_INVARIANTS = {}
_ALIASES = {
    "erc20": "erc20_invariants",
    "access-control": "access_control_invariants",
    "protocol": "protocol_invariants",
}


def register(name: str, content: str):
    _INVARIANTS[name] = content


def get_template(kind: str) -> str:
    kind = _ALIASES.get(kind, kind)
    if kind == "all":
        parts = []
        for name, content in _INVARIANTS.items():
            parts.append(f"// === {name.upper()} ===\n\n{content}")
        return "\n\n".join(parts)
    return _INVARIANTS.get(kind, f"No template for '{kind}'")


# Auto-register all .sol files in this directory
_here = Path(__file__).parent
for f in sorted(_here.glob("*.sol")):
    name = f.stem
    content = f.read_text(encoding="utf-8", errors="replace")
    register(name, content)
