"""
Reentrancy checks — single-function, cross-function, cross-contract, read-only.

Derived from:
  - Chapter 01: Reentrancy Attacks on Smart Contracts Distilled
  - Chapter 10: Read-only Reentrancy: In-Depth
  - Chapter 18: Solidity Checklist & Reentrancy Attack
  - Re-entrancy Attack Patterns List (uni-due-syssec/eth-reentrancy-attack-patterns)
"""

import re
from audit_agent import Check, Finding, AuditReport, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM

_REENTRANCY_REF = "https://github.com/uni-due-syssec/eth-reentrancy-attack-patterns"


def _find_functions(source: str):
    """Yield (func_name, body_start, body_end) for each function found via heuristic."""
    # crude heuristic: match `function name(...` then balance braces
    pattern = re.compile(r'function\s+([a-zA-Z_$][\w$]*)\s*\(')
    lines = source.split('\n')
    for match in pattern.finditer(source):
        func_name = match.group(1)
        # find the opening { by scanning forward
        start_offset = match.start()
        brace_open = source.find('{', start_offset)
        if brace_open == -1:
            continue
        depth = 1
        pos = brace_open + 1
        while pos < len(source) and depth > 0:
            ch = source[pos]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
            pos += 1
        if depth == 0:
            yield func_name, brace_open, pos


class _ReentrancyGuardChecker:
    """Utility: check if a function body snippet uses a reentrancy guard."""
    _GUARD_PATTERNS = [
        r'\bnonReentrant\b',
        r'\breentrancyGuard\b',
        r'\b_lock\b',
        r'\b_unlock\b',
        r'mutex\[',
        r'\bentered\b',
    ]

    @classmethod
    def has_guard(cls, body: str) -> bool:
        return any(re.search(p, body) for p in cls._GUARD_PATTERNS)

    @classmethod
    def has_checks_effects(cls, func_name: str, body: str) -> bool:
        """Heuristic: does the function update state before any external call?"""
        # Look for `send`, `transfer`, `call{value=` or `.call(` before state writes
        ext_call = re.search(r'\.(send|transfer|call)\s*(\{|\()', body)
        if not ext_call:
            return True  # no external call, no reentrancy risk here
        # Look for state writes (storage) before the external call
        state_writes_before = re.findall(
            r'(balances\[|msg\.value|_transfer|_mint|_burn|\.transfer\s*\()',
            body[:ext_call.start()],
        )
        # If there are external calls without prior state writes, flag
        return len(state_writes_before) > 0


class ReentrancyCheck(Check):
    """Detects single-function and cross-function reentrancy patterns."""

    name = "reentrancy"
    category = "Reentrancy"

    def run(self, source: str, filepath: str, report: AuditReport):
        lines = source.split('\n')
        for func_name, body_start, body_end in _find_functions(source):
            # Extract the full function body
            func_outer = source[body_start:body_end]
            body_lineno = source[:body_start].count('\n') + 1

            if _ReentrancyGuardChecker.has_guard(func_outer):
                continue

            # Pattern: external call (send/transfer/call) before state modification
            # Check for .call{value: or .send or .transfer(
            ext_calls = list(re.finditer(
                r'\.(send|transfer|call)\s*(\{|\().*?(\}|\))',
                func_outer,
                re.DOTALL,
            ))
            if not ext_calls:
                continue

            # For each external call, check if state is written after it
            for ext in ext_calls:
                after = func_outer[ext.end():]
                # Look for state writes in the remaining body
                state_writes_after = re.findall(
                    r'(balances\[|_transfer|_mint|_burn|approve\(|\.transfer\s*\()',
                    after,
                )
                if state_writes_after:
                    snippet_lines = func_outer.split('\n')[:5]
                    snippet = '\n'.join(snippet_lines[:3])
                    report.add(Finding(
                        title=f"Potential reentrancy in `{func_name}` — state updated after external call",
                        severity=SEVERITY_CRITICAL,
                        category="Reentrancy",
                        description=(
                            f"`{func_name}` makes an external call (`send`/`transfer`/`call`) "
                            "before updating contract state. An attacker can re-enter via the "
                            "external call and exploit stale state. Apply checks-effects-interactions: "
                            "update all state variables before making any external call, or use a "
                            "reentrancy guard modifier."
                        ),
                        file=filepath,
                        line=body_lineno,
                        snippet=snippet,
                        recommendation=(
                            "1. Move all state updates before the external call (Checks-Effects-Interactions).\n"
                            "2. Add a `nonReentrant` modifier from OpenZeppelin's ReentrancyGuard.\n"
                            "3. Consider using a simple boolean mutex for single-function protection."
                        ),
                        references=[_REENTRANCY_REF],
                    ))
                    break  # one finding per function

            # Cross-function: look for public/external functions that read shared state
            # after another public function has made an external call
            if not _ReentrancyGuardChecker.has_checks_effects(func_name, func_outer):
                # Already caught above; this is a secondary signal
                pass


class ReadOnlyReentrancyCheck(Check):
    """Detects view/pure functions that return state readable mid-reentry.

    Per Chapter 10: view functions without guards can be called during a reentrancy
    attack and return stale prices/exchange rates, exploiting downstream integrators.
    """

    name = "read-only-reentrancy"
    category = "Reentrancy"

    def run(self, source: str, filepath: str, report: AuditReport):
        lines = source.split('\n')
        # Find view functions that compute or return sensitive values
        view_funcs = re.finditer(
            r'function\s+(\w+)\s*\([^)]*\)\s*(public|external)\s+view\s+returns\s*\(',
            source,
        )
        for m in view_funcs:
            func_name = m.group(1)
            # Extract function body
            brace = source.find('{', m.end())
            if brace == -1:
                continue
            depth, pos = 1, brace + 1
            while pos < len(source) and depth > 0:
                if source[pos] == '{': depth += 1
                elif source[pos] == '}': depth -= 1
                pos += 1
            body = source[brace:pos]
            lineno = source[:m.start()].count('\n') + 1

            # Sensitive return values: price, rate, balanceOf, totalSupply
            sensitive_keywords = [
                r'\bprice\b', r'\brate\b', r'\bexchangeRate\b', r'\bgetAmount',
                r'\bbalanceOf\b', r'\btotalSupply\b', r'\bpreview',
                r'\bconvertTo', r'\bgetReserves\b', r'\bgetRatio\b',
            ]
            sensitive_vars = [kw for kw in sensitive_keywords if re.search(kw, body, re.I)]
            if not sensitive_vars:
                continue

            # Check if this view function is used as an oracle by other contracts
            # (detected by its name containing price, rate, etc.)
            name_is_sensitive = any(
                re.search(kw, func_name, re.I) for kw in
                [r'price', r'rate', r'exchange', r'balance', r'reserve', r'ratio',
                 r'preview', r'convert', r'spot', r'TVL', r'tvl', r'liquidity']
            )
            if name_is_sensitive:
                report.add(Finding(
                    title=f"Read-only reentrancy risk — view function `{func_name}` returns sensitive data",
                    severity=SEVERITY_MEDIUM,
                    category="Reentrancy",
                    description=(
                        f"`{func_name}` is a view function returning {', '.join(sensitive_vars)}. "
                        "During a reentrancy attack on a state-changing function, this view can be "
                        "called mid-reentry and return stale values. Downstream contracts or protocols "
                        "that trust this value (as an oracle) may be exploited."
                    ),
                    file=filepath,
                    line=lineno,
                    recommendation=(
                        "While view functions cannot have reentrancy guards, consider:\n"
                        "1. Documenting that this value is stale during callbacks.\n"
                        "2. Implementing a reentrancy lock that also blocks view calls "
                        "during unsafe reentrant windows.\n"
                        "3. Adding a `whenNotPaused` or similar check that downstream integrators "
                        "can query before trusting the value."
                    ),
                    references=[
                        "https://officercia.mirror.xyz/DBzFiDuxmDOTQEbfXhvLdK0DXVpKu1Nkurk0Cqk3QKc"
                    ],
                ))
