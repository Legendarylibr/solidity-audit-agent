"""
Arbitrary call and delegatecall checks.

Derived from:
  - Chapter 14: Arbitrary Calls Auditing Tips
  - Chapter 15: EVM Limitations & Assembly Auditing Tips
"""

import re
from audit_agent import Check, Finding, AuditReport, SEVERITY_CRITICAL, SEVERITY_HIGH


class ArbitraryCallCheck(Check):
    """Detects low-level calls to user-supplied addresses without validation."""

    name = "arbitrary-call"
    category = "Delegatecall / Arbitrary Calls"

    def run(self, source: str, filepath: str, report: AuditReport):
        # Pattern:  address.call(...) or address.delegatecall(...)
        # where the target comes from a function parameter
        func_bodies = re.finditer(
            r'function\s+(\w+)\s*\([^)]*\)[^{]*\{',
            source,
        )
        for fm in func_bodies:
            func_name = fm.group(1)
            brace = source.find('{', fm.start(0))
            if brace == -1:
                continue
            depth, pos = 1, brace + 1
            while pos < len(source) and depth > 0:
                if source[pos] == '{': depth += 1
                elif source[pos] == '}': depth -= 1
                pos += 1
            body = source[brace:pos]

            # Check for `.call{value:...}(...)` or `.call(...)` with parameter target
            # Two patterns: with curly braces (call{value:}(...)) and without (call(...))
            call_sites = list(re.finditer(
                r'(\w+)\.(call|delegatecall|staticcall)\s*(?:\{[^}]*\})?\s*\(',
                body,
                re.DOTALL,
            ))

            for cs in call_sites:
                target = cs.group(1)
                # Check if target is a parameter or storage variable that can be arbitrarily set
                params = re.findall(r'(\w+)\s*(?:,|\))', source[fm.start():fm.end()])
                if target in params:
                    lineno = source[:brace].count('\n') + 1
                    snippet = body[cs.start() - brace:cs.start() - brace + 80].split('\n')[0]

                    # Check if there's any address validation
                    validation_check = re.search(
                        rf'{re.escape(target)}\s*[=!]=\s*(address\(0\)|address\(0x0\))',
                        body,
                    )
                    if not validation_check:
                        sev = SEVERITY_CRITICAL if cs.group(2) == 'delegatecall' else SEVERITY_HIGH
                        report.add(Finding(
                            title=f"Arbitrary `.{cs.group(2)}` call with user-supplied target in `{func_name}`",
                            severity=sev,
                            category="Delegatecall / Arbitrary Calls",
                            description=(
                                f"`{func_name}` performs a `.{cs.group(2)}` to `{target}`, "
                                f"which is a function parameter. "
                                "An attacker can call any address, potentially executing malicious code "
                                f"{'in the contract\'s own storage context' if cs.group(2) == 'delegatecall' else 'with the contract\'s funds'}."
                            ),
                            file=filepath,
                            line=lineno,
                            snippet=snippet,
                            recommendation=(
                                "1. Whitelist allowed target addresses.\n"
                                "2. Verify the target against a trusted registry or factory.\n"
                                "3. For delegatecall, ensure the target is a known, audited contract."
                            ),
                            references=[
                                "https://officercia.mirror.xyz/tgIGArMaNUSZiYpsSht5RdKj_hHEvMUhR9Cyw32dmZk",
                            ],
                        ))


class DelegateCallCheck(Check):
    """Detects delegatecall usage and storage collision risks."""

    name = "delegatecall"
    category = "Delegatecall / Arbitrary Calls"

    def run(self, source: str, filepath: str, report: AuditReport):
        for m in re.finditer(r'\.delegatecall\s*\(', source):
            lineno = source[:m.start()].count('\n') + 1
            context = source[max(0, m.start() - 200):m.start()]
            # Check if there's any guard around it
            has_guard = bool(re.search(r'(require|if|onlyOwner|onlyAdmin|onlyRole)', context))

            sev = SEVERITY_HIGH if has_guard else SEVERITY_CRITICAL
            report.add(Finding(
                title="`delegatecall` usage — storage collision risk",
                severity=sev,
                category="Delegatecall / Arbitrary Calls",
                description=(
                    "`delegatecall` executes code from the target contract in the caller's "
                    "storage context. This can lead to:\n"
                    "1. Storage collisions if the storage layouts differ.\n"
                    "2. State manipulation of the caller contract.\n"
                    "3. Complete takeover if the target is malicious or compromised."
                ),
                file=filepath,
                line=lineno,
                recommendation=(
                    "1. Ensure the delegatecall target is immutable or upgradeable through a "
                    "timelock/multisig.\n"
                    "2. Verify storage layout compatibility between caller and callee.\n"
                    "3. Use transparent upgradeable proxy pattern for upgradeable contracts."
                ),
                references=[
                    "https://officercia.mirror.xyz/UDdVm2Nhc4obWJz9Sc-5MeYEZC4Lx04POy9M4v3cM34",
                    "https://swcregistry.io/docs/SWC-112",
                ],
            ))
            break  # one per file
