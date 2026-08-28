"""
Access control and authentication checks.

Derived from:
  - Chapter 02: NEAR auditing (access control patterns)
  - Chapter 18: Solidity Checklist & Reentrancy Attack
  - Chapter 19: Initializing, Proxy, Oracles & Multi-Chain
"""

import re
from audit_agent import (
    Check, Finding, AuditReport,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
)

_OWASP_ACCESS = "https://swcregistry.io/docs/SWC-105"


class AccessControlCheck(Check):
    """Detects missing or weak access control on sensitive functions."""

    name = "access-control"
    category = "Access Control"

    # Modifiers that indicate access control
    _ACCESS_MODIFIERS = [
        r'\bonlyOwner\b', r'\bonlyAdmin\b', r'\bonlyRole\b',
        r'\bauthorize\b', r'\bhasRole\b', r'\bisOwner\b',
        r'\brequire\(.*msg\.sender\s*==\s*owner', r'\brequire\(.*hasRole',
        r'\brequire\(.*isAuthorized', r'\b_onlyAdmin\b', r'\b_auth\b',
        r'\bonlyGovernance\b', r'\bonlyMultisig\b',
    ]

    # Function names that especially need access control
    _SENSITIVE_FUNCS = [
        r'\bwithdraw\b', r'\bwithdrawTo\b', r'\bemergencyWithdraw\b',
        r'\bmint\b', r'\bburn\b', r'\bpause\b', r'\bunpause\b',
        r'\bblacklist\b', r'\bunblacklist\b', r'\bfreeze\b',
        r'\bunfreeze\b', r'\bsetFee\b', r'\bsetRate\b', r'\bupdatePrice\b',
        r'\bsetMaxSupply\b', r'\bsetMin\b', r'\bsetMax\b',
        r'\bset\w*[Pp]aused?\b',
        r'\bupgradeTo\b', r'\bchangeAdmin\b', r'\btransferOwnership\b',
        r'\brenounceOwnership\b', r'\baddReward\b', r'\bnotifyReward\b',
        r'\brecoverFunds\b', r'\brecoverToken\b', r'\bsweep\b',
        r'\bcollect\b', r'\bclaimFees\b', r'\bsetImplementation\b',
        r'\binitialize\b', r'\binit\b',
    ]

    def run(self, source: str, filepath: str, report: AuditReport):
        lines = source.split('\n')

        # Collect all function definitions with their modifiers
        func_pattern = re.compile(
            r'function\s+(\w+)\s*\([^)]*\)\s*'
            r'((?:\s*(?:public|external|internal|private|'
            r'view|pure|payable|virtual|override|returns?\s*\([^)]*\)|'
            r'\w+(?:\s*\([^)]*\))?\s*)*))'
            r'\s*\{',
        )

        for m in func_pattern.finditer(source):
            func_name = m.group(1)
            modifiers = m.group(2)
            lineno = source[:m.start()].count('\n') + 1

            # Check if this is a sensitive function
            is_sensitive = any(re.search(p, func_name) for p in self._SENSITIVE_FUNCS)

            # Check if it has any access control modifier
            has_access = any(re.search(p, modifiers) for p in self._ACCESS_MODIFIERS)

            # Check visibility
            is_public_or_external = bool(
                re.search(r'\bpublic\b', modifiers) or re.search(r'\bexternal\b', modifiers)
            )

            if is_sensitive and is_public_or_external and not has_access:
                # Determine severity by how sensitive the name is
                sev = SEVERITY_HIGH
                if any(n in func_name.lower() for n in ['initialize', 'init', 'upgrade', 'changeadmin']):
                    sev = SEVERITY_CRITICAL
                elif any(n in func_name.lower() for n in ['mint', 'pause', 'setpaused', 'withdraw']):
                    sev = SEVERITY_HIGH

                snippet = source[m.start():m.start() + 120].split('\n')[0]

                report.add(Finding(
                    title=f"Missing access control on `{func_name}`",
                    severity=sev,
                    category="Access Control",
                    description=(
                        f"`{func_name}` is {'not ' if not has_access else ''}protected by "
                        f"an access control modifier but is exposed as "
                        f"{'public/external' if is_public_or_external else 'internal'}. "
                        "Anyone can call this function. If this is a sensitive operation, add "
                        "restrictions."
                    ),
                    file=filepath,
                    line=lineno,
                    snippet=snippet,
                    recommendation=(
                        "1. Add an `onlyOwner` modifier from OpenZeppelin's Ownable.\n"
                        "2. Or use OpenZeppelin's AccessControl with specific roles.\n"
                        "3. For initialization, use the `initializer` modifier."
                    ),
                    references=[_OWASP_ACCESS],
                ))


class TxOriginCheck(Check):
    """Detects use of tx.origin instead of msg.sender for authorization."""

    name = "tx-origin"
    category = "Access Control"

    def run(self, source: str, filepath: str, report: AuditReport):
        import re
        for m in re.finditer(r'\btx\.origin\b', source):
            lineno = source[:m.start()].count('\n') + 1
            report.add(Finding(
                title="`tx.origin` used for authorization",
                severity=SEVERITY_HIGH,
                category="Access Control",
                description=(
                    "`tx.origin` returns the original externally-owned account that "
                    "initiated the transaction. Using it for authorization makes the contract "
                    "vulnerable to phishing attacks: a malicious intermediary contract can "
                    "call this contract on behalf of the user, and `tx.origin` still resolves "
                    "to the user's address."
                ),
                file=filepath,
                line=lineno,
                recommendation="Use `msg.sender` instead of `tx.origin` for authorization checks.",
                references=["https://swcregistry.io/docs/SWC-115"],
            ))
