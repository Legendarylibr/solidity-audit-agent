"""
Initialization, proxy, and multi-chain checks.

Derived from:
  - Chapter 19: Initializing, Proxy, Oracles & Multi-Chain
  - Chapter 18: Solidity Checklist & Reentrancy Attack
"""

import re
from audit_agent import Check, Finding, AuditReport, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM


class InitializerCheck(Check):
    """Detects unprotected initializer functions."""

    name = "initializer"
    category = "Initialization / Proxy"

    def run(self, source: str, filepath: str, report: AuditReport):
        # --- Unprotected initialize() ---
        for m in re.finditer(r'function\s+(initialize|init)\s*\(', source):
            func_name = m.group(1)
            lineno = source[:m.start()].count('\n') + 1
            # Check if it has the `initializer` modifier
            context = source[m.start():m.start() + 400]

            if not re.search(r'\binitializer\b', context):
                report.add(Finding(
                    title=f"`{func_name}()` without `initializer` modifier",
                    severity=SEVERITY_HIGH,
                    category="Initialization / Proxy",
                    description=(
                        f"`{func_name}()` can be called multiple times or front-run by anyone. "
                        "Without the `initializer` modifier from OpenZeppelin, an attacker can "
                        "call this function first and take over the contract's initialization."
                    ),
                    file=filepath,
                    line=lineno,
                    recommendation=(
                        "1. Add the `initializer` modifier from OpenZeppelin's Initializable.\n"
                        "2. For newer Solidity (>=0.8), use `onlyInitializing` for internal functions.\n"
                        "3. Consider using a constructor for non-upgradeable contracts."
                    ),
                    references=[
                        "https://officercia.mirror.xyz/y7pHWYwL6cQwsSToolCvg2EuMkHZK5dfDSiRtS0akX8"
                    ],
                ))

        # --- Initializer called inside constructor (broken for proxies) ---
        if re.search(r'constructor\s*\([^)]*\)\s*\{[^}]*initialize\(', source):
            report.add(Finding(
                title="`initialize()` called in constructor — breaks proxy pattern",
                severity=SEVERITY_HIGH,
                category="Initialization / Proxy",
                description=(
                    "Calling `initialize()` from the constructor sets the initializer flag "
                    "in the implementation contract's storage, not the proxy's. The proxy's "
                    "`initialize()` will then revert because the `initializer` modifier sees "
                    "the flag as already set."
                ),
                file=filepath,
                line=1,
                recommendation=(
                    "Remove `initialize()` from the constructor. The proxy contract calls "
                    "`initialize()` via `delegatecall` after deployment."
                ),
            ))

        # --- Selfdestruct in implementation (breaks proxies) ---
        if re.search(r'\bselfdestruct\b', source):
            report.add(Finding(
                title="`selfdestruct` in implementation — proxy destruction risk",
                severity=SEVERITY_HIGH,
                category="Initialization / Proxy",
                description=(
                    "If an upgradeable proxy's implementation contract can selfdestruct, the "
                    "proxy will delegatecall into a contract with no code, reverting all calls. "
                    "This permanently bricks the proxy."
                ),
                file=filepath,
                line=1,
                recommendation=(
                    "Remove `selfdestruct` from implementations used behind proxies."
                ),
            ))


class ProxyCheck(Check):
    """Detects proxy-specific issues: storage gaps, UUPS vs transparent."""

    name = "proxy"
    category = "Initialization / Proxy"

    def run(self, source: str, filepath: str, report: AuditReport):
        # Check for UUPS pattern
        if 'UUPS' in source or 'upgradeTo' in source:
            # Verify the upgrade function has access control
            upgrade_m = re.search(r'function\s+upgradeTo\s*\(', source)
            if upgrade_m:
                ctx = source[upgrade_m.start():upgrade_m.start() + 500]
                if not re.search(r'(onlyOwner|onlyAdmin|onlyRole|onlyProxy|_authorizeUpgrade)', ctx):
                    report.add(Finding(
                        title="`upgradeTo()` without `_authorizeUpgrade` — anyone can upgrade",
                        severity=SEVERITY_CRITICAL,
                        category="Initialization / Proxy",
                        description=(
                            "`upgradeTo()` (UUPS pattern) is implemented but without calling "
                            "`_authorizeUpgrade` or an access control modifier. This lets anyone "
                            "upgrade the implementation contract to any address."
                        ),
                        file=filepath,
                        line=source[:upgrade_m.start()].count('\n') + 1,
                        recommendation=(
                            "Add `_authorizeUpgrade` with `onlyOwner` or appropriate role check.\n"
                            "```solidity\n"
                            "function _authorizeUpgrade(address newImplementation)\n"
                            "    internal\n"
                            "    override\n"
                            "    onlyOwner\n"
                            "{}\n"
                            "```"
                        ),
                    ))

        # Storage gap check
        if re.search(r'(contract\s+\w+)\s+is\s+\w+(?:,\s*\w+)*\s*\{', source):
            # Heuristic: if the contract inherits from upgradeable contracts,
            # check for __gap / __unused storage reservation
            if re.search(r'is\s+\w*(Upgradeable|OwnableUpgradeable|PausableUpgradeable)', source):
                if not re.search(r'__gap|__unused|uint256\[\s*\]\s+__gap', source):
                    report.add(Finding(
                        title="Upgradeable contract without storage gap",
                        severity=SEVERITY_MEDIUM,
                        category="Initialization / Proxy",
                        description=(
                            "Upgradeable contracts should declare a `__gap` array to reserve "
                            "storage slots for future upgrades. Without it, adding new variables "
                            "in a derived contract may corrupt storage layout."
                        ),
                        file=filepath,
                        line=1,
                        recommendation=(
                            "Add at the end of the contract:\n"
                            "```solidity\n"
                            "uint256[50] private __gap;\n"
                            "```"
                        ),
                    ))
