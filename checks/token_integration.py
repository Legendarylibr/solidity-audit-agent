"""
ERC20/ERC777 integration checks — real-world token quirks.

Derived from:
  - Chapter 17: ERC20 Integration Tips
  - Chapter 20: Tokens, EIP-712 & Meta-Transactions
  - Auditor's Notes: ERC20 Integration Tips
"""

import re
from audit_agent import Check, Finding, AuditReport, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_HIGH, SEVERITY_INFO


class ERC20IntegrationCheck(Check):
    """Detects unsafe assumptions about ERC20 token behavior."""

    name = "erc20"
    category = "Token Integration"

    def run(self, source: str, filepath: str, report: AuditReport):
        # --- .transfer() / .transferFrom() return value not checked ---
        # Safe patterns: SafeERC20, try/catch, or require(_success)
        if 'SafeERC20' not in source:
            for m in re.finditer(r'(\.transfer\s*\(|\.transferFrom\s*\()', source):
                lineno = source[:m.start()].count('\n') + 1
                # Check if the return value is used or if the call is in a require
                context = source[m.start():m.start() + 150]
                if not re.search(r'(require|if\s*\(|bool\s+\w+\s*=|success|\.safeTransfer)', context):
                    report.add(Finding(
                        title="ERC20 `transfer`/`transferFrom` return value not checked",
                        severity=SEVERITY_MEDIUM,
                        category="Token Integration",
                        description=(
                            "Some ERC20 tokens do not return a boolean from `transfer`/`transferFrom` "
                            "or return `false` on failure rather than reverting. If the return value "
                            "is not checked, a failed transfer may go unnoticed."
                        ),
                        file=filepath,
                        line=lineno,
                        snippet=m.group(0)[:60],
                        recommendation=(
                            "1. Use OpenZeppelin's `SafeERC20` library (`safeTransfer`/`safeTransferFrom`).\n"
                            "2. Or explicitly check the return value in a `require()` statement."
                        ),
                        references=[
                            "https://officercia.mirror.xyz/W6V7cWFfK8xuHvezjGL-kyen6c1aJwlvqtwtlpIS53A"
                        ],
                    ))

        # --- .approve() race condition (front-run on non-zero -> non-zero) ---
        approve_pattern = re.compile(
            r'\.approve\s*\(\s*\w+\s*,\s*(?!0\s*\))',
        )
        for m in approve_pattern.finditer(source):
            lineno = source[:m.start()].count('\n') + 1
            context = source[max(0, m.start() - 300):m.start()]
            # Check if it's using safeIncreaseAllowance pattern
            if not re.search(r'(safeIncreaseAllowance|safeDecreaseAllowance)', source):
                report.add(Finding(
                    title="ERC20 `approve()` non-zero to non-zero — front-running risk",
                    severity=SEVERITY_MEDIUM,
                    category="Token Integration",
                    description=(
                        "Changing an ERC20 approval from a non-zero value to another non-zero value "
                        "is vulnerable to front-running: the spender can observe the new approval "
                        "transaction and spend both the old and new allowances before the new value "
                        "is set. Use `safeIncreaseAllowance`/`safeDecreaseAllowance` instead."
                    ),
                    file=filepath,
                    line=lineno,
                    recommendation=(
                        "1. Use OpenZeppelin's `SafeERC20.safeIncreaseAllowance()` and "
                        "`safeDecreaseAllowance()`.\n"
                        "2. Or always reset to 0 first and confirm before setting a new non-zero value."
                    ),
                    references=["https://swcregistry.io/docs/SWC-114"],
                ))

        # --- Fee-on-transfer tokens: balance check != transfer amount ---
        balance_afters = re.finditer(
            r'balanceOf\s*\(.*\)\s*[.].*[Bb]efore',
            source,
        )
        for m in balance_afters:
            lineno = source[:m.start()].count('\n') + 1
            report.add(Finding(
                title="Fee-on-transfer token handling required",
                severity=SEVERITY_INFO,
                category="Token Integration",
                description=(
                    "The contract compares balances before and after a transfer. This is a good "
                    "pattern for fee-on-transfer tokens where the received amount != sent amount. "
                    "However, verify the diff should be the actual transferred amount."
                ),
                file=filepath,
                line=lineno,
                recommendation=(
                    "For fee-on-transfer / deflationary tokens, always check the actual balance "
                    "change rather than assuming `amount` was received."
                ),
            ),)

        # --- Rebase token hooks ---
        if re.search(r'rebase|elastic|ampl', source, re.I):
            report.add(Finding(
                title="Rebase/elastic supply token integration detected",
                severity=SEVERITY_LOW,
                category="Token Integration",
                description=(
                    "The contract interacts with a rebasing or elastic supply token. "
                    "Rebasing tokens change user balances outside of transfers, which can break "
                    "accounting logic that assumes balance == custody amount. "
                    "Total supply can also change between blocks."
                ),
                file=filepath,
                line=1,
                recommendation=(
                    "1. Never rely on `balanceOf` for internal accounting — track deposited shares.\n"
                    "2. Handle the case where totalSupply changes outside transfers.\n"
                    "3. Consider rounding errors in rebase math (see Chapter 30)."
                ),
                references=[
                    "https://officercia.mirror.xyz/nlIR1RkT5xIv4sZFYiOXCPhF2BJyAaJtOeVr6zsULsA",
                    "https://officercia.mirror.xyz/2SXrASlpw5L4PPQpXhJgiNyJ9b2CqfDzQHcGXZd4CHk",
                ],
            ))


class ERC777Check(Check):
    """Detects ERC777 integration issues — reentrancy via tokensReceived hook."""

    name = "erc777"
    category = "Token Integration"

    def run(self, source: str, filepath: str, report: AuditReport):
        if 'ERC777' not in source and 'tokensReceived' not in source:
            return

        report.add(Finding(
            title="ERC777 integration — reentrancy via `tokensReceived` hook",
            severity=SEVERITY_HIGH,
            category="Token Integration",
            description=(
                "ERC777 tokens call a `tokensReceived` hook on the recipient contract during "
                "transfer. This callback can re-enter the sending contract before state updates "
                "are complete, enabling reentrancy attacks (e.g., the Uniswap V1/ERC777 incident). "
                "`transfer` and `transferFrom` may not be safe from reentrancy."
            ),
            file=filepath,
            line=1,
            recommendation=(
                "1. Apply reentrancy guards to all functions that transfer ERC777 tokens.\n"
                "2. Apply checks-effects-interactions: update state before transfer.\n"
                "3. Consider using ERC20 instead of ERC777 for new deployments."
            ),
            references=[
                "https://medium.com/@Heuss/unprotected-swap-function-a-erc777-reentrancy-vulnerability-81aaeaa75a2a",
                "https://mixbytes.io/blog/one-more-problem-with-erc777",
            ],
        ))
