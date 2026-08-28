"""
Gas optimization and gas DoS checks.

Derived from:
  - Chapter 13: Gas Gauge: Pressure Control
  - Chapter 16: Math, Solidity & Gas Optimizations
"""

import re
from audit_agent import Check, Finding, AuditReport, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_HIGH


class GasOptimizationCheck(Check):
    """Detects opportunities for gas optimization that also affect safety."""

    name = "gas-optimization"
    category = "Gas"

    def run(self, source: str, filepath: str, report: AuditReport):
        # --- Unbounded loops ---
        for m in re.finditer(r'for\s*\(\s*;\s*(\w+)\s*[<<=]\s*(\w+)\.length\s*;\s*\1\+\+', source):
            loop_var = m.group(1)
            array = m.group(2)
            lineno = source[:m.start()].count('\n') + 1
            # Check if the array can grow unboundedly
            context = source[max(0, m.start() - 300):m.end() + 100]
            if 'push' in context or 'mint' in context or 'deposit' in context:
                report.add(Finding(
                    title=f"Unbounded loop over `{array}` — potential gas DoS",
                    severity=SEVERITY_MEDIUM,
                    category="Gas",
                    description=(
                        f"Loop iterates over `{array}` which can grow unboundedly. "
                        "As the array grows, the loop will eventually exceed the block gas limit, "
                        "making the function permanently unusable (gas DoS)."
                    ),
                    file=filepath,
                    line=lineno,
                    recommendation=(
                        "1. Use paginated access (e.g., `withdraw(index)` instead of `withdrawAll()`).\n"
                        "2. Track user-specific data in mappings instead of arrays.\n"
                        "3. If iteration is needed, enforce a maximum array size or use a pull-over-push pattern."
                    ),
                    references=[
                        "https://arxiv.org/abs/2112.14771",
                        "https://officercia.mirror.xyz/ZWYaJILJntwLtK7rXBfTU45bbBI7Zm1CXy5_S_YyDhM",
                    ],
                ))

        # --- Storage variable read in loop (repeated SLOAD) ---
        for_loops = list(re.finditer(r'for\s*\([^;]*;[^;]*;\s*[^)]+\)\s*\{', source, re.DOTALL))
        for fm in for_loops:
            loop_body_end = source.find('}', fm.end())
            if loop_body_end == -1:
                continue
            loop_body = source[fm.end():loop_body_end]
            # Look for storage reads (not memory copies) inside the loop
            storage_reads = re.findall(r'(balances\[|_balances\[|\.totalSupply\(|\.balanceOf\()', loop_body)
            if storage_reads and not re.search(r'\b(memory|calldata)\b', loop_body[:200]):
                lineno = source[:fm.start()].count('\n') + 1
                report.add(Finding(
                    title="Repeated storage reads inside loop — high gas cost",
                    severity=SEVERITY_LOW,
                    category="Gas",
                    description=(
                        "Storage reads (`SLOAD`) inside a loop are expensive. "
                        "Cache storage values in memory before the loop to save gas."
                    ),
                    file=filepath,
                    line=lineno,
                    recommendation=(
                        "Cache storage variables in local memory variables before the loop:\n"
                        "```solidity\n"
                        "uint256 cachedBalance = balances[owner];\n"
                        "for (uint256 i; i < length; ++i) {\n"
                        "    // use cachedBalance instead of balances[owner]\n"
                        "}\n"
                        "```"
                    ),
                ))


class GasDoSCheck(Check):
    """Detects gas-based denial of service patterns."""

    name = "gas-dos"
    category = "Gas"

    def run(self, source: str, filepath: str, report: AuditReport):
        # --- Dynamic array iteration without limit or removal ---
        array_iter = re.finditer(
            r'for\s*\([^)]+\)\s*\{[^}]*\.(transfer|send|call)\s*\{',
            source, re.DOTALL,
        )
        for m in array_iter:
            lineno = source[:m.start()].count('\n') + 1
            report.add(Finding(
                title="Loop with external calls — gas DoS risk",
                severity=SEVERITY_HIGH,
                category="Gas",
                description=(
                    "A loop makes external calls (send/transfer/call). If one recipient reverts "
                    "or consumes all gas, the entire transaction fails. This is a classic "
                    "gas-based DoS vector. Use pull-over-push withdrawal pattern."
                ),
                file=filepath,
                line=lineno,
                recommendation=(
                    "Replace the push-based payout with pull-based: let each recipient "
                    "withdraw their own funds individually instead of iterating over all recipients."
                ),
                references=[
                    "https://officercia.mirror.xyz/ZWYaJILJntwLtK7rXBfTU45bbBI7Zm1CXy5_S_YyDhM"
                ],
            ))
            break

        # --- .send() / .transfer() with fixed 2300 gas ---
        for m in re.finditer(r'\.(send|transfer)\s*\(', source):
            lineno = source[:m.start()].count('\n') + 1
            context = source[m.start():m.start() + 200]
            # Check if this looks like sending ETH to users (not to a contract)
            if not re.search(r'(WETH|weth|Wrapped)', context):
                report.add(Finding(
                    title="`.{0}` uses fixed 2300 gas — may fail with smart contract wallets".format(
                        m.group(0)[:10]
                    ),
                    severity=SEVERITY_MEDIUM if m.group(1) == 'send' else SEVERITY_LOW,
                    category="Gas",
                    description=(
                        f"`{m.group(0)[:20]}` forwards only 2300 gas. Smart contract wallets, "
                        "multisigs, or receivers with complex `receive()`/`fallback()` logic "
                        "will revert with insufficient gas. Use `.call{value: amount}(\"\")` "
                        "instead, which forwards all remaining gas."
                    ),
                    file=filepath,
                    line=lineno,
                    recommendation=(
                        "Replace with:\n"
                        "```solidity\n"
                        "(bool success, ) = payable(to).call{value: amount}(\"\");\n"
                        "require(success, \"ETH transfer failed\");\n"
                        "```"
                        "\n\n"
                        "Note: Ensure reentrancy protection is in place when using `call`."
                    ),
                ))
            break  # one per file
