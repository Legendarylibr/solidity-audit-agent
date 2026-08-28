"""
DeFi integration checks — AMM, Aave, Compound, Curve, flash loans.

Derived from:
  - Chapter 11: AMM Integration Tips
  - Chapter 21-22: AAVE V3 Integration
  - Chapter 23-24: Compound v2 Integration
  - Chapter 25: Convex Finance Integration
  - Chapter 26: CurveV1 Integration Tips
  - Chapter 28: BalancerV1 Integration Tips
"""

import re
from audit_agent import Check, Finding, AuditReport, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM


class AMMIntegrationCheck(Check):
    """Detects unsafe AMM integration patterns."""

    name = "amm"
    category = "DeFi Integration"

    def run(self, source: str, filepath: str, report: AuditReport):
        # --- Uniswap V3: unverified callback origin ---
        if re.search(r'uniswapV3SwapCallback', source):
            if not re.search(r'(factory|POOL_INIT_CODE_HASH|computeAddress|getPool)', source):
                report.add(Finding(
                    title="Uniswap V3 callback without pool verification",
                    severity=SEVERITY_CRITICAL,
                    category="DeFi Integration",
                    description=(
                        "`uniswapV3SwapCallback` is implemented but there's no verification that "
                        "the caller is the genuine Uniswap pool. An attacker can spoof being a pool "
                        "and call back into the contract. Always verify the pool address against the "
                        "factory or compute it deterministically via CREATE2."
                    ),
                    file=filepath,
                    line=1,
                    recommendation=(
                        "Verify the caller in the callback:\n"
                        "```solidity\n"
                        "require(\n"
                        "    msg.sender == IUniswapV3Factory(FACTORY).getPool(token0, token1, fee),\n"
                        "    \"Invalid pool\"\n"
                        ");\n"
                        "```"
                    ),
                    references=["https://officercia.mirror.xyz/dUf_OxeK8KvAWfdWHNaikJxDTEkfPRypFqnETJiMic4"],
                ))

        # --- Uniswap V2: skim() on deflationary tokens ---
        if re.search(r'\.skim\s*\(', source):
            if re.search(r'(deflationary|fee.?on.?transfer|_fee|tax|reflect)', source, re.I):
                report.add(Finding(
                    title="`skim()` with deflationary/fee token — potential drain",
                    severity=SEVERITY_HIGH,
                    category="DeFi Integration",
                    description=(
                        "`skim()` sends the balance difference to the caller. With a deflationary "
                        "or fee-on-transfer token, the actual received amount is less than the "
                        "transfer amount, and the difference can be extracted via `skim()`. "
                        "Reference: WDOGE-BNB drain via `skim()`."
                    ),
                    file=filepath,
                    line=1,
                    recommendation=(
                        "If the pool uses a fee-on-transfer token, rebase the reserve tracking "
                        "or disable `skim()` for the affected pair."
                    ),
                    references=["https://officercia.mirror.xyz/2SXrASlpw5L4PPQpXhJgiNyJ9b2CqfDzQHcGXZd4CHk"],
                ))

        # --- Slippage protection ---
        swap_funcs = re.finditer(
            r'function\s+(\w+).*?\{[^}]*\.swap\s*\(',
            source,
            re.DOTALL,
        )
        for m in swap_funcs:
            func_name = m.group(1)
            func_body = m.group(0)
            # Check for slippage parameters
            if not re.search(r'(amountOutMin|minAmountOut|minOut|slippage|_minOut|deadline)', func_body):
                lineno = source[:m.start()].count('\n') + 1
                report.add(Finding(
                    title=f"Swap function `{func_name}` lacks slippage protection",
                    severity=SEVERITY_MEDIUM,
                    category="DeFi Integration",
                    description=(
                        f"`{func_name}` performs a swap without `amountOutMin` (minimum output) "
                        "or `deadline` parameters. The transaction can be sandwiched by MEV bots, "
                        "resulting in a worse price for the user."
                    ),
                    file=filepath,
                    line=lineno,
                    recommendation=(
                        "1. Add `uint256 amountOutMin` and `uint256 deadline` parameters.\n"
                        "2. Revert if output is below `amountOutMin` or if block.timestamp > deadline.\n"
                        "3. Consider using a price oracle to validate the swap output."
                    ),
                ))


class FlashLoanCheck(Check):
    """Detects flash loan manipulable state checks."""

    name = "flash-loan"
    category = "DeFi Integration"

    def run(self, source: str, filepath: str, report: AuditReport):
        # Too many patterns to flag generically, but key signals:
        # 1. Balance-based pricing without flash loan awareness
        # 2. uniswapV2Call / uniswapV3FlashCallback without balance verification
        for callback in ['uniswapV2Call', 'uniswapV3FlashCallback', 'flashCallback']:
            if callback in source:
                # Check if the callback verifies the actual payment
                m = re.search(rf'function\s+{callback}\s*\(', source)
                if m:
                    brace = source.find('{', m.end())
                    if brace != -1:
                        body = source[brace:source.find('}', brace) + 1]
                        if 'balanceOf' not in body and 'balance' not in body:
                            lineno = source[:m.start()].count('\n') + 1
                            report.add(Finding(
                                title=f"`{callback}` may not verify paid-back amount",
                                severity=SEVERITY_HIGH,
                                category="DeFi Integration",
                                description=(
                                    f"`{callback}` does not explicitly verify the balance "
                                    "after repaying the flash loan. An attacker might not repay "
                                    "the full amount. Always check the balance after the callback "
                                    "to ensure the loan was fully repaid."
                                ),
                                file=filepath,
                                line=lineno,
                                recommendation=(
                                    "After executing the flash loan logic, verify that the "
                                    "contract's token balance has increased by at least the "
                                    "borrowed amount plus fee."
                                ),
                            ))
