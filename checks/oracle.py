"""
Oracle manipulation, price feed safety, and randomness checks.

Derived from:
  - Chapter 03: Oracles, Entropy & Chainlink VRF
  - Chapter 04: Chainlink VRF Specifications
  - Chapter 05: Price & Reward Manipulation Attacks Distilled
  - Chapter 19: Initializing, Proxy, Oracles & Multi-Chain
"""

import re
from audit_agent import (
    Check, Finding, AuditReport,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_INFO,
)


class OracleCheck(Check):
    """Detects unsafe oracle usage patterns."""

    name = "oracle"
    category = "Oracle / Price Manipulation"

    def run(self, source: str, filepath: str, report: AuditReport):
        # --- Single-source oracle (no comparison/decentralization) ---
        oracle_reads = list(re.finditer(r'\.(peek|latestAnswer|latestRoundData|getPrice|getRate)\s*\(', source))
        for m in oracle_reads:
            lineno = source[:m.start()].count('\n') + 1
            # Check if a second oracle source is also consulted nearby
            snippet_start = max(0, m.start() - 200)
            snippet_end = min(len(source), m.end() + 200)
            context = source[snippet_start:snippet_end]

            if not re.search(r'(peek|latestAnswer|latestRoundData|getPrice|getRate)\s*\(', context[m.end()-m.start():]):
                report.add(Finding(
                    title="Single-source oracle — price manipulation risk",
                    severity=SEVERITY_HIGH,
                    category="Oracle / Price Manipulation",
                    description=(
                        f"The contract reads from a single oracle at `{m.group(0)[:40]}`. "
                        "If this oracle (e.g., a single Uniswap TWAP, an untrusted feed, or a "
                        "manipulable on-chain price) returns a manipulated value, the contract's "
                        "logic can be exploited. Use multiple independent sources or a "
                        "decentralized oracle network like Chainlink."
                    ),
                    file=filepath,
                    line=lineno,
                    recommendation=(
                        "1. Use Chainlink Price Feeds (decentralized, multiple sources).\n"
                        "2. Implement a TWAP (Time-Weighted Average Price) with a safe window.\n"
                        "3. Add a circuit breaker that pauses if the price changes beyond a threshold.\n"
                        "4. Cross-reference at least two independent price sources."
                    ),
                    references=["https://officercia.mirror.xyz/2SXrASlpw5L4PPQpXhJgiNyJ9b2CqfDzQHcGXZd4CHk"],
                ))

        # --- Spot price from pool reserves (flash loan manipulable) ---
        reserve_reads = re.finditer(r'\.(getReserves|getAmountsOut|getAmountIn|swap)\s*\(', source)
        for m in reserve_reads:
            lineno = source[:m.start()].count('\n') + 1
            context_before = source[max(0, m.start() - 300):m.start()]
            # Check if this reserve value is used as a price oracle (not just for swapping)
            if 'price' in context_before.lower() or 'collateral' in context_before.lower() or 'value' in context_before.lower():
                # Check if TWAP is used
                if 'twap' not in source.lower() and 'cumulative' not in source.lower():
                    report.add(Finding(
                        title="Spot reserve price used without TWAP — flash loan manipulable",
                        severity=SEVERITY_HIGH,
                        category="Oracle / Price Manipulation",
                        description=(
                            "The contract reads spot reserves from a liquidity pool (e.g., "
                            "Uniswap V2 getReserves) and uses them for pricing. Spot prices can "
                            "be manipulated by flash loans in a single transaction. "
                            "Use a time-weighted average price (TWAP) instead."
                        ),
                        file=filepath,
                        line=lineno,
                        recommendation=(
                            "1. Use Uniswap V2/V3 TWAP oracles instead of spot prices.\n"
                            "2. Apply a minimum delay between price observation and use.\n"
                            "3. Add a price deviation check against a trusted reference."
                        ),
                    ))

        # --- Price without decimals check ---
        price_uses = re.finditer(r'price\s*[=:]\s*.*\b(peek|latestAnswer|getPrice|amountOut|reserve)\b', source, re.I)
        for m in price_uses:
            lineno = source[:m.start()].count('\n') + 1
            context = source[m.start():m.start() + 200]
            if 'decimals' not in context.lower() and 'scale' not in context.lower() and 'precision' not in context.lower():
                report.add(Finding(
                    title="Price used without decimal/scale normalization",
                    severity=SEVERITY_MEDIUM,
                    category="Oracle / Price Manipulation",
                    description=(
                        "Price values from different sources may have different decimal "
                        "precisions. Failing to normalize decimals before arithmetic can "
                        "lead to incorrect pricing, liquidation errors, or manipulation."
                    ),
                    file=filepath,
                    line=lineno,
                    recommendation=(
                        "Always normalize prices to a consistent decimal precision before "
                        "performing arithmetic. Chainlink feeds have their own decimals; "
                        "your token might have different decimals."
                    ),
                    references=["https://officercia.mirror.xyz/y7pHWYwL6cQwsSToolCvg2EuMkHZK5dfDSiRtS0akX8"],
                ))


class RandomnessCheck(Check):
    """Detects VRF misuse patterns from Chapter 04 specifications."""

    name = "vrf"
    category = "Oracle / Price Manipulation"

    def run(self, source: str, filepath: str, report: AuditReport):
        # --- fulfillRandomWords that can revert ---
        if 'fulfillRandomWords' in source:
            m = re.search(r'function\s+fulfillRandomWords\s*\(', source)
            if m:
                brace = source.find('{', m.end())
                if brace != -1:
                    # Check if function can revert
                    body = source[brace:source.find('}', brace) + 1]
                    if re.search(r'\brevert\b|\brequire\b|\bassert\b', body):
                        lineno = source[:m.start()].count('\n') + 1
                        report.add(Finding(
                            title="`fulfillRandomWords` can revert — VRF callback may fail",
                            severity=SEVERITY_HIGH,
                            category="Oracle / Price Manipulation",
                            description=(
                                "Chainlink VRF will not retry a failed `fulfillRandomWords` callback. "
                                "If this function reverts, the randomness request is lost permanently. "
                                "The function must handle all paths without reverting."
                            ),
                            file=filepath,
                            line=lineno,
                            recommendation=(
                                "Ensure `fulfillRandomWords` never reverts. Use try/catch pattern "
                                "or store the randomness and handle edge cases separately. "
                                "Per VRF spec: the callback MUST NOT revert."
                            ),
                            references=["https://officercia.mirror.xyz/ekYLAK6uZl2fNCCzAL0eCTtImBD8fSdTurM0duryoxU"],
                        ))

        # --- On-chain randomness ---
        for pattern, label in [
            (r'block\.timestamp', 'block.timestamp'),
            (r'block\.hash', 'block.prevrandao (or block.difficulty)'),
            (r'block\.gaslimit', 'block.gaslimit'),
            (r'blockhash\s*\(', 'blockhash()'),
            (r'now\b', 'now (alias for block.timestamp)'),
        ]:
            for m in re.finditer(pattern, source):
                lineno = source[:m.start()].count('\n') + 1
                report.add(Finding(
                    title=f"Predictable randomness source: `{label}`",
                    severity=SEVERITY_HIGH,
                    category="Oracle / Price Manipulation",
                    description=(
                        f"Using `{label}` as a source of randomness is predictable. "
                        "Miners/validators can influence these values. An attacker can wait "
                        "for a favorable outcome or, in extreme cases, buy it."
                    ),
                    file=filepath,
                    line=lineno,
                    recommendation=(
                        "Use Chainlink VRF for genuine randomness. VRF produces a provably "
                        "fair random number that cannot be manipulated by miners or users."
                    ),
                    references=[
                        "https://officercia.mirror.xyz/vUsNhI6GZhXWabifqFZqNmB93Fr0zsfIpCKBZEeEB7E",
                        "https://github.com/uni-due-syssec/eth-reentrancy-attack-patterns",
                    ],
                ))
                break  # one per pattern per file
