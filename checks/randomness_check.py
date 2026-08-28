"""
Additional randomness checks — extends oracle.py's RandomnessCheck.

Derived from:
  - Chapter 03: Oracles, Entropy & Chainlink VRF
  - Chapter 04: Chainlink VRF Specifications
  - Chapter 06: Fuzzing with Echidna
"""

import re
from audit_agent import Check, Finding, AuditReport, SEVERITY_HIGH, SEVERITY_MEDIUM


class OnChainRandomnessCheck(Check):
    """Detects on-chain randomness as a source of PRNG."""

    name = "onchain-randomness"
    category = "Randomness"

    def run(self, source: str, filepath: str, report: AuditReport):
        # --- Wallets withdrawn after VRF request ---
        if re.search(r'requestRandomWords|requestRandomness', source):
            # Check if the contract locks state between request and fulfillment
            state_modifiers = re.finditer(
                r'function\s+(\w+).*?\{',
                source,
            )
            request_funcs = [m for m in state_modifiers
                             if 'requestRandom' in m.group(0)]
            for m in request_funcs:
                brace = source.find('{', m.end())
                if brace == -1:
                    continue
                body = source[brace:source.find('}', brace)]

                # Check if there's a "no bets after request" pattern
                if not re.search(r'(pendingRequest|requestInProgress|_locked|paused)', body):
                    lineno = source[:m.start()].count('\n') + 1
                    report.add(Finding(
                        title="VRF request without locking new state changes",
                        severity=SEVERITY_HIGH,
                        category="Randomness",
                        description=(
                            "After requesting VRF randomness, users should not be able to "
                            "change their bet/mint/entry until the randomness is fulfilled. "
                            "Otherwise, users can observe the pending randomness and modify "
                            "their position disadvantageously."
                        ),
                        file=filepath,
                        line=lineno,
                        recommendation=(
                            "Lock new state changes between VRF request and fulfillment:\n"
                            "```solidity\n"
                            "function requestRandomness() external onlyOwner {\n"
                            "    require(!pendingRequest, \"Request already pending\");\n"
                            "    pendingRequest = true;\n"
                            "    // ... request VRF\n"
                            "}\n"
                            "```"
                        ),
                        references=[
                            "https://officercia.mirror.xyz/ekYLAK6uZl2fNCCzAL0eCTtImBD8fSdTurM0duryoxU"
                        ],
                    ))
                break
