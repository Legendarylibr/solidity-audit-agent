"""
Meta-transaction, EIP-712, and signature replay checks.

Derived from:
  - Chapter 20: Tokens, EIP-712 & Meta-Transactions
  - Chapter 27: Auditing Tips for NFT Projects
"""

import re
from audit_agent import Check, Finding, AuditReport, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM


class EIP712Check(Check):
    """Detects EIP-712 implementation issues."""

    name = "eip712"
    category = "Meta-Transactions / EIP-712"

    def run(self, source: str, filepath: str, report: AuditReport):
        # --- EIP-712 domain separator not matched to chain/contract ---
        if 'EIP712' in source or 'eip712' in source.lower() or '_domainSeparatorV4' in source:
            # Check for replay protection across chains
            if not re.search(r'block\.chainid|chain\.id|CHAIN_ID', source):
                report.add(Finding(
                    title="EIP-712 domain separator may not include chain ID",
                    severity=SEVERITY_MEDIUM,
                    category="Meta-Transactions / EIP-712",
                    description=(
                        "EIP-712 signatures must include the chain ID in the domain separator "
                        "to prevent cross-chain replay attacks. Without it, signatures collected "
                        "on one chain (e.g., L2 testnet) can be replayed on another (e.g., mainnet)."
                    ),
                    file=filepath,
                    line=1,
                    recommendation=(
                        "Ensure the domain separator includes `block.chainid` so signatures "
                        "are bound to a single chain. OpenZeppelin's EIP712 does this automatically."
                    ),
                    references=["https://officercia.mirror.xyz/nlIR1RkT5xIv4sZFYiOXCPhF2BJyAaJtOeVr6zsULsA"],
                ))

        # --- permit() without nonce management ---
        if 'permit' in source or 'ERC20Permit' in source:
            if not re.search(r'nonces\[|_nonces|nonce\s*\+\+', source):
                report.add(Finding(
                    title="`permit()` without nonce-based replay protection",
                    severity=SEVERITY_HIGH,
                    category="Meta-Transactions / EIP-712",
                    description=(
                        "The permit function (EIP-2612 / ERC20Permit) must use nonces to "
                        "prevent signature replay. Without nonces, the same signature can be "
                        "submitted multiple times."
                    ),
                    file=filepath,
                    line=1,
                    recommendation=(
                        "Implement a nonce counter per-address, incrementing on each permit use. "
                        "OpenZeppelin's ERC20Permit handles this correctly."
                    ),
                ))


class SignatureReplayCheck(Check):
    """Detects signature replay vulnerabilities."""

    name = "signature-replay"
    category = "Meta-Transactions / EIP-712"

    def run(self, source: str, filepath: str, report: AuditReport):
        # --- ecrecover without address recovery from signature ---
        for m in re.finditer(r'ecrecover\s*\(', source):
            lineno = source[:m.start()].count('\n') + 1
            # Check if used/consumed tracking exists
            context = source[max(0, m.start() - 500):m.end() + 500]
            if not re.search(r'(nonce|usedNonces|_usedHashes|consumed|signatureCount|isValid)', context):
                report.add(Finding(
                    title="Signature verification with `ecrecover` without replay protection",
                    severity=SEVERITY_HIGH,
                    category="Meta-Transactions / EIP-712",
                    description=(
                        "`ecrecover` is used to verify off-chain signatures, but there is no "
                        "visible nonce, used-hash tracking, or expiry check. Without replay "
                        "protection, the same signature can be reused indefinitely."
                    ),
                    file=filepath,
                    line=lineno,
                    recommendation=(
                        "1. Track used signatures (e.g., `mapping(bytes32 => bool) usedSignatures`).\n"
                        "2. Use EIP-712 structured data with nonces and deadlines.\n"
                        "3. Consider OpenZeppelin's SignatureChecker utility."
                    ),
                    references=["https://swcregistry.io/docs/SWC-121"],
                ))
                break  # one per file

        # --- Missing deadline ---
        sig_funcs = re.finditer(
            r'function\s+\w+.*\{[^}]*ecrecover\(',
            source, re.DOTALL,
        )
        for m in sig_funcs:
            if 'deadline' not in m.group(0) and '_deadline' not in m.group(0):
                lineno = source[:m.start()].count('\n') + 1
                report.add(Finding(
                    title="Signature-based function missing deadline parameter",
                    severity=SEVERITY_LOW,
                    category="Meta-Transactions / EIP-712",
                    description=(
                        "Functions accepting off-chain signatures should include a `deadline` "
                        "parameter to prevent stale signatures from being used indefinitely."
                    ),
                    file=filepath,
                    line=lineno,
                    recommendation=(
                        "Add a `uint256 deadline` parameter and check `block.timestamp <= deadline`."
                    ),
                ))
                break
