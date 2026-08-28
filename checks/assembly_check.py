"""
Assembly and EVM-level checks.

Derived from:
  - Chapter 15: EVM Limitations & Assembly Auditing Tips
  - Chapter 37: How Does a Compiler Actually Work?
"""

import re
from audit_agent import Check, Finding, AuditReport, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_HIGH


class AssemblyAuditCheck(Check):
    """Flags inline assembly blocks and known dangerous opcodes."""

    name = "assembly"
    category = "Assembly / EVM"

    def run(self, source: str, filepath: str, report: AuditReport):
        # Inline assembly usage
        for m in re.finditer(r'assembly\s*\{', source):
            lineno = source[:m.start()].count('\n') + 1
            report.add(Finding(
                title="Inline assembly block used",
                severity=SEVERITY_MEDIUM,
                category="Assembly / EVM",
                description=(
                    "The contract uses inline assembly (`assembly { ... }`). Solidity's safety "
                    "guarantees (overflow checks, access control) do not apply inside assembly. "
                    "Each assembly block should be carefully reviewed for correctness."
                ),
                file=filepath,
                line=lineno,
                recommendation=(
                    "1. Minimize assembly usage; prefer high-level Solidity when possible.\n"
                    "2. Review each assembly block for: unchecked overflow, incorrect storage "
                    "slot access, memory corruption.\n"
                    "3. Test edge cases thoroughly with a fuzzer like Echidna."
                ),
                references=[
                    "https://officercia.mirror.xyz/UDdVm2Nhc4obWJz9Sc-5MeYEZC4Lx04POy9M4v3cM34"
                ],
            ))
            break  # one finding per file is sufficient

        # Dangerous opcodes / patterns
        dangerous = {
            r'\bselfdestruct\b': "`selfdestruct` — contract can be destroyed, funds sent to target",
            r'\bsuicide\b': "`suicide` — deprecated alias for selfdestruct",
            r'\.delegatecall\b': "`delegatecall` — execution in caller's storage context",
            r'create2\b': "`CREATE2` — contract address can be precomputed; collision risk with prior bytecode",
        }
        for pattern, desc in dangerous.items():
            for m in re.finditer(pattern, source):
                lineno = source[:m.start()].count('\n') + 1
                report.add(Finding(
                    title=f"Dangerous opcode/pattern: {desc.split(' — ')[0]}",
                    severity=SEVERITY_HIGH if 'selfdestruct' in desc else SEVERITY_MEDIUM,
                    category="Assembly / EVM",
                    description=desc,
                    file=filepath,
                    line=lineno,
                    recommendation=_opcode_recommendation(pattern),
                ))
                break  # one per pattern per file

        # Storage slot access patterns
        for m in re.finditer(r'sload\(|sstore\(', source):
            lineno = source[:m.start()].count('\n') + 1
            report.add(Finding(
                title="Direct storage slot access (`sload`/`sstore`)",
                severity=SEVERITY_LOW,
                category="Assembly / EVM",
                description=(
                    "The contract accesses raw storage slots via `sload`/`sstore`. "
                    "This bypasses Solidity's abstraction and can lead to storage collisions "
                    "or incorrect slot mappings if storage layout is misunderstood."
                ),
                file=filepath,
                line=lineno,
                recommendation=(
                    "Clearly document which storage slot each `sload`/`sstore` accesses. "
                    "Use foundry's `forge inspect` to verify the storage layout."
                ),
            ))
            break


def _opcode_recommendation(pattern: str) -> str:
    if 'selfdestruct' in pattern or 'suicide' in pattern:
        return (
            "1. Remove `selfdestruct` if not absolutely necessary.\n"
            "2. If needed, protect with `onlyOwner` and consider a timelock delay.\n"
            "3. Understand that selfdestruct may be removed in future EVM upgrades (EIP-4758)."
        )
    if 'delegatecall' in pattern:
        return (
            "1. Ensure the target is a trusted, immutable contract.\n"
            "2. Verify storage layout compatibility.\n"
            "3. Use transparent proxy pattern if upgradeability is required."
        )
    if 'create2' in pattern:
        return (
            "1. Ensure the salt is not user-controlled in a way that enables front-running.\n"
            "2. Check for address collision with previously deployed bytecode.\n"
            "3. Verify the contract at the CREATE2 address before assuming its behavior."
        )
    return "Review the pattern and document why it's safe."
