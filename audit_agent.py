"""
Solidity Audit Agent — Officer's Big Auditing Book distilled into code.

Static analysis, fuzzing harness generation, and structured audit reporting
based on the vulnerability taxonomy and field knowledge from:
    https://github.com/OffcierCia/tips-solidity-code-auditors

Usage:
    python audit_agent.py audit path/to/contracts/ --out report.md
    python audit_agent.py fuzz path/to/contract.sol --out harness.sol
    python audit_agent.py invariants erc20          # list invariant templates
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_GAS = "Gas"
SEVERITY_INFO = "Info"


@dataclass
class Finding:
    title: str
    severity: str
    category: str
    description: str
    file: str
    line: Optional[int] = None
    snippet: Optional[str] = None
    recommendation: Optional[str] = None
    references: List[str] = field(default_factory=list)


@dataclass
class AuditReport:
    target: str
    findings: List[Finding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def add(self, finding: Finding):
        self.findings.append(finding)

    def finalize(self):
        sev = {}
        for f in self.findings:
            sev[f.severity] = sev.get(f.severity, 0) + 1
        cats = {}
        for f in self.findings:
            cats.setdefault(f.category, []).append(f.title)
        self.summary = {
            "total": len(self.findings),
            "severity": sev,
            "categories": cats,
        }

    def markdown(self) -> str:
        self.finalize()
        lines = [
            f"# Solidity Audit Report — `{self.target}`",
            "",
            "## Summary",
            f"- **Total findings**: {self.summary['total']}",
        ]
        for sev in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
                     SEVERITY_LOW, SEVERITY_GAS, SEVERITY_INFO]:
            c = self.summary["severity"].get(sev, 0)
            if c:
                lines.append(f"- **{sev}**: {c}")
        lines += [
            "",
            "## Findings by Category",
        ]
        for cat, titles in sorted(self.summary["categories"].items()):
            lines.append(f"- **{cat}** ({len(titles)})")
        lines += ["", "---", ""]

        for i, f in enumerate(self.findings, 1):
            lines += [
                f"### {i}. [{f.severity}] {f.title}",
                f"**Category**: {f.category}  ",
                f"**File**: `{f.file}`"
                + (f"  **Line**: {f.line}" if f.line else ""),
                "",
                f.description,
            ]
            if f.snippet:
                lines += ["", f"```solidity\n{f.snippet}\n```"]
            if f.recommendation:
                lines += ["", "**Recommendation**:", "", f.recommendation]
            if f.references:
                lines += ["", "**References**:", ""] + [
                    f"- {r}" for r in f.references
                ]
            lines += ["", "---", ""]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Source loader
# ---------------------------------------------------------------------------

def load_solidity_files(path: str) -> dict[str, str]:
    """Return {filepath: content} for all .sol files under *path*."""
    p = Path(path)
    if p.is_file():
        return {str(p): p.read_text(encoding="utf-8", errors="replace")}
    result = {}
    for f in sorted(p.rglob("*.sol")):
        result[str(f)] = f.read_text(encoding="utf-8", errors="replace")
    return result


# ---------------------------------------------------------------------------
# Check base
# ---------------------------------------------------------------------------

class Check:
    """Override `run(source, filepath, report)`."""
    name = "base"
    category = "General"

    def run(self, source: str, filepath: str, report: AuditReport):
        raise NotImplementedError


def register_checks():
    """Lazy-import all check modules so the agent stays loadable."""
    import sys
    from pathlib import Path

    # Ensure the agent's own directory is on sys.path so that package-level
    # imports (from audit_agent import ...) resolve when run as a script.
    _self = Path(__file__).parent.resolve()
    if str(_self) not in sys.path:
        sys.path.insert(0, str(_self))

    from checks import (
        reentrancy,
        access_control,
        arithmetic,
        oracle,
        delegation,
        token_integration,
        defi_integration,
        assembly_check,
        gas_check,
        randomness_check,
        initialization,
        meta_tx,
        nft_check,
    )
    return [
        reentrancy.ReentrancyCheck(),
        reentrancy.ReadOnlyReentrancyCheck(),
        access_control.AccessControlCheck(),
        access_control.TxOriginCheck(),
        arithmetic.ArithmeticCheck(),
        arithmetic.ShortTypeCheck(),
        oracle.OracleCheck(),
        oracle.RandomnessCheck(),
        delegation.ArbitraryCallCheck(),
        delegation.DelegateCallCheck(),
        token_integration.ERC20IntegrationCheck(),
        token_integration.ERC777Check(),
        defi_integration.AMMIntegrationCheck(),
        defi_integration.FlashLoanCheck(),
        assembly_check.AssemblyAuditCheck(),
        gas_check.GasOptimizationCheck(),
        gas_check.GasDoSCheck(),
        randomness_check.OnChainRandomnessCheck(),
        initialization.InitializerCheck(),
        initialization.ProxyCheck(),
        meta_tx.SignatureReplayCheck(),
        meta_tx.EIP712Check(),
        nft_check.NFTCheck(),
    ]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_audit(target: str, out: Optional[str] = None) -> AuditReport:
    sources = load_solidity_files(target)
    checks = register_checks()
    report = AuditReport(target=target)

    for filepath, source in sources.items():
        for check in checks:
            try:
                check.run(source, filepath, report)
            except Exception as exc:
                report.add(Finding(
                    title=f"Check '{check.name}' crashed on {filepath}",
                    severity=SEVERITY_INFO,
                    category="Internal",
                    description=f"Exception: {exc}",
                    file=filepath,
                ))

    md = report.markdown()
    if out:
        Path(out).write_text(md, encoding="utf-8")
        print(f"Report written to {out}")
    else:
        print(md)
    return report


def run_fuzz(contract_source: str, out: Optional[str] = None):
    """Generate Echidna/Foundry fuzz harness for a given Solidity file."""
    from fuzzing.harness_generator import generate_fuzz_harness
    source = Path(contract_source).read_text(encoding="utf-8", errors="replace")
    harness = generate_fuzz_harness(source, contract_source)
    if out:
        Path(out).write_text(harness, encoding="utf-8")
        print(f"Fuzz harness written to {out}")
    else:
        print(harness)


def list_invariants(kind: str):
    """Print invariant templates."""
    from invariants import get_template
    print(get_template(kind))


def main():
    parser = argparse.ArgumentParser(
        description="Solidity Audit Agent — from Officer's Big Auditing Book",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # audit
    a = sub.add_parser("audit", help="Run static analysis audit")
    a.add_argument("target", help="Solidity file or directory")
    a.add_argument("--out", "-o", help="Output markdown file")

    # fuzz
    f = sub.add_parser("fuzz", help="Generate Echidna/Foundry fuzz harness")
    f.add_argument("target", help="Solidity file")
    f.add_argument("--out", "-o", help="Output Solidity file")

    # invariants
    i = sub.add_parser("invariants", help="Show invariant templates")
    i.add_argument(
        "kind", nargs="?",
        choices=["erc20", "access-control", "protocol", "all"],
        default="all",
    )

    args = parser.parse_args()

    if args.command == "audit":
        run_audit(args.target, args.out)
    elif args.command == "fuzz":
        run_fuzz(args.target, args.out)
    elif args.command == "invariants":
        list_invariants(args.kind)


if __name__ == "__main__":
    main()
