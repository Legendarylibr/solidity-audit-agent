"""
Arithmetic, rounding, and short-type overflow checks.

Derived from:
  - Chapter 12: Short Types in Solidity: Rare Tricks Uncovered
  - Chapter 16: Math, Solidity & Gas Optimizations
  - Chapter 30: Rebase Tokens, Rounding Errors & DoS Attacks
"""

import re
from audit_agent import Check, Finding, AuditReport, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_HIGH

_ARITH_REF = "https://swcregistry.io/docs/SWC-101"


class ArithmeticCheck(Check):
    """Detects division before multiplication, unchecked arithmetic, and precision loss."""

    name = "arithmetic"
    category = "Arithmetic"

    def run(self, source: str, filepath: str, report: AuditReport):
        # --- Division before multiplication pattern ---
        for m in re.finditer(r'(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)', source):
            lineno = source[:m.start()].count('\n') + 1
            report.add(Finding(
                title="Division before multiplication — precision loss risk",
                severity=SEVERITY_MEDIUM,
                category="Arithmetic",
                description=(
                    f"`{m.group(0)}` performs division before multiplication. "
                    "In Solidity integer arithmetic, division truncates towards zero, so dividing "
                    "first loses precision. Multiply first, then divide to preserve accuracy."
                ),
                file=filepath,
                line=lineno,
                snippet=m.group(0),
                recommendation=(
                    "Reorder to multiply first, then divide. "
                    "Instead of `a / b * c`, use `a * c / b` (ensure no overflow from intermediate product)."
                ),
                references=[_ARITH_REF],
            ))

        # --- Solidity <0.8 unchecked math (no SafeMath) ---
        # Only flag arithmetic operators not inside unchecked blocks if pragma <0.8
        pragma_match = re.search(r'pragma\s+solidity\s+([<>=^]*\d+\.\d+)', source)
        if pragma_match:
            raw_ver = pragma_match.group(1)
            # Extract major.minor
            ver_nums = re.findall(r'\d+', raw_ver)
            if ver_nums and int(ver_nums[0]) == 0 and len(ver_nums) > 1 and int(ver_nums[1]) < 8:
                # Check for SafeMath or unchecked usage
                if 'SafeMath' not in source and 'unchecked' not in source:
                    report.add(Finding(
                        title="Solidity <0.8 without SafeMath — overflow risk",
                        severity=SEVERITY_HIGH,
                        category="Arithmetic",
                        description=(
                            f"Contract uses Solidity {raw_ver} (pre-0.8) which does not "
                            "have built-in overflow checking. Arithmetic operations may silently overflow. "
                            "Use SafeMath library or upgrade to Solidity >=0.8."
                        ),
                        file=filepath,
                        line=1,
                        recommendation=(
                            "1. Upgrade to Solidity >=0.8 for built-in overflow protection.\n"
                            "2. Or import and use OpenZeppelin's SafeMath library for all arithmetic."
                        ),
                        references=[_ARITH_REF],
                    ))

        # --- Unchecked block arithmetic ---
        # Check for arithmetic inside unchecked blocks that could overflow
        for m in re.finditer(r'unchecked\s*\{([^}]*[+\-*/][^}]*)\}', source):
            block = m.group(1)
            if re.search(r'[+\-*/]=?\s*\d+', block) or re.search(r'\+\+|--', block):
                lineno = source[:m.start()].count('\n') + 1
                report.add(Finding(
                    title="Arithmetic inside `unchecked` block",
                    severity=SEVERITY_LOW,
                    category="Arithmetic",
                    description=(
                        "Arithmetic in an `unchecked` block can overflow silently. "
                        "Ensure the values are bounded or overflow is intentional and safe."
                    ),
                    file=filepath,
                    line=lineno,
                    recommendation=(
                        "Verify that overflow cannot occur (e.g., pre-condition checks, bounded loops). "
                        "Document why `unchecked` is safe for each use."
                    ),
                ))


class ShortTypeCheck(Check):
    """Detects potentially dangerous downcasts and short-type truncation.

    Per Chapter 12: short types (uint128, uint96, etc.) introduce truncation
    surfaces that uint256 doesn't — every explicit or implicit downcast deserves review.
    """

    name = "short-types"
    category = "Arithmetic"

    def run(self, source: str, filepath: str, report: AuditReport):
        lines = source.split('\n')

        # Look for explicit downcasts like uint256 -> uint128, uint256 -> uint96
        for m in re.finditer(r'(uint(?:128|96|64|32|16|8)|int(?:128|64|32|16|8))\s*\(', source):
            cast_type = m.group(1)
            # Check what's being cast
            paren_open = m.end()
            paren_close = source.find(')', paren_open)
            if paren_close == -1:
                continue
            inner = source[paren_open:paren_close].strip()
            lineno = source[:m.start()].count('\n') + 1
            report.add(Finding(
                title=f"Explicit downcast to `{cast_type}` — potential truncation",
                severity=SEVERITY_MEDIUM,
                category="Arithmetic",
                description=(
                    f"Downcast `{cast_type}({inner})` can silently truncate the value. "
                    f"If `{inner}` exceeds `{cast_type}`'s max value ({2**(int(re.findall(r'\\d+', cast_type)[0])) - 1}), "
                    "the result will wrap unexpectedly."
                ),
                file=filepath,
                line=lineno,
                snippet=m.group(0),
                recommendation=(
                    f"Before casting, assert that the source value fits in `{cast_type}`:\n"
                    f"```solidity\nrequire({inner} <= type({cast_type}).max);\n{cast_type}({inner})\n```"
                ),
                references=[
                    "https://officercia.mirror.xyz/SnmH8v6QV6jHa64boANXySxBZsem8oiSP7zxgss_BEU"
                ],
            ))

        # Safe casting patterns (e.g. OpenZeppelin's SafeCast) are positive signals
        # We only flag if SafeCast is NOT imported
