# How to Contribute

## Adding a New Static Check

1. Create `checks/<your_check>.py` with a class that extends `Check` from `audit_agent`:

```python
from audit_agent import Check, Finding, AuditReport, SEVERITY_MEDIUM

class YourCheck(Check):
    name = "your-check"
    category = "Your Category"

    def run(self, source: str, filepath: str, report: AuditReport):
        # Analyze source, add findings to report
        report.add(Finding(
            title="Issue title",
            severity=SEVERITY_MEDIUM,
            category=self.category,
            description="What the issue is and why it matters",
            file=filepath,
            recommendation="How to fix it",
        ))
```

2. Register it in `audit_agent.py`'s `register_checks()`.

3. Add a test case in `test/` and verify with:
   ```bash
   python audit_agent.py audit test/YourTest.sol
   ```

## Adding an Invariant Template

Create a `.sol` file in `invariants/`. It's auto-registered on import.

## Running All Static Checks

```bash
python audit_agent.py audit test/VulnerableBank.sol
```

## Style

- Python 3.10+ type annotations
- 100-char line length
- Each finding must include severity, description, and recommendation
- Reference the original source (SWC registry, Book chapter, audit post) when applicable
