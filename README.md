# Solidity Audit Agent

This does not replace regular auditing or make any claims about accuracy of findings. It is a agentic tool to help assist with secure smart contract development.

Static analysis, fuzzing harness generation, and structured audit reporting for Solidity smart contracts. Embeds the vulnerability taxonomy and field knowledge from [Officer's Big Auditing Book](https://github.com/OffcierCia/tips-solidity-code-auditors) into runnable code.

## Quick Start

```bash
# Audit a contract or project
python audit_agent.py audit path/to/contracts/ --out report.md

# Generate an Echidna/Foundry fuzz harness
python audit_agent.py fuzz path/to/contract.sol --out harness.sol

# Print invariant templates
python audit_agent.py invariants all
```

## What It Catches

Static checks (14 modules, covering the full vulnerability taxonomy from the Book):

| Category | Checks |
|---|---|
| **Reentrancy** | Single-function, cross-function, cross-contract, read-only reentrancy |
| **Access Control** | Missing `onlyOwner`/role guards, `tx.origin` auth |
| **Arithmetic** | Division-before-multiplication, short-type downcast truncation, unchecked overflow |
| **Oracle / Price** | Single-source oracle, spot-price manipulation, missing decimal normalization |
| **Randomness** | On-chain PRNG (`block.timestamp`, `blockhash`), VRF callback-revert, missing state lock |
| **Arbitrary Calls** | Unvalidated `.call()`/`.delegatecall()` to user-supplied targets |
| **Token Integration** | Unchecked ERC20 return values, approve race, fee-on-transfer, rebase, ERC777 reentrancy |
| **DeFi Integration** | Uniswap V3 callback spoofing, slippage protection, flash-loan repayment verification |
| **Initialization** | Unprotected `initialize()`, broken proxy init, missing storage gaps |
| **Meta-Transactions** | EIP-712 chain-ID omission, signature replay, missing deadlines |
| **NFT** | On-chain rarity randomness, unprotected metadata URIs, safeTransfer reentrancy |
| **Gas / DoS** | Unbounded loops, push-pull pattern violations, `send`/`transfer` fixed-gas |
| **Assembly / EVM** | Inline assembly, `selfdestruct`, `CREATE2`, `sload`/`sstore` |
| **Proxy** | UUPS without `_authorizeUpgrade`, missing storage gaps |

Each finding includes: severity, description, code snippet, recommendation, and reference links.

## Fuzzing Support

```bash
python audit_agent.py fuzz VulnerableBank.sol --out harness.sol
```

Generates an Echidna-compatible / Foundry-compatible harness with:
- Handler functions for every public/external function
- Echidna-style `echidna_*()` invariant assertions
- Deployed actor addresses for multi-user fuzzing

## Invariant Templates

Pre-built Solidity invariants for Echidna/Foundry that encode the canonical safety properties of common patterns:

```bash
python audit_agent.py invariants erc20          # ERC20 invariants
python audit_agent.py invariants access-control # Access control invariants
python audit_agent.py invariants protocol       # AMM/Vault/Protocol invariants
```

## Project Structure

```
.
├── audit_agent.py              # CLI entry point
├── checks/                     # 14 static analysis modules
│   ├── reentrancy.py
│   ├── access_control.py
│   ├── arithmetic.py
│   ├── oracle.py
│   ├── randomness_check.py
│   ├── delegation.py
│   ├── token_integration.py
│   ├── defi_integration.py
│   ├── initialization.py
│   ├── meta_tx.py
│   ├── nft_check.py
│   ├── gas_check.py
│   └── assembly_check.py
├── fuzzing/
│   └── harness_generator.py    # Echidna/Foundry harness generation
├── invariants/                 # Invariant templates
│   ├── erc20_invariants.sol
│   ├── access_control_invariants.sol
│   └── protocol_invariants.sol
├── test/
│   └── VulnerableBank.sol      # Smoke-test contract with planted bugs
├── README.md
├── LICENSE
├── CONTRIBUTING.md
└── setup.py
```

## Running the Smoke Test

```bash
python audit_agent.py audit test/VulnerableBank.sol
```

This contract contains 14 deliberate vulnerabilities across all major categories. The agent picks up every one.

## Requirements

- Python >= 3.10
- No external dependencies required for static analysis
- [Echidna](https://github.com/crytic/echidna) or [Foundry](https://book.getfoundry.sh/) for fuzzing with generated harnesses

## References

- [tips-solidity-code-auditors](https://github.com/OffcierCia/tips-solidity-code-auditors) — the curated knowledge base this agent was built from
- [Officer's Big Auditing Book](https://github.com/OffcierCia/tips-solidity-code-auditors/blob/main/Officers_Big_Auditing_Book.pdf) — 37 chapters on Solidity security auditing
- [SWC Registry](https://swcregistry.io/) — Smart Contract Weakness Classification
