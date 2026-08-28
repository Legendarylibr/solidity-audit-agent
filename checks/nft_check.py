"""
NFT-specific vulnerability checks.

Derived from:
  - Chapter 27: Auditing Tips for NFT Projects
  - Quillhash NFT Attack Vectors
"""

import re
from audit_agent import Check, Finding, AuditReport, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_CRITICAL


class NFTCheck(Check):
    """Detects NFT-specific issues: randomness, metadata freeze, approvals."""

    name = "nft"
    category = "NFT"

    def run(self, source: str, filepath: str, report: AuditReport):
        # --- On-chain randomness for mint ---
        mint_funcs = re.finditer(
            r'function\s+mint\w*\s*\([^)]*\)\s*(?:public|external)[^{]*\{',
            source,
        )
        for m in mint_funcs:
            func_body_end = source.find('}', m.end())
            if func_body_end == -1:
                continue
            body = source[m.end():func_body_end]
            if re.search(r'(block\.(timestamp|hash|difficulty|prevrandao)|uint256\(blockhash)', body):
                lineno = source[:m.start()].count('\n') + 1
                report.add(Finding(
                    title="On-chain randomness for NFT minting — rarity manipulation",
                    severity=SEVERITY_CRITICAL,
                    category="NFT",
                    description=(
                        "The mint function uses on-chain values (block.timestamp, blockhash, etc.) "
                        "for random trait/rarity assignment. Miners or MEV bots can select blocks "
                        "where the randomness produces their desired outcome."
                    ),
                    file=filepath,
                    line=lineno,
                    recommendation=(
                        "Use Chainlink VRF for provably fair NFT minting randomness. "
                        "Request randomness, wait for fulfillment, then assign the token "
                        "and its traits in the callback."
                    ),
                    references=[
                        "https://officercia.mirror.xyz/YlW24vuFe7Ao0WWAxip1JgDXnyzX9B4cT_AoPFhD-Ww",
                        "https://github.com/Quillhash/NFT-Attack-Vectors",
                    ],
                ))
                break

        # --- Metadata not frozen / upgrade path unstable ---
        if re.search(r'(setBaseURI|setTokenURI|updateURI|setContractURI)', source):
            if not re.search(r'(onlyOwner|onlyAdmin|whenNotPaused)', source):
                report.add(Finding(
                    title="Metadata update function without access control",
                    severity=SEVERITY_MEDIUM,
                    category="NFT",
                    description=(
                        "The contract exposes metadata URI update functions. If these are "
                        "unprotected, the metadata can be changed to point to different "
                        "images/attributes after minting."
                    ),
                    file=filepath,
                    line=1,
                    recommendation=(
                        "1. Protect URI update functions with `onlyOwner`.\n"
                        "2. Consider adding a `baseURIFrozen` toggle to permanently lock metadata.\n"
                        "3. Use content-addressed storage (IPFS with pinning) for immutable metadata."
                    ),
                ))

        # --- ERC721 .safeTransferFrom reentrancy ---
        if 'safeTransferFrom' in source or 'safeMint' in source:
            report.add(Finding(
                title="`safeTransferFrom`/`safeMint` — ERC721 receiver callback reentrancy",
                severity=SEVERITY_MEDIUM,
                category="NFT",
                description=(
                    "ERC721 `safeTransferFrom` and `safeMint` call `onERC721Received` on the "
                    "recipient. If this callback re-enters the contract before state updates "
                    "are finalized, it can exploit stale state. Apply reentrancy guards."
                ),
                file=filepath,
                line=1,
                recommendation=(
                    "1. Apply the `nonReentrant` modifier from ReentrancyGuard.\n"
                    "2. Apply checks-effects-interactions: update state before calling safeTransfer.\n"
                    "3. Consider using `_transfer` (unsafe) with explicit recipient verification."
                ),
                references=[
                    "https://officercia.mirror.xyz/YlW24vuFe7Ao0WWAxip1JgDXnyzX9B4cT_AoPFhD-Ww",
                ],
            ))
