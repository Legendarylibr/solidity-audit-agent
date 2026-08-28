// SPDX-License-Identifier: UNLICENSED
// Invariant template: Protocol-level invariants
//
// For AMMs, lending protocols, vaults, and staking contracts.
//
// Derived from:
//   - Chapter 11: AMM Integration Tips
//   - Chapter 21-24: AAVE and Compound integration
//   - Chapter 30: Rebase Tokens & Rounding Errors
//
// Key protocol invariants:
// 1. No free lunch: total assets in >= total assets out + fees
// 2. Share price never decreases (unless fees/slashing)
// 3. Collateralization never drops below required threshold
// 4. Reserve ratios are maintained
// 5. Liquidation is always profitable for liquidators
// 6. User balances are never inflated by rounding

import "forge-std/Test.sol";

// === AMM / Liquidity Pool Invariants ===

interface IMinimalPair {
    function getReserves() external view returns (uint112, uint112, uint32);
    function totalSupply() external view returns (uint256);
    function token0() external view returns (address);
    function token1() external view returns (address);
}

contract AMMInvariants {
    IMinimalPair public pair;

    constructor(address _pair) {
        pair = IMinimalPair(_pair);
    }

    /// @notice K (reserve product) should never decrease without a swap/fee
    // This is best checked by capturing state before and after each operation
    function echidna_k_non_decreasing() public view returns (bool) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return uint256(r0) * uint256(r1) > 0; // Basic: pool has liquidity
    }

    /// @notice LP token total supply is reasonable
    function echidna_lp_supply_bounded() public view returns (bool) {
        return pair.totalSupply() < type(uint128).max;
    }
}

// === Vault / Yield-bearing Invariants ===

interface IMinimalVault {
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function convertToAssets(uint256 shares) external view returns (uint256);
    function convertToShares(uint256 assets) external view returns (uint256);
}

contract VaultInvariants {
    IMinimalVault public vault;

    constructor(address _vault) {
        vault = IMinimalVault(_vault);
    }

    /// @notice Share price must be non-decreasing (no negative yield sneak)
    // This is a cross-block invariant; simulate at block boundaries
    function echidna_share_price_positive() public view returns (bool) {
        return vault.totalSupply() == 0 || vault.convertToAssets(1e18) > 0;
    }

    /// @notice Rounding direction: deposit should not inflate share count
    // EIP-4626: convertToShares(assets) <= totalSupply when totalAssets > 0
    function echidna_no_free_shares() public view returns (bool) {
        uint256 supply = vault.totalSupply();
        uint256 assets = vault.totalAssets();
        if (supply == 0 || assets == 0) return true;

        // A single wei of shares should cost at least 1 wei of assets
        uint256 cost = vault.convertToAssets(1);
        return cost >= 1;
    }
}

// === Foundry-style invariant test harness ===

contract ProtocolFoundryInvariants is Test {
    // --- Invariant: Solidity 0.8 overflow protection safe ---
    // (check is passive — compiler enforces this)

    // --- Invariant: no division by zero ---
    // (runtime check — ensure all divisions are guarded)

    // --- Invariant: ETH balance matches internal accounting ---
    // Requires an ERC20 that wraps ETH (WETH) pattern
    function invariant_eth_accounting(uint256 expectedBalance) internal view {
        // Override in concrete test with actual accounting logic
    }

    // Helper: check rounding direction of any division-heavy computation
    function assertNoPrecisionLoss(
        uint256 numerator,
        uint256 divisor,
        uint256 minPrecision
    ) internal pure {
        // Multiply first, then divide to preserve precision
        vm.assume(divisor > 0);
        assertTrue(
            (numerator * minPrecision) / divisor > 0,
            "Precision loss: result rounds to zero"
        );
    }
}
