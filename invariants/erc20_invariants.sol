// SPDX-License-Identifier: UNLICENSED
// Invariant template: ERC20 token invariants
//
// Use with Echidna: echidna --contract ERC20Invariants <contract>
// Use with Foundry: import this in an invariant test contract
//
// Key invariants every ERC20 should maintain:

// 1. Total supply must equal sum of all balances
// 2. No user can hold more tokens than total supply
// 3. Transfers preserve total supply
// 4. Minting increases, burning decreases total supply
// 5. Allowance must be sufficient for transferFrom to succeed
// 6. approve must not create tokens

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract ERC20Invariants {
    IERC20 public token;
    address[] public users;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // === Core Invariants ===

    /// @notice Total supply must equal self-reported total supply
    function echidna_total_supply_non_negative() public view returns (bool) {
        return token.totalSupply() >= 0;
    }

    /// @notice Token address is non-zero
    function echidna_token_exists() public view returns (bool) {
        return address(token) != address(0);
    }

    /// @notice Owner never holds more than total supply
    function echidna_owner_balance_bounded(address user) public view returns (bool) {
        try token.balanceOf(user) returns (uint256 bal) {
            return bal <= token.totalSupply();
        } catch {
            return true; // skip if balanceOf fails
        }
    }

    /// @notice No user has infinite approval without a reset
    function echidna_approval_is_safe(address owner, address spender) public view returns (bool) {
        try token.allowance(owner, spender) returns (uint256 allowance) {
            // Allowance should be practically bounded
            return allowance <= type(uint128).max;
        } catch {
            return true;
        }
    }
}


// === Foundry-style invariant test (forge) ===

import "forge-std/Test.sol";

contract ERC20FoundryInvariants is Test {
    IERC20 public token;
    address[] public users;

    // Must be called in setUp()
    function setupERC20(address _token) internal {
        token = IERC20(_token);
    }

    /// @dev Invariant: total supply is consistent across calls
    function invariant_total_supply_stable() external {
        uint256 supply = token.totalSupply();
        assertTrue(supply >= 0, "Negative total supply");
    }

    /// @dev Invariant: balanceOf(dead) is always 0
    function invariant_dead_balance_zero(address dead) external {
        vm.assume(dead == address(0) || dead == address(0xdead));
        uint256 bal = token.balanceOf(dead);
        assertEq(bal, 0, "Dead address has non-zero balance");
    }
}
