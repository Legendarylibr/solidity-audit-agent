// SPDX-License-Identifier: MIT
// A deliberately vulnerable contract for smoke-testing the audit agent.
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;
    bool public paused;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    // Missing initializer modifier — anyone can re-init
    function initialize(address _owner) public {
        owner = _owner;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // Classic reentrancy: state updated AFTER external call
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call BEFORE state update — VULNERABLE
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
        emit Withdrawn(msg.sender, amount);
    }

    // Read-only reentrancy risk: view function returns sensitive data
    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }

    // tx.origin used for auth — phishing vulnerability
    function withdrawAllTo(address to) public {
        require(tx.origin == owner, "Not owner via tx.origin");
        uint256 amount = balances[msg.sender];
        (bool success, ) = to.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
    }

    // Unprotected sensitive function
    function setPaused(bool _paused) public {
        paused = _paused;
    }

    // Arbitrary call — user-supplied target
    function execute(address target, bytes calldata data) public returns (bytes memory) {
        (bool success, bytes memory result) = target.call(data);
        require(success, "Call failed");
        return result;
    }

    // Division before multiplication — precision loss
    function calculateRate(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
        return a / b * c;
    }

    // Unchecked arithmetic
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        unchecked {
            return a + b;
        }
    }

    // Predictable randomness
    function randomMint() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao, msg.sender)));
    }

    // Single-source oracle
    function getPrice() public view returns (uint256) {
        // Using AMM spot price directly
        return block.prevrandao;
    }
}
