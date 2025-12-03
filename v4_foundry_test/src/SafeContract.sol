// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * 安全合约 - 有适当的访问控制
 */
contract SafeContract {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // ✅ 正确的访问控制
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }
}
