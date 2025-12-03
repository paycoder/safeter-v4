// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * 故意设计的漏洞合约 - 用于测试 V4
 * 漏洞: 缺少访问控制的提款函数
 */
contract VulnerableContract {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // 用户存款
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // ❌ 漏洞: 任何人都可以提取任何地址的余额
    function withdraw(address beneficiary, uint256 amount) public {
        // 缺少访问控制！应该是：
        // require(msg.sender == beneficiary, "Not authorized");

        require(balances[beneficiary] >= amount, "Insufficient balance");
        balances[beneficiary] -= amount;
        payable(msg.sender).transfer(amount);  // 注意：转给 msg.sender，而不是 beneficiary
    }

    // 查询余额
    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }
}
