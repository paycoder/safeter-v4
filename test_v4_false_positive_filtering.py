#!/usr/bin/env python3
"""
V4 误报过滤测试

使用 V3 验证的已知误报来测试 V4 的过滤能力

测试案例:
1. Radiant depositWithAutoDLP - V3: Critical → 实际: Medium/Low (可组合性问题)
2. Prisma Flash Loan - V3: High → 实际: 误报 (ERC20 余额保护)
3. Radiant zapWETH - V3: High → 实际: Low/Info (外层保护)
"""

from pathlib import Path
from poc_generator import PoCGenerator, VulnerabilityCandidate
from exploit_validator import ExploitValidator
from dotenv import load_dotenv

load_dotenv()


def test_case_1_radiant_deposit():
    """
    测试案例 1: Radiant depositWithAutoDLP

    V3 报告: Critical - tx.origin 权限提升
    实际: Medium/Low - 可组合性问题，但deposit()从msg.sender转账，无法盗取资金

    预期: V4 应该生成 PoC，但 PoC 测试应该失败（因为无法真正盗取资金）
    """
    print("\n" + "=" * 70)
    print("TEST CASE 1: Radiant depositWithAutoDLP")
    print("=" * 70)

    candidate = VulnerabilityCandidate(
        vuln_type="ACCESS_CONTROL",
        function_name="depositWithAutoDLP",
        contract_name="LendingPool",
        description="Uses tx.origin for authentication, allows privilege escalation",
        severity="Critical",
        code_snippet="""
function depositWithAutoDLP(
    address asset,
    uint256 amount,
    address onBehalfOf,
    uint16 referralCode
) external {
    require(tx.origin == onBehalfOf, "Invalid user");
    deposit(asset, amount, onBehalfOf, referralCode);
}

function deposit(
    address asset,
    uint256 amount,
    address onBehalfOf,
    uint16 referralCode
) public {
    IERC20(asset).safeTransferFrom(msg.sender, aToken, amount);  // ✅ 从 msg.sender 转账！
    IAToken(aToken).mint(onBehalfOf, amount);
}
"""
    )

    # 简化的合约代码用于测试
    contract_code = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MockERC20 {
    mapping(address => uint256) public balances;

    function safeTransferFrom(address from, address to, uint256 amount) public {
        require(balances[from] >= amount, "Insufficient balance");
        balances[from] -= amount;
        balances[to] += amount;
    }

    function mint(address to, uint256 amount) public {
        balances[to] += amount;
    }
}

contract LendingPool {
    MockERC20 public token;
    MockERC20 public aToken;

    constructor() {
        token = new MockERC20();
        aToken = new MockERC20();
    }

    function depositWithAutoDLP(
        uint256 amount,
        address onBehalfOf
    ) external {
        require(tx.origin == onBehalfOf, "Invalid user");
        deposit(amount, onBehalfOf);
    }

    function deposit(
        uint256 amount,
        address onBehalfOf
    ) public {
        // 关键：从 msg.sender 转账，而不是 onBehalfOf
        token.safeTransferFrom(msg.sender, address(aToken), amount);
        aToken.mint(onBehalfOf, amount);
    }

    function setupBalance(address user, uint256 amount) public {
        token.balances(user) = amount;
    }
}
"""

    # 生成 PoC
    generator = PoCGenerator()
    poc_result = generator.generate(candidate, contract_code)

    if poc_result.success:
        print(f"\n✅ PoC generated")

        # 验证 PoC
        validator = ExploitValidator()
        validation = validator.validate(
            poc_code=poc_result.poc_code,
            target_contract_code=contract_code,
            target_contract_name="LendingPool",
            poc_test_name=poc_result.contract_name
        )

        print(f"\n🧪 Validation Result:")
        print(f"   Exploitable: {validation.exploitable}")

        if not validation.exploitable:
            print(f"   ✅ CORRECT: V4 filtered this false positive!")
            print(f"   Reason: {validation.reason}")
            return True
        else:
            print(f"   ❌ ERROR: V4 should have filtered this!")
            return False
    else:
        print(f"\n✅ AI correctly identified this as not exploitable")
        print(f"   Reason: {poc_result.reason}")
        return True


def test_case_2_safe_contract():
    """
    测试案例 2: 安全合约（对照组）

    预期: V4 应该正确识别为安全
    """
    print("\n" + "=" * 70)
    print("TEST CASE 2: Safe Contract (Control)")
    print("=" * 70)

    candidate = VulnerabilityCandidate(
        vuln_type="ACCESS_CONTROL",
        function_name="withdraw",
        contract_name="SafeContract",
        description="Potential missing access control",
        severity="High",
        code_snippet="""
function withdraw(uint256 amount) public {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    payable(msg.sender).transfer(amount);
}
"""
    )

    contract_code = Path("v4_foundry_test/src/SafeContract.sol").read_text()

    # 生成 PoC
    generator = PoCGenerator()
    poc_result = generator.generate(candidate, contract_code)

    if not poc_result.success:
        print(f"\n✅ AI correctly identified as not exploitable")
        print(f"   Reason: {poc_result.reason}")
        return True

    # 如果生成了 PoC，验证它应该失败
    print(f"\n⚠️  PoC was generated, validating...")
    validator = ExploitValidator()
    validation = validator.validate(
        poc_code=poc_result.poc_code,
        target_contract_code=contract_code,
        target_contract_name="SafeContract",
        poc_test_name=poc_result.contract_name
    )

    if not validation.exploitable:
        print(f"   ✅ CORRECT: Validation filtered this")
        return True
    else:
        print(f"   ❌ ERROR: Safe contract should not be exploitable!")
        return False


def test_case_3_real_vulnerability():
    """
    测试案例 3: 真实漏洞（对照组）

    预期: V4 应该正确识别为可利用
    """
    print("\n" + "=" * 70)
    print("TEST CASE 3: Real Vulnerability (Control)")
    print("=" * 70)

    candidate = VulnerabilityCandidate(
        vuln_type="ACCESS_CONTROL",
        function_name="withdraw",
        contract_name="VulnerableContract",
        description="Missing access control allows anyone to withdraw from any address",
        severity="Critical",
        code_snippet="""
function withdraw(address beneficiary, uint256 amount) public {
    require(balances[beneficiary] >= amount);
    balances[beneficiary] -= amount;
    payable(msg.sender).transfer(amount);  // ❌ 转给 msg.sender 而不是 beneficiary
}
"""
    )

    contract_code = Path("v4_foundry_test/src/VulnerableContract.sol").read_text()

    # 生成 PoC
    generator = PoCGenerator()
    poc_result = generator.generate(candidate, contract_code)

    if not poc_result.success:
        print(f"\n❌ ERROR: AI should have generated PoC for real vulnerability")
        print(f"   Reason: {poc_result.reason}")
        return False

    print(f"\n✅ PoC generated")

    # 验证 PoC
    validator = ExploitValidator()
    validation = validator.validate(
        poc_code=poc_result.poc_code,
        target_contract_code=contract_code,
        target_contract_name="VulnerableContract",
        poc_test_name=poc_result.contract_name
    )

    if validation.exploitable:
        print(f"   ✅ CORRECT: Real vulnerability confirmed!")
        print(f"   Severity: {validation.severity}")
        return True
    else:
        print(f"   ❌ ERROR: Real vulnerability should be exploitable!")
        print(f"   Reason: {validation.reason}")
        return False


def main():
    """运行所有测试"""
    print("\n" + "=" * 70)
    print("V4 FALSE POSITIVE FILTERING TEST")
    print("Testing V4's ability to filter V3's known false positives")
    print("=" * 70)

    results = {}

    # 测试 1: V3 的误报
    try:
        results["Radiant depositWithAutoDLP"] = test_case_1_radiant_deposit()
    except Exception as e:
        print(f"\n❌ Test 1 failed with exception: {e}")
        results["Radiant depositWithAutoDLP"] = False

    # 测试 2: 安全合约
    try:
        results["Safe Contract"] = test_case_2_safe_contract()
    except Exception as e:
        print(f"\n❌ Test 2 failed with exception: {e}")
        results["Safe Contract"] = False

    # 测试 3: 真实漏洞
    try:
        results["Real Vulnerability"] = test_case_3_real_vulnerability()
    except Exception as e:
        print(f"\n❌ Test 3 failed with exception: {e}")
        results["Real Vulnerability"] = False

    # 汇总结果
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    for test_name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {test_name}")

    total = len(results)
    passed = sum(results.values())
    print(f"\nTotal: {passed}/{total} passed ({passed/total*100:.1f}%)")

    if passed == total:
        print("\n🎉 All tests passed! V4 is working correctly!")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")

    print("=" * 70)

    return passed == total


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
