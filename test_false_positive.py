#!/usr/bin/env python3
"""
测试 ExploitValidator 是否能正确过滤误报
"""

from pathlib import Path
from exploit_validator import ExploitValidator


def test_false_positive():
    """测试安全合约（应该测试失败 = 不可利用）"""

    print("=" * 60)
    print("Testing FALSE POSITIVE Detection")
    print("=" * 60)

    # 读取安全合约和失败的 PoC
    safe_contract = Path("v4_foundry_test/src/SafeContract.sol").read_text()
    failed_poc = Path("v4_foundry_test/test/FailedExploit.t.sol").read_text()

    # 创建验证器
    validator = ExploitValidator()

    # 验证
    print("\n🔍 Validating exploit against SAFE contract...\n")
    result = validator.validate(
        poc_code=failed_poc,
        target_contract_code=safe_contract,
        target_contract_name="SafeContract",
        poc_test_name="FailedExploitTest"
    )

    # 显示结果
    print("\n" + "=" * 60)
    print("VALIDATION RESULT")
    print("=" * 60)
    print(f"Exploitable: {result.exploitable}")
    print(f"Test Passed: {result.test_passed}")

    if not result.exploitable:
        print(f"\n✅ CORRECTLY FILTERED AS FALSE POSITIVE")
        print(f"   Reason: {result.reason}")
    else:
        print(f"\n❌ ERROR: Should have been filtered!")

    print("=" * 60)

    return result.exploitable == False


if __name__ == "__main__":
    success = test_false_positive()
    exit(0 if success else 1)
