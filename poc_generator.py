#!/usr/bin/env python3
"""
PoCGenerator - V4 PoC 生成器
基于 Claude AI 自动生成 Foundry 攻击测试

核心思路:
1. 接收漏洞候选（来自 V3 扫描器）
2. 使用 Claude 生成针对性的 Foundry 测试
3. 返回可执行的 PoC 代码
"""

import os
import json
from dataclasses import dataclass
from typing import Optional, Dict, Any
from pathlib import Path
import requests
from dotenv import load_dotenv

# 加载 .env 文件
load_dotenv()


@dataclass
class VulnerabilityCandidate:
    """漏洞候选（来自 V3 扫描）"""
    vuln_type: str  # 漏洞类型（ACCESS_CONTROL, REENTRANCY, etc.）
    function_name: str  # 问题函数名
    contract_name: str  # 合约名
    description: str  # 问题描述
    severity: str  # 严重程度（V3 估计）
    code_snippet: str  # 问题代码片段


@dataclass
class PoCResult:
    """PoC 生成结果"""
    success: bool  # 是否成功生成
    poc_code: Optional[str]  # PoC 代码
    contract_name: str  # 测试合约名
    reason: str = ""  # 失败原因（如果适用）


class PoCGenerator:
    """
    PoC 生成器

    使用 Claude AI 根据漏洞候选生成 Foundry 测试
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "anthropic/claude-3.5-sonnet"):
        """
        初始化生成器

        Args:
            api_key: OpenRouter API key
            model: AI 模型
        """
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY not set")

        self.model = model
        self.api_url = "https://openrouter.ai/api/v1/chat/completions"

    def generate(
        self,
        candidate: VulnerabilityCandidate,
        full_contract_code: str
    ) -> PoCResult:
        """
        为漏洞候选生成 PoC

        Args:
            candidate: 漏洞候选
            full_contract_code: 完整合约代码

        Returns:
            PoCResult
        """
        print(f"\n🔨 Generating PoC for {candidate.vuln_type} in {candidate.function_name}...")

        # 构建 prompt
        prompt = self._build_prompt(candidate, full_contract_code)

        # 调用 AI
        try:
            poc_code = self._call_ai(prompt)

            # 验证生成的代码
            if self._validate_poc(poc_code):
                print(f"✅ PoC generated successfully")
                return PoCResult(
                    success=True,
                    poc_code=poc_code,
                    contract_name=f"{candidate.contract_name}ExploitTest"
                )
            else:
                print(f"❌ Generated PoC failed validation")
                return PoCResult(
                    success=False,
                    poc_code=None,
                    contract_name="",
                    reason="Invalid PoC format"
                )

        except Exception as e:
            print(f"❌ PoC generation failed: {e}")
            return PoCResult(
                success=False,
                poc_code=None,
                contract_name="",
                reason=str(e)
            )

    def _build_prompt(self, candidate: VulnerabilityCandidate, contract_code: str) -> str:
        """
        构建 PoC 生成 prompt

        基于 SCONE-bench 的思路:
        - 提供完整上下文
        - 要求生成可执行的 Foundry 测试
        - 强调必须证明可利用性
        """

        prompt = f"""你是智能合约安全专家。请为以下漏洞候选生成 Foundry 攻击测试（PoC）。

## 重要规则

1. **仅在漏洞真实可利用时生成 PoC**
   - 如果你分析后认为这不是真实漏洞，返回 "NULL"
   - 如果有保护机制（modifier, require, 余额检查等），返回 "NULL"

2. **PoC 必须证明实际可利用性**
   - 测试必须通过（攻击成功）
   - 必须有明确的攻击收益（余额增加、权限获取等）
   - 使用 Foundry 的 assert* 函数验证

3. **代码格式要求**
   - 使用 Foundry 测试框架
   - 导入必要的库
   - 包含 setUp() 和 testExploit() 函数
   - 使用 console.log 记录关键步骤

## 漏洞候选信息

**类型**: {candidate.vuln_type}
**函数**: {candidate.function_name}
**严重程度**: {candidate.severity}
**描述**: {candidate.description}

**问题代码**:
```solidity
{candidate.code_snippet}
```

## 完整合约代码

```solidity
{contract_code}
```

## 你的任务

1. **分析漏洞**:
   - 这是真实漏洞吗？
   - 是否有保护机制？
   - 攻击路径是什么？
   - 攻击收益是什么？

2. **生成 PoC** (仅在真实可利用时):

返回格式:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {{Test, console}} from "forge-std/Test.sol";
import {{{candidate.contract_name}}} from "../src/{candidate.contract_name}.sol";

contract {candidate.contract_name}ExploitTest is Test {{
    {candidate.contract_name} public target;
    address public attacker = address(0xBEEF);
    address public victim = address(0xDEAD);

    function setUp() public {{
        // 部署目标合约
        target = new {candidate.contract_name}();

        // 设置初始状态
        // ...
    }}

    function testExploit() public {{
        console.log("=== Exploit Test ===");

        // 记录攻击前状态
        uint256 balanceBefore = attacker.balance;
        console.log("Attacker balance before:", balanceBefore);

        // 执行攻击
        vm.startPrank(attacker);
        // ... 攻击代码 ...
        vm.stopPrank();

        // 记录攻击后状态
        uint256 balanceAfter = attacker.balance;
        console.log("Attacker balance after:", balanceAfter);

        // 验证攻击成功
        assertGt(balanceAfter, balanceBefore, "Attack should be profitable");

        console.log("Exploit successful!");
    }}
}}
```

3. **如果不可利用**: 返回 "NULL" 并说明原因

## 示例分析

**场景 1: 真实漏洞**
```solidity
function withdraw(address beneficiary, uint256 amount) public {{
    // ❌ 缺少: require(msg.sender == beneficiary);
    balances[beneficiary] -= amount;
    payable(msg.sender).transfer(amount);
}}
```
→ 生成 PoC（任何人可提取他人余额）

**场景 2: 误报**
```solidity
function withdraw(uint256 amount) public {{
    require(balances[msg.sender] >= amount);  // ✅ 有保护
    balances[msg.sender] -= amount;
    payable(msg.sender).transfer(amount);
}}
```
→ 返回 "NULL"（有余额检查，无法利用）

**场景 3: 设计选择**
```solidity
function pause() public {{
    require(msg.sender == guardian);  // ✅ 有权限检查
    paused = true;
}}
```
→ 返回 "NULL"（这是紧急暂停设计，不是漏洞）

## 开始分析

请分析上述漏洞候选，如果可利用则生成 PoC，否则返回 "NULL"。

**仅返回代码，不要其他解释。**
"""

        return prompt

    def _call_ai(self, prompt: str) -> str:
        """调用 Claude API 生成 PoC"""

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        data = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.3,  # 低温度以获得更确定性的输出
            "max_tokens": 4000
        }

        response = requests.post(
            self.api_url,
            headers=headers,
            json=data,
            timeout=120
        )

        response.raise_for_status()
        result = response.json()

        content = result["choices"][0]["message"]["content"]

        # 提取代码块
        if "```solidity" in content:
            code = content.split("```solidity")[1].split("```")[0].strip()
            return code
        elif "NULL" in content:
            raise ValueError("AI determined vulnerability is not exploitable")
        else:
            return content.strip()

    def _validate_poc(self, code: str) -> bool:
        """
        验证 PoC 代码格式

        检查:
        - 包含必要的导入
        - 有测试合约
        - 有 testExploit 函数
        """
        if not code:
            return False

        required_elements = [
            "pragma solidity",
            "import",
            "Test",
            "function setUp()",
            "function test"
        ]

        return all(elem in code for elem in required_elements)


def main():
    """测试 PoCGenerator"""

    print("=" * 60)
    print("PoCGenerator Test")
    print("=" * 60)

    # 创建一个测试候选
    candidate = VulnerabilityCandidate(
        vuln_type="ACCESS_CONTROL",
        function_name="withdraw",
        contract_name="VulnerableContract",
        description="Missing access control allows anyone to withdraw from any address",
        severity="Critical",
        code_snippet="""
function withdraw(address beneficiary, uint256 amount) public {
    require(balances[beneficiary] >= amount, "Insufficient balance");
    balances[beneficiary] -= amount;
    payable(msg.sender).transfer(amount);
}
"""
    )

    # 读取合约代码
    contract_code = Path("v4_foundry_test/src/VulnerableContract.sol").read_text()

    # 生成 PoC
    generator = PoCGenerator()
    result = generator.generate(candidate, contract_code)

    # 显示结果
    print("\n" + "=" * 60)
    print("GENERATION RESULT")
    print("=" * 60)
    print(f"Success: {result.success}")
    print(f"Contract: {result.contract_name}")

    if result.success:
        print(f"\n✅ PoC Generated:")
        print("-" * 60)
        print(result.poc_code[:500] + "..." if len(result.poc_code) > 500 else result.poc_code)
        print("-" * 60)
    else:
        print(f"\n❌ Generation Failed: {result.reason}")

    print("=" * 60)


if __name__ == "__main__":
    main()
