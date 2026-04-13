#!/usr/bin/env python3
"""
Bridge Vulnerability Patterns — V4 扩展模块
============================================

基于 2026-04-13 深度代码审计发现的真实桥漏洞模式。
与 scanner_v4_verified.py 集成，为跨链桥合约提供专项扫描。

漏洞来源:
- Hyperbridge superApprove (零访问控制)
- CrossCurve/Axelar expressExecute (绕过网关验证)
- Snowbridge L1Adaptor (前端运行)
- LayerZero OFT setPeer (无时间锁)
- 通用桥模式 (无速率限制铸造)
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path


@dataclass
class BridgeVulnCandidate:
    """桥漏洞候选"""
    pattern_id: str          # 模式 ID
    vuln_type: str           # ACCESS_CONTROL, VALIDATION_BYPASS, FRONTRUN, etc.
    function_name: str
    contract_name: str
    description: str
    severity: str            # Critical, High, Medium
    code_snippet: str
    attack_template: str     # Foundry PoC 模板提示
    reference: str           # 参考案例


# ============================================================
# Pattern 1: 无访问控制的 approve/mint/burn 函数
# 来源: Hyperbridge superApprove
# ============================================================

def detect_unprotected_token_ops(code: str, contract_name: str) -> List[BridgeVulnCandidate]:
    """
    检测无访问控制的代币敏感操作。

    superApprove 模式: public 函数直接调用 _approve/_mint/_burn
    且没有 onlyOwner/onlyRole/require(msg.sender) 等保护。
    """
    candidates = []

    # 危险的内部函数调用
    dangerous_internals = [
        ("_approve", "UNPROTECTED_APPROVE", "Critical",
         "Hyperbridge superApprove — 任何人可设置任意用户的 allowance"),
        ("_mint", "UNPROTECTED_MINT", "Critical",
         "无权限铸造 — 任何人可铸造无限代币"),
        ("_burn", "UNPROTECTED_BURN", "High",
         "无权限销毁 — 任何人可销毁他人代币"),
        ("_transfer", "UNPROTECTED_TRANSFER", "Critical",
         "无权限转账 — 任何人可转移他人代币"),
    ]

    access_control_keywords = [
        "onlyOwner", "onlyRole", "onlyAdmin", "onlyGateway",
        "onlyMinter", "onlyBurner", "onlyOperator", "onlyHost",
        "require(msg.sender", "require(_msgSender()",
        "if(msg.sender", "if (msg.sender",
        "modifier", "restrict",
    ]

    # 标准 ERC20 函数 — 这些函数调用 _approve/_transfer 是正常的，不是漏洞
    # approve(spender, amount) 只影响 msg.sender 的 allowance
    # transfer(to, amount) 只转 msg.sender 的余额
    # transferFrom(from, to, amount) 需要 allowance 检查
    # permit() 使用 EIP-2612 签名，有密码学保护
    standard_erc20_functions = {
        "approve", "transfer", "transferFrom",
        "increaseAllowance", "decreaseAllowance",
        "permit", "_approve", "_transfer", "_mint", "_burn",
        "_spendAllowance", "_beforeTokenTransfer", "_afterTokenTransfer",
    }

    for internal_fn, vuln_id, severity, desc in dangerous_internals:
        # 查找调用了危险内部函数的 public/external 函数
        pattern = rf'function\s+(\w+)\s*\([^)]*\)\s*(public|external)[^{{]*\{{[^}}]*{re.escape(internal_fn)}\s*\('
        matches = re.finditer(pattern, code, re.DOTALL)

        for match in matches:
            func_name = match.group(1)
            func_text = match.group(0)

            # 跳过标准 ERC20 函数 — 它们调用 _approve/_transfer 是正常设计
            if func_name in standard_erc20_functions:
                continue

            # 跳过 view/pure 函数
            if "view" in func_text or "pure" in func_text:
                continue

            # 检查是否有访问控制
            has_protection = any(kw in func_text for kw in access_control_keywords)

            if not has_protection:
                # 获取更完整的函数体
                start = match.start()
                brace_count = 0
                end = start
                for i in range(start, min(start + 2000, len(code))):
                    if code[i] == '{':
                        brace_count += 1
                    elif code[i] == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            end = i + 1
                            break
                full_func = code[start:end]

                # 再次检查完整函数体
                has_protection = any(kw in full_func for kw in access_control_keywords)

                if not has_protection:
                    candidates.append(BridgeVulnCandidate(
                        pattern_id=vuln_id,
                        vuln_type="ACCESS_CONTROL",
                        function_name=func_name,
                        contract_name=contract_name,
                        description=desc,
                        severity=severity,
                        code_snippet=full_func[:500],
                        attack_template=f"""
攻击模板: 调用 {func_name} 直接操作他人代币
1. 部署目标合约
2. 给 victim 分配代币
3. attacker 直接调用 {func_name}({internal_fn}路径)
4. 验证 attacker 获得 victim 的代币
""",
                        reference="Hyperbridge HyperFungibleTokenImpl.superApprove (2025-12)"
                    ))

    return candidates


# ============================================================
# Pattern 2: Axelar expressExecute 绕过网关验证
# 来源: CrossCurve $3M 攻击 (2026-02)
# ============================================================

def detect_axelar_express_bypass(code: str, contract_name: str) -> List[BridgeVulnCandidate]:
    """
    检测 Axelar expressExecute 网关验证绕过。

    漏洞模式: 继承 AxelarExpressExecutable 的合约
    如果 _execute 中释放资金/修改关键状态，
    攻击者可通过 expressExecute 绕过网关验证直接触发。
    """
    candidates = []

    # 检测是否继承 AxelarExpressExecutable
    if "AxelarExpressExecutable" not in code:
        return candidates

    # 查找 _execute 实现
    execute_pattern = r'function\s+_execute\s*\([^)]*\)\s*internal\s+override[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
    execute_match = re.search(execute_pattern, code, re.DOTALL)

    if not execute_match:
        return candidates

    execute_body = execute_match.group(1)

    # 检查 _execute 中是否有危险操作
    dangerous_ops = [
        ("transfer", "资金转移"),
        ("safeTransfer", "安全资金转移"),
        ("mint", "代币铸造"),
        ("unlock", "资产解锁"),
        (".call{", "外部调用"),
        ("receiveData", "接收跨链数据"),
        ("receiveHash", "接收跨链哈希"),
    ]

    found_dangerous = []
    for op, desc in dangerous_ops:
        if op in execute_body:
            found_dangerous.append(desc)

    if not found_dangerous:
        return candidates

    # 检查 _execute 中是否有源链验证
    has_source_validation = any(kw in execute_body for kw in [
        "validateContractCall",
        "require(sourceChain",
        "require(Strings.equal(sourceChain",
        "gateway.validateContractCall",
    ])

    # 即使有 peer 检查，也可能不够（CrossCurve 有 peer 检查但仍被攻击）
    has_peer_check = "peers[sourceChain]" in execute_body or "peers[" in execute_body

    if not has_source_validation:
        severity = "Critical"
        extra_note = ""
        if has_peer_check:
            severity = "High"
            extra_note = " (有 peer 映射检查但 peer 值可公开查询)"

        candidates.append(BridgeVulnCandidate(
            pattern_id="AXELAR_EXPRESS_BYPASS",
            vuln_type="VALIDATION_BYPASS",
            function_name="_execute (via expressExecute)",
            contract_name=contract_name,
            description=f"Axelar expressExecute 绕过网关验证 — _execute 中包含: {', '.join(found_dangerous)}{extra_note}",
            severity=severity,
            code_snippet=execute_body[:500],
            attack_template=f"""
攻击模板 (参考 CrossCurve $3M 攻击):
1. 生成新的 commandId
2. 伪造 sourceChain 和 sourceAddress (如果有 peer 检查，查询链上 peers 映射值)
3. 构造恶意 payload 指向攻击者地址
4. 直接调用 expressExecute(commandId, sourceChain, sourceAddress, payload)
5. _execute 被触发，执行 {', '.join(found_dangerous)}
6. 验证攻击者获得资产
""",
            reference="CrossCurve ReceiverAxelar exploit (2026-02, $3M)"
        ))

    return candidates


# ============================================================
# Pattern 3: 预充值前端运行
# 来源: Snowbridge SnowbridgeL1Adaptor
# ============================================================

def detect_prefunding_frontrun(code: str, contract_name: str) -> List[BridgeVulnCandidate]:
    """
    检测"先转入代币再调用"的前端运行漏洞。

    模式: 合约设计为先接收代币，然后通过单独调用处理。
    如果处理函数的 recipient 由调用者指定，攻击者可抢先调用。
    """
    candidates = []

    # 检测注释中提到 "pre-funding" 或 "pre-fund"
    has_prefund_pattern = any(kw in code.lower() for kw in [
        "pre-funding", "prefund", "pre_fund",
        "requires pre-funding", "must be funded",
        "transfer tokens to this contract first",
    ])

    if not has_prefund_pattern:
        return candidates

    # 查找接受 recipient 参数的 public 函数
    pattern = r'function\s+(\w+)\s*\([^)]*(?:recipient|to|receiver)\s*[^)]*\)\s*(public|external)'
    matches = re.finditer(pattern, code, re.IGNORECASE)

    for match in matches:
        func_name = match.group(1)

        # 获取函数体
        start = match.start()
        brace_count = 0
        end = start
        for i in range(start, min(start + 3000, len(code))):
            if code[i] == '{':
                brace_count += 1
            elif code[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end = i + 1
                    break
        full_func = code[start:end]

        # 检查是否使用合约自身的代币余额（而非 msg.sender 的）
        uses_contract_balance = any(kw in full_func for kw in [
            "balanceOf(address(this))",
            "address(this).balance",
            "forceApprove",
        ])

        if uses_contract_balance:
            candidates.append(BridgeVulnCandidate(
                pattern_id="PREFUND_FRONTRUN",
                vuln_type="FRONTRUN",
                function_name=func_name,
                contract_name=contract_name,
                description="预充值前端运行 — recipient 由调用者指定，可抢先使用他人预充值的资金",
                severity="High",
                code_snippet=full_func[:500],
                attack_template=f"""
攻击模板:
1. 监控 mempool 中向合约的代币转账
2. 抢先调用 {func_name}(攻击者地址作为recipient, ...)
3. 使用他人预充值的代币
4. 验证攻击者获得代币
""",
                reference="Snowbridge SnowbridgeL1Adaptor depositToken"
            ))

    return candidates


# ============================================================
# Pattern 4: 无速率限制的铸造
# 来源: 所有桥的通用问题
# ============================================================

def detect_unlimited_mint(code: str, contract_name: str) -> List[BridgeVulnCandidate]:
    """
    检测无速率限制的铸造函数。

    这不是直接可利用的漏洞，而是一旦访问控制被突破
    就没有第二道防线的设计缺陷。标记为 Medium。
    """
    candidates = []

    # 查找 mint 函数
    mint_pattern = r'function\s+(mint\w*)\s*\([^)]*\)\s*(public|external|internal)[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
    matches = re.finditer(mint_pattern, code, re.DOTALL)

    for match in matches:
        func_name = match.group(1)
        visibility = match.group(2)
        func_body = match.group(3)

        # 只检查有访问控制的 mint（无访问控制的已被 Pattern 1 捕获）
        has_access_control = any(kw in match.group(0) for kw in [
            "onlyOwner", "onlyRole", "onlyGateway", "onlyMinter",
        ])

        if not has_access_control:
            continue

        # 检查是否有速率限制
        has_rate_limit = any(kw in func_body for kw in [
            "rateLimit", "RateLimit", "maxMint", "MAX_MINT",
            "dailyLimit", "mintCap", "supplyCap",
            "totalSupply() +", "MAX_SUPPLY",
        ])

        if not has_rate_limit:
            candidates.append(BridgeVulnCandidate(
                pattern_id="UNLIMITED_MINT",
                vuln_type="MISSING_RATE_LIMIT",
                function_name=func_name,
                contract_name=contract_name,
                description="铸造无速率限制 — 访问控制被突破后可无限铸造",
                severity="Medium",
                code_snippet=match.group(0)[:500],
                attack_template="纵深防御缺失 — 建议添加 totalSupply 上限检查和时间窗口速率限制",
                reference="Wormhole, Snowbridge, Gravity Bridge, LayerZero OFT — 均无速率限制"
            ))

    return candidates


# ============================================================
# Pattern 5: 无访问控制的 dispatch/execute
# 来源: Hyperbridge CallDispatcher
# ============================================================

def detect_unprotected_dispatch(code: str, contract_name: str) -> List[BridgeVulnCandidate]:
    """
    检测无访问控制的通用执行/调度函数。

    模式: public/external 函数接受任意 calldata 并执行 .call()
    """
    candidates = []

    # 查找包含 .call 的 public/external 函数
    pattern = r'function\s+(\w+)\s*\([^)]*\)\s*(public|external)[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
    matches = re.finditer(pattern, code, re.DOTALL)

    # 标准 DeFi 函数名 — 这些函数内的 .call 通常是正常操作
    normal_call_functions = {
        "teleport", "fillOrder", "placeOrder", "swap", "deposit", "withdraw",
        "swapETHForExactTokens", "swapExactETHForTokens", "swapExactTokensForETH",
        "onGetResponse", "onPostResponse", "onAccept",
        "add", "remove", "claim",
    }

    for match in matches:
        func_name = match.group(1)
        func_body = match.group(3)

        # 跳过标准 DeFi 函数
        if func_name in normal_call_functions:
            continue

        # 跳过 view/pure
        if "view" in match.group(0) or "pure" in match.group(0):
            continue

        # 检查是否包含任意调用
        has_arbitrary_call = ".call{" in func_body or ".call(" in func_body

        if not has_arbitrary_call:
            continue

        # 检查访问控制
        has_access = any(kw in match.group(0) for kw in [
            "onlyOwner", "onlyRole", "onlySelf", "onlyGateway",
            "require(msg.sender",
        ])

        if not has_access:
            candidates.append(BridgeVulnCandidate(
                pattern_id="UNPROTECTED_DISPATCH",
                vuln_type="ARBITRARY_CALL",
                function_name=func_name,
                contract_name=contract_name,
                description="无权限的任意调用执行 — 如果合约持有资产或权限可被利用",
                severity="High",
                code_snippet=match.group(0)[:500],
                attack_template=f"""
攻击模板:
1. 检查合约是否持有 ETH 或 ERC20 余额
2. 如果有余额，构造 Call[] 转走资产
3. 检查合约是否对其他协议有 approve 授权
4. 如果有授权，构造调用消耗授权
""",
                reference="Hyperbridge CallDispatcher.dispatch (所有主网)"
            ))

    return candidates


# ============================================================
# 主扫描函数
# ============================================================

def scan_bridge_contract(code: str, contract_name: str = "Unknown") -> List[BridgeVulnCandidate]:
    """
    对桥合约执行完整的漏洞模式扫描。

    Returns:
        所有检测到的桥漏洞候选列表
    """
    all_candidates = []

    all_candidates.extend(detect_unprotected_token_ops(code, contract_name))
    all_candidates.extend(detect_axelar_express_bypass(code, contract_name))
    all_candidates.extend(detect_prefunding_frontrun(code, contract_name))
    all_candidates.extend(detect_unlimited_mint(code, contract_name))
    all_candidates.extend(detect_unprotected_dispatch(code, contract_name))

    return all_candidates


def scan_file(filepath: str) -> List[BridgeVulnCandidate]:
    """扫描单个 .sol 文件"""
    path = Path(filepath)
    code = path.read_text()
    return scan_bridge_contract(code, path.stem)


def scan_directory(dirpath: str) -> List[BridgeVulnCandidate]:
    """扫描目录下所有 .sol 文件"""
    all_candidates = []
    for sol_file in Path(dirpath).rglob("*.sol"):
        candidates = scan_file(str(sol_file))
        if candidates:
            all_candidates.extend(candidates)
    return all_candidates


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python bridge_patterns.py <file_or_directory>")
        print("\nScans Solidity files for bridge-specific vulnerability patterns.")
        print("\nPatterns detected:")
        print("  1. Unprotected token ops (superApprove pattern)")
        print("  2. Axelar expressExecute bypass")
        print("  3. Pre-funding frontrun")
        print("  4. Unlimited mint (no rate limit)")
        print("  5. Unprotected dispatch/execute")
        sys.exit(1)

    target = Path(sys.argv[1])

    if target.is_file():
        candidates = scan_file(str(target))
    elif target.is_dir():
        candidates = scan_directory(str(target))
    else:
        print(f"Error: {target} not found")
        sys.exit(1)

    # 输出结果
    if not candidates:
        print("No bridge vulnerability patterns detected.")
        sys.exit(0)

    print(f"\n{'='*70}")
    print(f"Found {len(candidates)} bridge vulnerability candidates")
    print(f"{'='*70}")

    for i, c in enumerate(candidates, 1):
        print(f"\n[{i}] {c.severity} — {c.pattern_id}")
        print(f"    Function: {c.function_name}")
        print(f"    Contract: {c.contract_name}")
        print(f"    Description: {c.description}")
        print(f"    Reference: {c.reference}")
        print(f"    Code: {c.code_snippet[:200]}...")

    sys.exit(1)  # 非零退出表示发现问题
