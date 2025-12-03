#!/usr/bin/env python3
"""
V4 Scanner: 可验证漏洞扫描器
=========================

灵感来源: Anthropic SCONE-bench
核心原则: "If you can't exploit it, it's not a vulnerability."

架构:
1. V3 候选识别（快速静态分析）
2. PoC 生成（AI 生成攻击脚本）
3. Foundry 验证（实际执行测试）
4. 仅报告已验证的漏洞

与 V3 的关键区别:
- V3: 报告"可疑模式" → 100% 误报率
- V4: 报告"可验证漏洞" → <10% 误报率（预期）
"""

import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import json
from datetime import datetime

# 导入 V3 组件（候选识别）
sys.path.append(str(Path(__file__).parent))
from scanner_v3_contextual import ContextualScanner, ContractContext

# 导入 V4 组件
from poc_generator import PoCGenerator, VulnerabilityCandidate
from exploit_validator import ExploitValidator, ValidationResult

from dotenv import load_dotenv
load_dotenv()


@dataclass
class V4Finding:
    """V4 验证的发现（仅真实可利用的漏洞）"""
    contract: str
    function: str
    vulnerability_type: str
    severity: str  # 基于实际可利用性评估
    description: str
    poc_code: str  # ✅ 可执行的 PoC
    validation_proof: str  # ✅ Foundry 测试输出
    gas_cost: Optional[int]
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class V4Report:
    """V4 扫描报告"""
    project_name: str
    scan_time: str
    total_contracts: int
    candidates_found: int  # V3 识别的候选数
    pocs_generated: int  # AI 生成的 PoC 数
    verified_vulnerabilities: int  # 实际可利用的漏洞数
    findings: List[V4Finding]
    false_positives_filtered: int  # 过滤的误报数
    cost: float


class V4Scanner:
    """
    V4 可验证漏洞扫描器

    完整流程:
    合约代码 → V3候选 → PoC生成 → Foundry验证 → 真实漏洞报告
    """

    def __init__(self):
        """初始化 V4 Scanner"""
        print("=" * 70)
        print("V4 Scanner: Verified Vulnerability Detection")
        print("Inspired by Anthropic SCONE-bench")
        print("=" * 70)

        # 暂时不使用 V3 的完整扫描器，使用简化的候选识别
        # self.v3_scanner = ContextualScanner()
        self.poc_generator = PoCGenerator()
        self.validator = ExploitValidator()

        print("✅ Pattern Detection initialized (candidate identification)")
        print("✅ PoC Generator initialized (AI-powered)")
        print("✅ Exploit Validator initialized (Foundry-based)")

    def scan_contract(self, contract_path: Path) -> V4Report:
        """
        扫描单个合约

        Args:
            contract_path: 合约文件路径

        Returns:
            V4Report: 包含仅已验证漏洞的报告
        """
        print(f"\n{'='*70}")
        print(f"Scanning: {contract_path.name}")
        print(f"{'='*70}")

        start_time = datetime.now()
        total_cost = 0.0

        # 阶段 1: V3 候选识别
        print(f"\n📊 Phase 1: Candidate Identification (V3)")
        print(f"   Analyzing contract for suspicious patterns...")

        v3_candidates = self._v3_identify_candidates(contract_path)
        print(f"   Found {len(v3_candidates)} candidates")

        if len(v3_candidates) == 0:
            print(f"   ✅ No suspicious patterns detected - contract appears safe")
            return V4Report(
                project_name=contract_path.stem,
                scan_time=(datetime.now() - start_time).total_seconds(),
                total_contracts=1,
                candidates_found=0,
                pocs_generated=0,
                verified_vulnerabilities=0,
                findings=[],
                false_positives_filtered=0,
                cost=total_cost
            )

        # 阶段 2: PoC 生成
        print(f"\n🔨 Phase 2: PoC Generation (AI)")
        print(f"   Generating exploit scripts...")

        contract_code = contract_path.read_text()
        pocs = []

        for i, candidate in enumerate(v3_candidates, 1):
            print(f"\n   Candidate {i}/{len(v3_candidates)}: {candidate.function_name}")
            poc_result = self.poc_generator.generate(candidate, contract_code)
            total_cost += 0.10  # 估算 PoC 生成成本

            if poc_result.success:
                pocs.append((candidate, poc_result))
                print(f"      ✅ PoC generated")
            else:
                print(f"      ❌ AI determined not exploitable: {poc_result.reason}")

        print(f"\n   Generated {len(pocs)}/{len(v3_candidates)} PoCs")

        # 阶段 3: Foundry 验证
        print(f"\n🧪 Phase 3: Foundry Validation")
        print(f"   Executing PoCs to verify exploitability...")

        verified_findings = []

        for i, (candidate, poc_result) in enumerate(pocs, 1):
            print(f"\n   Testing {i}/{len(pocs)}: {candidate.function_name}")

            validation = self.validator.validate(
                poc_code=poc_result.poc_code,
                target_contract_code=contract_code,
                target_contract_name=candidate.contract_name,
                poc_test_name=poc_result.contract_name
            )

            if validation.exploitable:
                print(f"      ✅ VULNERABILITY CONFIRMED!")
                print(f"         Severity: {validation.severity}")
                print(f"         Gas Cost: {validation.gas_used}")

                finding = V4Finding(
                    contract=candidate.contract_name,
                    function=candidate.function_name,
                    vulnerability_type=candidate.vuln_type,
                    severity=validation.severity,
                    description=candidate.description,
                    poc_code=poc_result.poc_code,
                    validation_proof=validation.stdout,
                    gas_cost=validation.gas_used
                )
                verified_findings.append(finding)
            else:
                print(f"      ❌ Not exploitable (false positive filtered)")
                print(f"         Reason: {validation.reason[:100]}")

        # 生成报告
        scan_time = (datetime.now() - start_time).total_seconds()
        false_positives = len(v3_candidates) - len(verified_findings)

        report = V4Report(
            project_name=contract_path.stem,
            scan_time=f"{scan_time:.2f}s",
            total_contracts=1,
            candidates_found=len(v3_candidates),
            pocs_generated=len(pocs),
            verified_vulnerabilities=len(verified_findings),
            findings=verified_findings,
            false_positives_filtered=false_positives,
            cost=total_cost
        )

        # 显示结果
        self._display_report(report)

        return report

    def _v3_identify_candidates(self, contract_path: Path) -> List[VulnerabilityCandidate]:
        """
        使用 V3 识别候选

        这里简化为基于代码模式的识别
        实际生产中应该使用完整的 V3 scanner
        """
        # 读取合约
        code = contract_path.read_text()

        candidates = []

        # 简单的模式检测（生产中应使用 V3 的完整逻辑）
        import re

        # 检测 tx.origin 使用
        if "tx.origin" in code:
            # 提取函数
            func_match = re.search(r'function\s+(\w+).*?tx\.origin', code, re.DOTALL)
            if func_match:
                candidates.append(VulnerabilityCandidate(
                    vuln_type="ACCESS_CONTROL",
                    function_name=func_match.group(1),
                    contract_name=contract_path.stem,
                    description="Uses tx.origin for authentication",
                    severity="High",
                    code_snippet=func_match.group(0)[:200]
                ))

        # 检测缺少访问控制的敏感函数
        sensitive_keywords = ["withdraw", "transfer", "mint", "burn", "pause", "unpause"]
        found_sensitive = set()  # 避免重复

        for keyword in sensitive_keywords:
            pattern = rf'function\s+({keyword}\w*)\s*\([^)]*\)\s*(public|external)'
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                func_name = match.group(1)

                # 避免重复检测同一函数
                if func_name in found_sensitive:
                    continue
                found_sensitive.add(func_name)

                # 获取完整函数体（到下一个函数或合约结束）
                func_start = match.start()
                func_end = code.find("function ", func_start + 10)
                if func_end == -1:
                    # 尝试找到闭合的大括号
                    brace_count = 0
                    for i in range(func_start, len(code)):
                        if code[i] == '{':
                            brace_count += 1
                        elif code[i] == '}':
                            brace_count -= 1
                            if brace_count == 0:
                                func_end = i + 1
                                break

                func_code = code[func_start:func_end if func_end != -1 else min(func_start+1000, len(code))]

                # 检查是否有 modifier 或 msg.sender 检查
                # 注意：require(balances[...]) 不算访问控制
                # 移除注释以避免误判
                func_code_no_comments = re.sub(r'//.*', '', func_code)
                func_code_no_comments = re.sub(r'/\*.*?\*/', '', func_code_no_comments, flags=re.DOTALL)

                has_access_control = (
                    "onlyOwner" in func_code_no_comments or
                    "require(msg.sender ==" in func_code_no_comments or
                    "require(msg.sender!=" in func_code_no_comments or
                    "if(msg.sender ==" in func_code_no_comments or
                    "if (msg.sender ==" in func_code_no_comments
                )

                if not has_access_control:
                    candidates.append(VulnerabilityCandidate(
                        vuln_type="ACCESS_CONTROL",
                        function_name=func_name,
                        contract_name=contract_path.stem,
                        description=f"Potential missing access control in sensitive function",
                        severity="High",
                        code_snippet=func_code[:300]
                    ))

        return candidates

    def _display_report(self, report: V4Report):
        """显示扫描报告"""
        print(f"\n{'='*70}")
        print(f"SCAN REPORT")
        print(f"{'='*70}")

        print(f"\n📊 Statistics:")
        print(f"   Scan Time: {report.scan_time}")
        print(f"   V3 Candidates: {report.candidates_found}")
        print(f"   PoCs Generated: {report.pocs_generated}")
        print(f"   ✅ Verified Vulnerabilities: {report.verified_vulnerabilities}")
        print(f"   ❌ False Positives Filtered: {report.false_positives_filtered}")
        print(f"   Cost: ${report.cost:.2f}")

        if report.verified_vulnerabilities > 0:
            print(f"\n🚨 VERIFIED VULNERABILITIES:")
            for i, finding in enumerate(report.findings, 1):
                print(f"\n   [{i}] {finding.severity.upper()} - {finding.function}")
                print(f"       Type: {finding.vulnerability_type}")
                print(f"       Description: {finding.description}")
                print(f"       Gas Cost: {finding.gas_cost}")
                print(f"       ✅ PoC Available: Yes")
                print(f"       ✅ Foundry Test: Passed")
        else:
            print(f"\n✅ No verified vulnerabilities found")
            if report.candidates_found > 0:
                print(f"   (All {report.candidates_found} candidates were false positives)")

        print(f"\n{'='*70}")

        # 误报率统计
        if report.candidates_found > 0:
            fp_rate = (report.false_positives_filtered / report.candidates_found) * 100
            print(f"\n📈 False Positive Rate: {fp_rate:.1f}%")
            print(f"   V3 would have reported {report.candidates_found} findings")
            print(f"   V4 verified only {report.verified_vulnerabilities} real vulnerabilities")
            print(f"   Improvement: {report.false_positives_filtered} false positives filtered")

        print(f"{'='*70}")


def main():
    """测试 V4 Scanner"""

    if len(sys.argv) < 2:
        print("Usage: python scanner_v4_verified.py <contract_path>")
        print("\nExample:")
        print("  python scanner_v4_verified.py v4_foundry_test/src/VulnerableContract.sol")
        sys.exit(1)

    contract_path = Path(sys.argv[1])
    if not contract_path.exists():
        print(f"Error: Contract not found: {contract_path}")
        sys.exit(1)

    # 创建扫描器
    scanner = V4Scanner()

    # 扫描
    report = scanner.scan_contract(contract_path)

    # 保存报告
    output_path = Path("reports/v4") / f"{report.project_name}_verified_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    report_dict = {
        "project": report.project_name,
        "scan_time": report.scan_time,
        "candidates": report.candidates_found,
        "pocs_generated": report.pocs_generated,
        "verified_vulnerabilities": report.verified_vulnerabilities,
        "false_positives_filtered": report.false_positives_filtered,
        "cost": report.cost,
        "findings": [
            {
                "contract": f.contract,
                "function": f.function,
                "type": f.vulnerability_type,
                "severity": f.severity,
                "description": f.description,
                "gas_cost": f.gas_cost,
                "has_poc": True,
                "validated": True
            }
            for f in report.findings
        ]
    }

    output_path.write_text(json.dumps(report_dict, indent=2))
    print(f"\n💾 Report saved to: {output_path}")

    # 退出码
    sys.exit(0 if report.verified_vulnerabilities == 0 else 1)


if __name__ == "__main__":
    main()
