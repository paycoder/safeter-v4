#!/usr/bin/env python3
"""
Bridge Scanner Loop — 持续桥漏洞挖掘
======================================

完整 pipeline:
1. 抓取目标合约 (Etherscan + GitHub)
2. bridge_patterns 候选识别
3. AI PoC 生成 (V4)
4. Foundry 验证
5. 仅报告已验证漏洞
6. 保存结果 + 循环

用法:
  python bridge_scanner_loop.py                  # 单次扫描
  python bridge_scanner_loop.py --loop 3600      # 每小时循环
  python bridge_scanner_loop.py --github-only     # 仅扫描 GitHub
  python bridge_scanner_loop.py --add-target <chain> <address> <name>
"""

import sys
import json
import time
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Optional
from dataclasses import asdict

# 本地模块
from bridge_patterns import scan_bridge_contract, BridgeVulnCandidate
from contract_fetcher import (
    fetch_all_targets, fetch_from_etherscan, add_etherscan_target,
    FetchedContract, SCAN_RESULTS_DIR, KNOWN_BRIDGE_TARGETS
)

# V4 组件 (可选 — 需要 API key)
POC_AVAILABLE = False
try:
    from poc_generator import PoCGenerator, VulnerabilityCandidate
    from exploit_validator import ExploitValidator
    POC_AVAILABLE = True
except Exception:
    pass


class BridgeScannerLoop:
    """持续桥漏洞扫描器"""

    def __init__(self, enable_poc: bool = True, verbose: bool = True):
        self.verbose = verbose
        self.poc_enabled = enable_poc and POC_AVAILABLE
        self.total_scanned = 0
        self.total_candidates = 0
        self.total_verified = 0
        self.findings_log: List[dict] = []

        if self.poc_enabled:
            try:
                self.poc_gen = PoCGenerator()
                self.validator = ExploitValidator()
                self._log("V4 PoC + Foundry 验证已启用")
            except Exception as e:
                self._log(f"V4 PoC 不可用 ({e})，仅运行模式检测")
                self.poc_enabled = False
        else:
            self._log("仅运行模式检测（无 PoC 验证）")

    def _log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] {msg}")

    # ============================
    # 核心扫描
    # ============================

    def scan_contract(self, contract: FetchedContract) -> List[dict]:
        """扫描单个合约，返回发现列表"""

        # Phase 1: 模式检测
        candidates = scan_bridge_contract(
            contract.source_code,
            contract.name
        )

        if not candidates:
            return []

        self.total_candidates += len(candidates)
        findings = []

        for c in candidates:
            finding = {
                "timestamp": datetime.now().isoformat(),
                "contract_name": contract.name,
                "chain": contract.chain,
                "address": contract.address,
                "source": contract.source,
                "pattern_id": c.pattern_id,
                "vuln_type": c.vuln_type,
                "function": c.function_name,
                "severity": c.severity,
                "description": c.description,
                "reference": c.reference,
                "code_snippet": c.code_snippet[:300],
                "verified": False,
                "poc_available": False,
            }

            # Phase 2+3: PoC 生成 + Foundry 验证 (仅 Critical/High)
            if self.poc_enabled and c.severity in ("Critical", "High"):
                verified = self._verify_with_poc(c, contract)
                finding["verified"] = verified
                finding["poc_available"] = verified
                if verified:
                    self.total_verified += 1

            findings.append(finding)

        return findings

    def _verify_with_poc(self, candidate: BridgeVulnCandidate, contract: FetchedContract) -> bool:
        """使用 V4 pipeline 验证候选"""
        try:
            self._log(f"  [PoC] 生成 {candidate.function_name} 的攻击脚本...")

            vuln_candidate = VulnerabilityCandidate(
                vuln_type=candidate.vuln_type,
                function_name=candidate.function_name,
                contract_name=candidate.contract_name,
                description=candidate.description + "\n\n" + candidate.attack_template,
                severity=candidate.severity,
                code_snippet=candidate.code_snippet,
            )

            poc_result = self.poc_gen.generate(vuln_candidate, contract.source_code)

            if not poc_result.success:
                self._log(f"  [PoC] AI 判断不可利用: {poc_result.reason[:80]}")
                return False

            self._log(f"  [Foundry] 运行验证测试...")
            validation = self.validator.validate(
                poc_code=poc_result.poc_code,
                target_contract_code=contract.source_code,
                target_contract_name=candidate.contract_name,
                poc_test_name=f"{candidate.contract_name}ExploitTest",
            )

            if validation.exploitable:
                self._log(f"  [!!!] 已验证漏洞: {candidate.function_name} — {validation.severity}")
                return True
            else:
                self._log(f"  [x] 误报已过滤: {validation.reason[:80]}")
                return False

        except Exception as e:
            self._log(f"  [err] PoC 验证失败: {e}")
            return False

    # ============================
    # 批量扫描
    # ============================

    def run_scan(
        self,
        include_etherscan: bool = True,
        include_github: bool = True,
    ) -> List[dict]:
        """执行一轮完整扫描"""

        self._log("=" * 60)
        self._log("Bridge Vulnerability Scanner — 开始扫描")
        self._log("=" * 60)

        # 1. 抓取合约
        self._log("\n[Phase 0] 抓取目标合约...")
        contracts = fetch_all_targets(
            include_etherscan=include_etherscan,
            include_github=include_github,
        )

        if not contracts:
            self._log("没有合约可扫描")
            return []

        # 2. 逐个扫描
        self._log(f"\n[Phase 1-3] 扫描 {len(contracts)} 个合约...")
        all_findings = []

        for i, contract in enumerate(contracts, 1):
            self.total_scanned += 1
            if self.verbose:
                self._log(f"\n  [{i}/{len(contracts)}] {contract.name}")

            findings = self.scan_contract(contract)
            if findings:
                all_findings.extend(findings)
                for f in findings:
                    severity_icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡"}.get(f["severity"], "⚪")
                    verified_tag = " [VERIFIED]" if f["verified"] else ""
                    self._log(f"    {severity_icon} {f['severity']} — {f['pattern_id']}: {f['function']}{verified_tag}")

        # 3. 保存结果
        self._save_results(all_findings)

        # 4. 摘要
        self._print_summary(all_findings)

        return all_findings

    def _save_results(self, findings: List[dict]):
        """保存扫描结果"""
        if not findings:
            return

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = SCAN_RESULTS_DIR / f"bridge_scan_{ts}.json"
        output_file.write_text(json.dumps(findings, indent=2, ensure_ascii=False))
        self._log(f"\n结果保存到: {output_file}")

        # 追加到累计日志
        log_file = SCAN_RESULTS_DIR / "bridge_scan_history.jsonl"
        with open(log_file, "a") as f:
            for finding in findings:
                f.write(json.dumps(finding, ensure_ascii=False) + "\n")

    def _print_summary(self, findings: List[dict]):
        """打印扫描摘要"""
        self._log("\n" + "=" * 60)
        self._log("扫描完成")
        self._log("=" * 60)
        self._log(f"  合约扫描: {self.total_scanned}")
        self._log(f"  候选发现: {self.total_candidates}")

        if findings:
            by_severity = {}
            for f in findings:
                by_severity.setdefault(f["severity"], []).append(f)

            for sev in ["Critical", "High", "Medium"]:
                items = by_severity.get(sev, [])
                if items:
                    verified = sum(1 for i in items if i["verified"])
                    self._log(f"  {sev}: {len(items)} 个候选, {verified} 个已验证")

        if self.poc_enabled:
            self._log(f"  已验证漏洞: {self.total_verified}")
        else:
            self._log(f"  (PoC 验证未启用 — 设置 OPENROUTER_API_KEY 启用)")

        self._log("=" * 60)

    # ============================
    # 循环模式
    # ============================

    def run_loop(self, interval_seconds: int = 3600, **scan_kwargs):
        """持续循环扫描"""
        self._log(f"启动持续扫描模式 — 间隔 {interval_seconds}s")

        round_num = 0
        while True:
            round_num += 1
            self._log(f"\n{'#'*60}")
            self._log(f"第 {round_num} 轮扫描")
            self._log(f"{'#'*60}")

            try:
                findings = self.run_scan(**scan_kwargs)

                # 检查是否有 Critical 已验证漏洞
                critical_verified = [
                    f for f in findings
                    if f["severity"] == "Critical" and f["verified"]
                ]
                if critical_verified:
                    self._log(f"\n{'!'*60}")
                    self._log(f"发现 {len(critical_verified)} 个已验证 Critical 漏洞!")
                    self._log(f"{'!'*60}")
                    for cv in critical_verified:
                        self._log(f"  {cv['contract_name']}: {cv['function']} — {cv['description'][:100]}")

            except KeyboardInterrupt:
                self._log("\n用户中断，退出循环")
                break
            except Exception as e:
                self._log(f"扫描出错: {e}")

            self._log(f"\n下一轮扫描: {interval_seconds}s 后")
            try:
                time.sleep(interval_seconds)
            except KeyboardInterrupt:
                self._log("\n用户中断，退出循环")
                break


# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Bridge Vulnerability Scanner Loop")
    parser.add_argument("--loop", type=int, metavar="SECONDS",
                        help="循环模式，指定间隔秒数")
    parser.add_argument("--github-only", action="store_true",
                        help="仅扫描 GitHub 仓库")
    parser.add_argument("--etherscan-only", action="store_true",
                        help="仅扫描 Etherscan 合约")
    parser.add_argument("--no-poc", action="store_true",
                        help="禁用 PoC 生成和验证")
    parser.add_argument("--quiet", action="store_true",
                        help="减少输出")
    parser.add_argument("--add-target", nargs=3, metavar=("CHAIN", "ADDRESS", "NAME"),
                        help="添加新的 Etherscan 目标")

    args = parser.parse_args()

    # 添加目标
    if args.add_target:
        chain, address, name = args.add_target
        add_etherscan_target(name, chain, address)
        print(f"已添加: {name} on {chain} ({address})")

    # 创建扫描器
    scanner = BridgeScannerLoop(
        enable_poc=not args.no_poc,
        verbose=not args.quiet,
    )

    scan_kwargs = {
        "include_etherscan": not args.github_only,
        "include_github": not args.etherscan_only,
    }

    if args.loop:
        scanner.run_loop(interval_seconds=args.loop, **scan_kwargs)
    else:
        findings = scanner.run_scan(**scan_kwargs)
        sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
