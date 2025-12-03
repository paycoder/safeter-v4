# V4 架构：SCONE-bench 启发的可验证漏洞扫描器

**设计日期**: 2025-12-02
**灵感来源**: Anthropic SCONE-bench Framework
**核心原则**: **不能证明可利用的发现，不是漏洞**

---

## 🎯 核心理念转变

### V3 的根本问题
```
静态分析 → 模式匹配 → 报告 → 100% 误报
```

### V4 的解决方案
```
静态分析 → 生成 PoC → Foundry 测试 → 仅报告可执行的漏洞
```

**关键差异**: V4 要求 **实际证明可利用性**

---

## 📐 系统架构

### 阶段 1: 候选识别（保留 V3）
```python
class CandidateScanner:
    """使用 V3 快速识别可疑代码模式"""

    def scan(self, contract: str) -> List[Candidate]:
        # 保留 V3 的所有检测器
        # 但不直接报告，而是生成"候选"
        candidates = []

        # 权限问题
        if self.detect_access_control_issue(contract):
            candidates.append(Candidate(
                type="ACCESS_CONTROL",
                function="withdraw",
                pattern="missing onlyOwner"
            ))

        # 重入风险
        if self.detect_reentrancy(contract):
            candidates.append(Candidate(
                type="REENTRANCY",
                function="flashLoan",
                pattern="external call before state update"
            ))

        return candidates  # 可能有高误报，没关系
```

### 阶段 2: PoC 生成（新增）
```python
class PoCGenerator:
    """为每个候选生成 Foundry 测试攻击脚本"""

    def generate_exploit(self, candidate: Candidate, contract: ContractContext) -> str:
        """
        使用 Claude 生成 Foundry 测试

        Prompt 模板:
        ---
        你是智能合约安全研究员。请为以下可疑模式开发攻击脚本。

        合约代码:
        {contract.code}

        可疑模式:
        类型: {candidate.type}
        函数: {candidate.function}
        问题: {candidate.pattern}

        请编写 Foundry 测试脚本（Test.t.sol），证明此漏洞可被利用。

        要求:
        1. 使用 forge-std/Test.sol
        2. 设置初始状态（用户余额、合约状态）
        3. 执行攻击
        4. 断言攻击成功（余额增加、权限获取等）
        5. 如果攻击不可行，返回 NULL

        示例格式:
        ```solidity
        contract ExploitTest is Test {
            TargetContract target;
            address attacker = address(0xBEEF);

            function setUp() public {
                target = new TargetContract();
                vm.deal(attacker, 1 ether);
            }

            function testExploit() public {
                vm.startPrank(attacker);

                // 执行攻击
                target.withdraw(attacker, 1000 ether);

                // 验证成功
                assertGt(attacker.balance, 1 ether);
            }
        }
        ```
        ---
        """

        prompt = self._build_prompt(candidate, contract)
        poc_code = self.ai.generate(prompt)

        return poc_code
```

### 阶段 3: 验证执行（核心）
```python
class ExploitValidator:
    """在 Foundry 中执行 PoC，验证可利用性"""

    def __init__(self):
        self.foundry_installed = self._check_foundry()

    def validate(self, poc: str, contract: ContractContext) -> ValidationResult:
        """
        执行 PoC 并返回结果

        流程:
        1. 创建临时 Foundry 项目
        2. 部署目标合约
        3. 运行 PoC 测试
        4. 检查是否通过
        """

        # 1. 创建测试项目
        test_dir = self._create_foundry_project()

        # 2. 写入合约和测试
        self._write_contract(test_dir, contract.code)
        self._write_test(test_dir, poc)

        # 3. 执行测试
        result = subprocess.run(
            ["forge", "test", "-vvv"],
            cwd=test_dir,
            capture_output=True,
            timeout=60
        )

        # 4. 分析结果
        if result.returncode == 0:
            # 测试通过 = 攻击成功 = 真实漏洞
            return ValidationResult(
                exploitable=True,
                proof=result.stdout.decode(),
                severity=self._assess_impact(poc, result.stdout)
            )
        else:
            # 测试失败 = 攻击不可行 = 误报
            return ValidationResult(
                exploitable=False,
                reason=result.stderr.decode()
            )

    def _create_foundry_project(self) -> Path:
        """创建临时 Foundry 项目"""
        temp_dir = Path(f"/tmp/safeter_test_{uuid.uuid4()}")
        subprocess.run(["forge", "init", str(temp_dir)], check=True)
        return temp_dir
```

### 阶段 4: 报告生成（仅真实漏洞）
```python
class V4Reporter:
    """仅报告已验证的漏洞"""

    def generate_report(self, validated: List[ValidationResult]) -> Report:
        # 过滤：仅包含 exploitable=True 的发现
        real_vulns = [v for v in validated if v.exploitable]

        if len(real_vulns) == 0:
            return Report(
                status="SAFE",
                message="未发现可验证的漏洞"
            )

        return Report(
            status="VULNERABLE",
            findings=[
                Finding(
                    severity=v.severity,
                    description=v.description,
                    proof_of_concept=v.proof,  # ✅ 包含实际 PoC
                    foundry_test=v.test_code   # ✅ 可复现的测试
                )
                for v in real_vulns
            ]
        )
```

---

## 🔧 完整 V4 工作流

```python
class V4Scanner:
    """完整的可验证漏洞扫描器"""

    def __init__(self):
        self.candidate_scanner = CandidateScanner()  # V3 逻辑
        self.poc_generator = PoCGenerator()
        self.validator = ExploitValidator()
        self.reporter = V4Reporter()

    def scan(self, contract_path: Path) -> Report:
        """
        完整扫描流程
        """

        # 1. 加载合约
        contract = self._load_contract(contract_path)

        # 2. 阶段 1: 候选识别（V3）
        print(f"📊 阶段 1: 扫描 {contract.name}...")
        candidates = self.candidate_scanner.scan(contract)
        print(f"   发现 {len(candidates)} 个候选模式")

        # 3. 阶段 2: PoC 生成
        print(f"🔨 阶段 2: 生成攻击脚本...")
        pocs = []
        for candidate in candidates:
            poc = self.poc_generator.generate_exploit(candidate, contract)
            if poc:  # AI 认为可以攻击
                pocs.append((candidate, poc))
        print(f"   生成 {len(pocs)} 个 PoC")

        # 4. 阶段 3: 验证执行
        print(f"🧪 阶段 3: Foundry 验证...")
        validated = []
        for candidate, poc in pocs:
            result = self.validator.validate(poc, contract)
            if result.exploitable:
                print(f"   ✅ {candidate.type} - 可利用！")
                validated.append(result)
            else:
                print(f"   ❌ {candidate.type} - 误报（{result.reason[:50]}...）")

        # 5. 阶段 4: 报告
        print(f"📝 阶段 4: 生成报告...")
        report = self.reporter.generate_report(validated)

        return report
```

**示例输出**:
```
📊 阶段 1: 扫描 LendingPool.sol...
   发现 3 个候选模式

🔨 阶段 2: 生成攻击脚本...
   生成 2 个 PoC (1个候选被AI判断为不可攻击)

🧪 阶段 3: Foundry 验证...
   ✅ ACCESS_CONTROL - 可利用！
   ❌ REENTRANCY - 误报（balance check prevents attack）

📝 阶段 4: 生成报告...
   发现 1 个真实漏洞
```

---

## 📊 预期改进

### V3 vs V4 对比

| 指标 | V3 | V4 (预期) |
|------|----|----|
| **误报率** | 100% | **<10%** |
| **验证方法** | 人工代码审查 | 自动 Foundry 测试 |
| **PoC** | 需要人工开发 | 自动生成 |
| **可信度** | 低（仅模式） | **高（实际执行）** |
| **成本/合约** | $0.020 | $0.50-$1.00 (含 PoC 生成) |
| **扫描速度** | 快 | 慢（需要测试） |

### 为什么 V4 会成功？

#### 1. 实际执行验证
```python
# V3: 猜测
if "tx.origin" in code:
    report("可能有权限问题")  # 误报

# V4: 证明
poc = "target.withdraw(attacker, 1000 ether)"
result = forge.test(poc)
if result.success and attacker.balance > initial:
    report("确认权限漏洞")  # 真实
```

#### 2. 经济可行性自动验证
```python
# V3: 手动计算
# 需要人工分析是否有利可图

# V4: 自动测试
def testProfitability():
    initial = attacker.balance
    attack()
    final = attacker.balance
    assert final > initial + gas_cost  # ✅ 自动验证
```

#### 3. 状态一致性自动检查
```python
# V3: 猜测重入问题
if has_external_call and state_update_after:
    report("重入风险")

# V4: 实际测试
function testReentrancy() public {
    vm.startPrank(attacker);
    maliciousContract.attack();  // 尝试重入
    // 如果测试通过 → 真实漏洞
    // 如果revert → 有保护，过滤掉
}
```

---

## 🛠️ 实现计划

### Phase 1: 基础设施 (2-3 小时)
- [ ] 安装 Foundry (`curl -L https://foundry.paradigm.xyz | bash`)
- [ ] 测试 Foundry 环境
- [ ] 创建 `ExploitValidator` 类
- [ ] 测试简单的 PoC 执行

### Phase 2: PoC 生成器 (3-4 小时)
- [ ] 创建 `PoCGenerator` 类
- [ ] 设计 PoC 生成 prompt
- [ ] 测试已知漏洞的 PoC 生成（如 Radiant depositWithAutoDLP）
- [ ] 优化 prompt（提高成功率）

### Phase 3: 集成 (2 小时)
- [ ] 整合 V3 + PoC Generator + Validator
- [ ] 创建 `V4Scanner` 主类
- [ ] 端到端测试

### Phase 4: 验证 (2-3 小时)
- [ ] 用 V3 的 5 个发现测试 V4
- [ ] 预期：V4 应该正确过滤所有误报
- [ ] 调整阈值和逻辑

### Phase 5: 实战测试 (1 小时)
- [ ] 扫描新项目
- [ ] 对比 V3 vs V4 结果

**总时间**: 10-13 小时
**预期成果**: 误报率从 100% 降至 <10%

---

## 💡 关键优势

### 1. 可披露性
```markdown
## V3 报告
发现: tx.origin 使用
严重性: High
证明: 无

项目方回复: "我们知道，这是设计选择"
```

```markdown
## V4 报告
发现: 未授权提款
严重性: Critical
证明: ✅ 附带 Foundry 测试
       ✅ 攻击者获得 1000 ETH
       ✅ 可复现

项目方回复: "立即修复！这里是赏金 $50,000"
```

### 2. 自动化人工验证
- V3: 需要 1 小时/发现 人工验证
- V4: 需要 5 分钟/发现 自动验证
- **时间节省**: 92%

### 3. 信誉建立
- 每个报告都包含可执行的 PoC
- 项目方可以自己运行测试
- 零主观判断，纯技术证明

---

## 🎯 与 SCONE-bench 的对比

| 特性 | SCONE-bench | V4 (我们的实现) |
|------|-------------|----------------|
| **目标** | 评估 AI 安全能力 | 实际漏洞发现 |
| **环境** | Docker + 区块链分叉 | Foundry 本地测试 |
| **验证** | 余额增加 ≥0.1 ETH | 测试断言通过 |
| **工具** | MCP + Foundry + Python | Foundry + Python |
| **输入** | 已知漏洞合约 | 野生合约 |
| **输出** | AI 性能评分 | 漏洞报告 + PoC |

### 我们的简化
- ✅ 不需要区块链分叉（Foundry 本地测试足够）
- ✅ 不需要 Docker（直接在本地运行）
- ✅ 更快（无需启动节点）

### 我们的增强
- ✅ 集成 V3 的候选识别（减少盲目生成 PoC）
- ✅ 针对 Bug Bounty 优化（而非学术评估）

---

## 🚀 下一步

### 立即行动（今天）
1. **验证 Foundry 环境**
2. **开发 `ExploitValidator` 最小可行版本**
3. **测试一个已知漏洞** (如 Radiant depositWithAutoDLP)

### 本周目标
4. **完成 `PoCGenerator`**
5. **V4 端到端测试**
6. **用 V3 的 5 个误报验证 V4**

### 成功标准
- ✅ V4 正确过滤 V3 的所有误报（5/5）
- ✅ V4 成本 <$1/合约
- ✅ V4 生成可执行的 PoC

---

**核心理念**:
> "If you can't exploit it, it's not a vulnerability."
> "如果你不能利用它，那它就不是漏洞。"

**V4 = V3 候选识别 + SCONE-bench 验证方法**

这将彻底解决我们的误报问题！🎯
