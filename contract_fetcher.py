#!/usr/bin/env python3
"""
Contract Fetcher — 从 Etherscan 和 GitHub 拉取桥合约源码
=========================================================

支持:
- Etherscan API (Ethereum, Arbitrum, Optimism, Base, BSC, Polygon)
- GitHub 仓库直接克隆
- 已知桥合约地址库
"""

import os
import json
import time
import subprocess
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict
import urllib.request
import urllib.error

CACHE_DIR = Path.home() / ".safeter" / "contracts"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

SCAN_RESULTS_DIR = Path.home() / ".safeter" / "results"
SCAN_RESULTS_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# Explorer API 配置
# ============================================================

EXPLORER_APIS = {
    "ethereum": "https://api.etherscan.io/api",
    "arbitrum": "https://api.arbiscan.io/api",
    "optimism": "https://api-optimistic.etherscan.io/api",
    "base": "https://api.basescan.org/api",
    "bsc": "https://api.bscscan.com/api",
    "polygon": "https://api.polygonscan.com/api",
}


# ============================================================
# 已知桥合约目标库
# ============================================================

KNOWN_BRIDGE_TARGETS: List[Dict] = [
    # Hyperbridge
    {
        "name": "Hyperbridge-ETH-Host",
        "chain": "ethereum",
        "address": "0x792A6236AF69787C40cF76b69B4c8c7B28c4cA20",
        "type": "bridge_host",
    },
    {
        "name": "Hyperbridge-CallDispatcher",
        "chain": "ethereum",
        "address": "0xC71251c8b3e7B02697A84363Eef6DcE8DfBdF333",
        "type": "dispatcher",
    },
    {
        "name": "Hyperbridge-ARB-Host",
        "chain": "arbitrum",
        "address": "0xE05AFD4Eb2ce6d65c40e1048381BD0Ef8b4B299e",
        "type": "bridge_host",
    },
    {
        "name": "Hyperbridge-OP-Host",
        "chain": "optimism",
        "address": "0x78c8A5F27C06757EA0e30bEa682f1FD5C8d7645d",
        "type": "bridge_host",
    },
    {
        "name": "Hyperbridge-BSC-Host",
        "chain": "bsc",
        "address": "0x24B5d421Ec373FcA57325dd2F0C074009Af021F7",
        "type": "bridge_host",
    },
    # wXRP
    {
        "name": "wXRP-Token",
        "chain": "ethereum",
        "address": "0x39fBBABf11738317a448031930706cd3e612e1B9",
        "type": "wrapped_token",
    },
    # CrossCurve (attacked)
    {
        "name": "CrossCurve-ReceiverAxelar",
        "chain": "ethereum",
        "address": "0xb2185950f5a0a46687ac331916508aada202e063",
        "type": "bridge_receiver",
    },
]

# GitHub 仓库目标
GITHUB_TARGETS: List[Dict] = [
    {
        "name": "Hyperbridge",
        "repo": "polytope-labs/hyperbridge",
        "sol_paths": ["evm/src/"],
    },
    {
        "name": "Snowbridge",
        "repo": "Snowfork/snowbridge",
        "sol_paths": ["contracts/src/"],
    },
    {
        "name": "Wormhole",
        "repo": "wormhole-foundation/wormhole",
        "sol_paths": ["ethereum/contracts/bridge/"],
    },
    {
        "name": "LayerZero-V2",
        "repo": "LayerZero-Labs/LayerZero-v2",
        "sol_paths": ["packages/layerzero-v2/evm/oapp/contracts/oft/"],
    },
    {
        "name": "Gravity-Bridge",
        "repo": "Gravity-Bridge/Gravity-Bridge",
        "sol_paths": ["solidity/contracts/"],
    },
]


@dataclass
class FetchedContract:
    """拉取到的合约"""
    name: str
    chain: str
    address: Optional[str]
    source_code: str
    file_path: Path
    source: str  # "etherscan" or "github"


# ============================================================
# Etherscan 抓取
# ============================================================

def fetch_from_etherscan(
    chain: str,
    address: str,
    api_key: Optional[str] = None,
    name: str = "Unknown"
) -> Optional[FetchedContract]:
    """从 Etherscan API 拉取已验证合约源码"""

    api_base = EXPLORER_APIS.get(chain)
    if not api_base:
        print(f"  [!] Unknown chain: {chain}")
        return None

    # 检查缓存
    cache_file = CACHE_DIR / f"{chain}_{address}.sol"
    if cache_file.exists():
        print(f"  [cache] {name} ({address[:10]}...)")
        return FetchedContract(
            name=name,
            chain=chain,
            address=address,
            source_code=cache_file.read_text(),
            file_path=cache_file,
            source="etherscan_cache",
        )

    key = api_key or os.getenv("ETHERSCAN_API_KEY", "")
    url = f"{api_base}?module=contract&action=getsourcecode&address={address}"
    if key:
        url += f"&apikey={key}"

    print(f"  [fetch] {name} on {chain} ({address[:10]}...)")

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "safeter-v4"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        if data.get("status") != "1" or not data.get("result"):
            print(f"  [!] API error: {data.get('message', 'unknown')}")
            return None

        result = data["result"][0]
        source = result.get("SourceCode", "")

        if not source or source == "":
            print(f"  [!] Contract not verified")
            return None

        # 处理多文件格式 (JSON)
        if source.startswith("{") or source.startswith("{{"):
            source_clean = source.strip("{}")
            try:
                parsed = json.loads("{" + source_clean + "}")
                if "sources" in parsed:
                    # 合并所有源文件
                    all_code = []
                    for fname, fdata in parsed["sources"].items():
                        all_code.append(f"// === {fname} ===\n{fdata['content']}")
                    source = "\n\n".join(all_code)
                elif "content" in parsed:
                    source = parsed["content"]
            except json.JSONDecodeError:
                pass  # 保持原始 source

        # 缓存
        cache_file.write_text(source)

        return FetchedContract(
            name=name,
            chain=chain,
            address=address,
            source_code=source,
            file_path=cache_file,
            source="etherscan",
        )

    except (urllib.error.URLError, TimeoutError) as e:
        print(f"  [!] Fetch failed: {e}")
        return None


# ============================================================
# GitHub 抓取
# ============================================================

def fetch_from_github(
    repo: str,
    sol_paths: List[str],
    name: str = "Unknown"
) -> List[FetchedContract]:
    """从 GitHub 克隆仓库并提取 Solidity 文件"""

    clone_dir = CACHE_DIR / "github" / repo.replace("/", "_")

    if clone_dir.exists():
        print(f"  [cache] {name} ({repo})")
    else:
        print(f"  [clone] {name} ({repo})")
        clone_dir.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", f"https://github.com/{repo}.git", str(clone_dir)],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            print(f"  [!] Clone failed: {result.stderr[:200]}")
            return []

    contracts = []
    for sol_path in sol_paths:
        full_path = clone_dir / sol_path
        if not full_path.exists():
            continue
        for sol_file in full_path.rglob("*.sol"):
            code = sol_file.read_text()
            contracts.append(FetchedContract(
                name=f"{name}/{sol_file.name}",
                chain="github",
                address=None,
                source_code=code,
                file_path=sol_file,
                source="github",
            ))

    print(f"  [done] {len(contracts)} .sol files from {name}")
    return contracts


# ============================================================
# 批量抓取
# ============================================================

def fetch_all_targets(
    include_etherscan: bool = True,
    include_github: bool = True,
) -> List[FetchedContract]:
    """拉取所有已知目标"""

    all_contracts = []

    if include_etherscan:
        print("\n== Etherscan Targets ==")
        for target in KNOWN_BRIDGE_TARGETS:
            contract = fetch_from_etherscan(
                chain=target["chain"],
                address=target["address"],
                name=target["name"],
            )
            if contract:
                all_contracts.append(contract)
            time.sleep(0.3)  # Rate limit

    if include_github:
        print("\n== GitHub Targets ==")
        for target in GITHUB_TARGETS:
            contracts = fetch_from_github(
                repo=target["repo"],
                sol_paths=target["sol_paths"],
                name=target["name"],
            )
            all_contracts.extend(contracts)

    print(f"\nTotal: {len(all_contracts)} contracts fetched")
    return all_contracts


def add_etherscan_target(name: str, chain: str, address: str, contract_type: str = "bridge"):
    """动态添加新目标"""
    KNOWN_BRIDGE_TARGETS.append({
        "name": name,
        "chain": chain,
        "address": address,
        "type": contract_type,
    })


def add_github_target(name: str, repo: str, sol_paths: List[str]):
    """动态添加 GitHub 目标"""
    GITHUB_TARGETS.append({
        "name": name,
        "repo": repo,
        "sol_paths": sol_paths,
    })


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import sys

    mode = sys.argv[1] if len(sys.argv) > 1 else "all"

    if mode == "etherscan":
        fetch_all_targets(include_github=False)
    elif mode == "github":
        fetch_all_targets(include_etherscan=False)
    elif mode == "all":
        fetch_all_targets()
    elif mode == "address":
        if len(sys.argv) < 4:
            print("Usage: python contract_fetcher.py address <chain> <address>")
            sys.exit(1)
        result = fetch_from_etherscan(sys.argv[2], sys.argv[3], name="manual")
        if result:
            print(f"Saved to: {result.file_path}")
    else:
        print("Usage: python contract_fetcher.py [all|etherscan|github|address <chain> <addr>]")
