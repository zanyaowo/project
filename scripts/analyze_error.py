#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["anthropic>=0.40"]
# ///
"""
Error Analysis Multi-Agent System

架構：
  Sub-agents（並行）: ML Pipeline | eBPF Kernel | Rust Userspace | Data Pipeline | Test Harness
  Summarizer（串行）: 匯總 → 更新 docs/claude_ref/failure_records.md + CLAUDE.md

用法：
  uv run scripts/analyze_error.py --error "錯誤訊息"
  cat error.log | uv run scripts/analyze_error.py
"""
import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from pathlib import Path

import anthropic

# ── 路徑常數 ──────────────────────────────────────────────────────────────────

PROJECT_ROOT     = Path(__file__).parent.parent
FAILURE_RECORDS  = PROJECT_ROOT / "docs/claude_ref/failure_records.md"
CLAUDE_MD        = PROJECT_ROOT / "CLAUDE.md"

# ── Sub-agent 定義 ────────────────────────────────────────────────────────────

SUBSYSTEMS: dict[str, dict] = {
    "ml_pipeline": {
        "name": "Python ML Pipeline",
        "prompt": """\
你是 eBPF firewall 專案的 Python ML pipeline 專家。
負責範圍：service/model/pipeline/、service/model/data/、service/model/schema.py

已知約束：
- FEATURE_COLS 必須維持 26 個（schema.py）
- IsolationForest 只用 BENIGN 資料訓練
- Train=03-11（2018-11-03）必須早於 Test=01-12（2018-12-01）
- clean_and_save() 之後不可再呼叫 clean()

分析錯誤是否屬於你的範圍。若是，回傳：
1. 根本原因（1-2 句）
2. 受影響的程式碼位置
3. 防止再犯的規則

若不在你的範圍內，只回覆：NOT_MY_SCOPE""",
    },
    "ebpf_kernel": {
        "name": "eBPF/Kernel",
        "prompt": """\
你是 eBPF firewall 專案的 eBPF kernel 程式專家。
負責範圍：service/firewall/ebpf/（XDP 和 TC 程式）

已知約束：
- 無浮點運算 → 用定點數（位移 10 位）或 BPF_MAP 查表
- Stack 上限 512B → 大型陣列放 BPF_MAP
- 迴圈必須有界（#pragma unroll）
- 單函式指令數上限 → 用 tail call 拆分
- 無遞迴

分析錯誤是否屬於你的範圍。若是，回傳：
1. 根本原因（1-2 句）
2. Verifier 錯誤訊息（若有）
3. 防止再犯的規則

若不在你的範圍內，只回覆：NOT_MY_SCOPE""",
    },
    "rust_userspace": {
        "name": "Rust Userspace",
        "prompt": """\
你是 eBPF firewall 專案的 Rust userspace 程式專家。
負責範圍：service/firewall/src/（RingBuf consumer、ModelFeature、IPC）

關鍵介面：
- ModelFeature struct 必須有剛好 26 個欄位（對應 Python FEATURE_COLS）
- Unix socket IPC 送特徵向量到 Python ML
- BPF_MAP 更新模型權重與分位桶邊界

分析錯誤是否屬於你的範圍。若是，回傳：
1. 根本原因（1-2 句）
2. 受影響的程式碼位置
3. 防止再犯的規則

若不在你的範圍內，只回覆：NOT_MY_SCOPE""",
    },
    "data_pipeline": {
        "name": "Data Pipeline",
        "prompt": """\
你是 eBPF firewall 專案的資料 pipeline 專家。
負責範圍：service/model/data/（loader.py、cleaner.py、sample.py）

已知失敗模式：
- 拼字 silent failure："BEGIN" 應為 "BENIGN"，"transfrom" 應為 "transform"
- 用 get_balance_sample_from_files 訓練 IF（應用 get_normal_sample_from_files）
- Inbound 欄位 data leakage
- Source Port 不可作為模型特徵

分析錯誤是否屬於你的範圍。若是，回傳：
1. 根本原因（1-2 句）
2. Silent failure 模式（若有）
3. 防止再犯的規則

若不在你的範圍內，只回覆：NOT_MY_SCOPE""",
    },
    "test_harness": {
        "name": "Test Harness",
        "prompt": """\
你是 eBPF firewall 專案的測試 harness 專家。
負責範圍：service/model/tests/（harness_*.py、conftest.py）

關鍵契約：
- FEATURE_COLS 必須剛好 26 個（Rust ModelFeature 契約）
- FPR < 2%（synthetic BENIGN 資料）
- AUC > 0.90（真實資料，@slow）
- IsolationForest 推論具確定性

分析錯誤是否屬於你的範圍。若是，回傳：
1. 根本原因（1-2 句）
2. 哪個測試失敗及原因
3. 防止再犯的規則

若不在你的範圍內，只回覆：NOT_MY_SCOPE""",
    },
}

# ── CLAUDE.md 現有絕對禁止事項（給 summarizer 判斷是否為新規則用）──────────────

EXISTING_PROHIBITIONS = """\
- FEATURE_COLS 改動 → 必須同步 schema.py 並重跑 feature_select（目前 26 個）
- IF 訓練資料不可混入 attack label（BENIGN only）
- Train=03-11（2018-11-03）必須早於 Test=01-12（2018-12-01）
- clean_and_save() 之後不可再呼叫 clean()"""

SUMMARIZER_PROMPT = f"""\
你是 eBPF firewall 專案的首席錯誤分析師。

你將收到多個子系統代理的分析結果（Python ML Pipeline、eBPF Kernel、Rust Userspace、Data Pipeline、Test Harness）。

任務：
1. 找出哪個子代理找到根本原因
2. 寫出簡潔的失敗記錄（2-4 句：發生什麼 → 根本原因 → 防止措施）
3. 判斷是否揭示了一條 CLAUDE.md 目前尚未列出的新絕對禁止規則

CLAUDE.md 現有絕對禁止事項：
{EXISTING_PROHIBITIONS}

輸出必須為合法 JSON，格式如下：
{{
  "title": "簡短失敗標題（不超過 15 字）",
  "record": "失敗描述（2-4 句，繁體中文）",
  "new_prohibition": null 或 "需要加入 CLAUDE.md 的新規則（繁體中文）"
}}"""


# ── API 呼叫工具 ───────────────────────────────────────────────────────────────

def _call_agent(client: anthropic.Anthropic, system: str, user_error: str) -> str:
    msg = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=512,
        system=system,
        messages=[{"role": "user", "content": f"錯誤訊息：\n\n{user_error}"}],
    )
    return msg.content[0].text.strip()


def _call_summarizer(
    client: anthropic.Anthropic,
    sub_results: dict[str, str],
    user_error: str,
) -> dict:
    context = "\n\n".join(
        f"=== {SUBSYSTEMS[key]['name']} ===\n{result}"
        for key, result in sub_results.items()
        if result != "NOT_MY_SCOPE"
    ) or "（所有子代理均回報 NOT_MY_SCOPE）"

    user_content = f"原始錯誤：\n{user_error}\n\n子代理分析結果：\n{context}"

    msg = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=SUMMARIZER_PROMPT,
        messages=[{"role": "user", "content": user_content}],
    )
    text = msg.content[0].text.strip()

    # 解析 JSON（容錯：嘗試擷取第一個 {...} 區塊）
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        import re
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group())
        raise ValueError(f"Summarizer 未回傳合法 JSON：\n{text}")


# ── 檔案更新 ───────────────────────────────────────────────────────────────────

def _update_failure_records(summary: dict) -> None:
    today = date.today().isoformat()
    entry = f"\n---\n\n**{today} — {summary['title']}**\n{summary['record']}\n"
    with open(FAILURE_RECORDS, "a", encoding="utf-8") as f:
        f.write(entry)
    print(f"[✓] 已寫入 failure_records.md：{summary['title']}")


def _update_claude_md(new_prohibition: str) -> None:
    text = CLAUDE_MD.read_text(encoding="utf-8")
    marker = "## 絕對禁止（違反即為 bug）"
    if marker not in text:
        print("[!] CLAUDE.md 找不到絕對禁止段落，跳過更新")
        return

    # 在最後一條 `-` 開頭的禁止事項後插入新規則
    idx = text.index(marker)
    block_end = text.find("\n---", idx)
    insertion = f"- {new_prohibition}\n"
    new_text = text[:block_end] + insertion + text[block_end:]
    CLAUDE_MD.write_text(new_text, encoding="utf-8")
    print(f"[✓] 已更新 CLAUDE.md 絕對禁止：{new_prohibition}")


# ── 主流程 ────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="分析錯誤並更新失敗記錄")
    parser.add_argument("--error", "-e", help="錯誤訊息（省略則從 stdin 讀取）")
    args = parser.parse_args()

    error_text = args.error or sys.stdin.read().strip()
    if not error_text:
        print("錯誤：請提供錯誤訊息（--error 或 stdin）", file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic()

    # Phase 1：並行執行 sub-agents
    print("=== Phase 1：Sub-agent 並行分析 ===")
    sub_results: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=len(SUBSYSTEMS)) as executor:
        futures = {
            executor.submit(_call_agent, client, info["prompt"], error_text): key
            for key, info in SUBSYSTEMS.items()
        }
        for future in as_completed(futures):
            key = futures[future]
            result = future.result()
            sub_results[key] = result
            status = "✓" if result != "NOT_MY_SCOPE" else "–"
            print(f"  [{status}] {SUBSYSTEMS[key]['name']}")

    relevant = {k: v for k, v in sub_results.items() if v != "NOT_MY_SCOPE"}
    if not relevant:
        print("\n[!] 所有子代理均回報不在範圍內，仍繼續匯總。")

    # Phase 2：Summarizer
    print("\n=== Phase 2：Summarizer 匯總 ===")
    summary = _call_summarizer(client, sub_results, error_text)
    print(f"  標題：{summary['title']}")
    print(f"  記錄：{summary['record']}")
    if summary.get("new_prohibition"):
        print(f"  新禁止規則：{summary['new_prohibition']}")

    # Phase 3：更新檔案
    print("\n=== Phase 3：更新文件 ===")
    _update_failure_records(summary)
    if summary.get("new_prohibition"):
        _update_claude_md(summary["new_prohibition"])

    print("\n完成。")


if __name__ == "__main__":
    main()
