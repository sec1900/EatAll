"""网站漏扫"探测思路"归纳（四期）。

输入：某扫描事件内的 HTTP 会话（含 parsed_json），输出：
- path_sequence：路径发现序列（先扫什么后扫什么）+ 每路径请求数
- param_matrix：参数测试矩阵（哪个路径的哪些参数被 fuzz、几个变体、示例 payload）
- techniques：攻击手法统计（sqli/xss/traversal/cmd_injection/ssti/deserialization/ssrf/lfi）
- dict_scan：字典爆破特征（60s 窗口内大量不同路径）

数据来源：sessions.parsed_json 的 method/path/body_b64——全部来自真实捕获。
"""
from __future__ import annotations

import base64
import json
from collections import Counter, defaultdict
from typing import Optional
from urllib.parse import parse_qs, unquote

# 手法识别：分层分类引擎（特征 + 结构 + 未知兜底）
from classify import classify as classify_payload  # noqa: E402

# 展示顺序
TECHNIQUE_ORDER = ["rce", "sql_injection", "deserialization", "expression",
                   "traversal", "xss", "ssrf", "brute", "obfuscation", "unknown"]

DICT_SCAN_PATHS_60S = 30  # 60s 窗口内不同路径数超过该值 → 字典爆破/爬虫


def _parsed(row) -> dict:
    try:
        out = json.loads(row.get("parsed_json") or "{}")
    except (json.JSONDecodeError, AttributeError, TypeError):
        return {}
    return out if isinstance(out, dict) else {}  # "null" 是合法 JSON → None


def _path_of(parsed: dict) -> str:
    """路径（去 query）——路径序列与参数矩阵按 base path 聚合。"""
    path = str(parsed.get("path") or "/")
    if "?" in path:
        path = path.split("?", 1)[0]
    return path


def _params_of(parsed: dict) -> dict[str, str]:
    """提取请求参数（query + POST body urlencoded），返回 name → 原始值。"""
    out: dict[str, str] = {}
    raw_path = str(parsed.get("path") or "/")
    if "?" in raw_path:
        try:
            for k, vs in parse_qs(raw_path.split("?", 1)[1], keep_blank_values=True).items():
                if vs:
                    out[k] = vs[0]
        except ValueError:
            pass
    # POST body
    try:
        body = base64.b64decode(parsed.get("body_b64") or "").decode("utf-8", "replace")
    except (ValueError, TypeError):
        body = ""
    if body and "=" in body and "\x00" not in body:
        try:
            for k, vs in parse_qs(body, keep_blank_values=True).items():
                if k not in out and vs:
                    out[k] = vs[0]
        except ValueError:
            pass
    return out


def _techniques_of(text: str) -> list[str]:
    """分层分类：特征层 + 结构层 + 未知兜底（unknown 也计入，绝不静默归探测）。"""
    r = classify_payload(text)
    if r["kind"] == "probe":
        return []
    return [r["kind"]]


def analyze_webscan(sessions: list) -> dict:
    """归纳扫描事件的网站探测思路。

    sessions: 事件内 HTTP 会话行（sqlite3.Row 或 dict，需含 parsed_json、ts_start）。
    """
    # 按 ts 排序
    sess = sorted(sessions, key=lambda r: r.get("ts_start") or 0)

    # 1. 路径发现序列（去重后首次出现顺序）
    path_first: dict[str, dict] = {}
    path_count: Counter = Counter()
    techniques: Counter = Counter()
    param_seen: dict[tuple, set] = defaultdict(set)  # (path, param) → 值集合
    param_example: dict[tuple, str] = {}

    for r in sess:
        p = _parsed(r)
        path = _path_of(p)
        path_count[path] += 1
        if path not in path_first:
            path_first[path] = {"path": path, "first_ts": r.get("ts_start") or 0,
                                "method": p.get("method", "")}

        # 手法识别（path + query + body 全文，URL 解码后匹配——payload 常被编码传输）
        raw = f"{p.get('method', '')} {p.get('path', '')} {p.get('body_b64', '')}"
        text = unquote(raw)
        for t in _techniques_of(text):
            techniques[t] += 1

        # 参数矩阵
        for k, v in _params_of(p).items():
            key = (path, k)
            param_seen[key].add(v)
            # example 优先保留含手法特征词的值（展示探测 payload 样例）
            if key not in param_example or _techniques_of(v):
                param_example[key] = v[:80]

    path_sequence = [
        {**path_first[path], "count": path_count[path]}
        for path in sorted(path_first, key=lambda x: path_first[x]["first_ts"])
    ]

    # 2. 参数矩阵
    param_matrix = {}
    for (path, param), values in sorted(param_seen.items()):
        param_matrix.setdefault(path, {})[param] = {
            "variants": len(values),
            "example": param_example[(path, param)],
        }

    # 3. 手法统计
    tech_list = [{"name": n, "count": techniques[n]} for n in TECHNIQUE_ORDER
                 if techniques[n] > 0]

    # 4. 字典扫描特征：60s 窗口内不同路径峰值
    dict_scan = _dict_scan_score(sess)

    return {
        "total_requests": len(sess),
        "distinct_paths": len(path_sequence),
        "path_sequence": path_sequence[:100],
        "param_matrix": param_matrix,
        "techniques": tech_list,
        "dict_scan": dict_scan,
    }


def _dict_scan_score(sess: list) -> bool:
    """滑动 60s 窗口，不同路径数峰值 > 阈值 → 字典爆破/爬虫特征。"""
    times = [r.get("ts_start") or 0 for r in sess]
    if not times:
        return False
    window = 60_000
    best = 0
    j = 0
    paths = []
    for i, t in enumerate(times):
        while j < len(times) and times[j] - t <= window:
            j += 1
        # 窗口 [i, j) 内不同路径
        distinct = len({_path_of(_parsed(sess[k])) for k in range(i, j)})
        best = max(best, distinct)
        _ = paths
    return best > DICT_SCAN_PATHS_60S
