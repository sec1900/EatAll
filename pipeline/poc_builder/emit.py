"""YAML 输出：nuclei 模板落盘。

- yaml.safe_dump（优先 PyYAML；缺失时退化为内置极简序列化器）
- {{xxx}} 动态值自动加引号（避免被 YAML 解析为 flow mapping）
- 文件头注释：生成时间 + 源 IP（可审计）
- tmp + rename 原子写；可选 nuclei -validate 门禁
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from db import templates_dir

# nuclei id 允许字符集（计划 id 命名：poc-{type}-{vendor}-{feature}-{hash8}）
# 与 nuclei 校验一致：段间分隔符不允许连续、不允许首尾
_ID_RE = re.compile(r"^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$")


def sanitize_segment(s: str, max_len: int = 24) -> str:
    """id 段清洗：小写、非字母数字 → '-', 压缩连续 '-'，去掉首尾 '-'。"""
    out = re.sub(r"-+", "-", re.sub(r"[^a-z0-9-]", "-", str(s).lower())).strip("-")
    return out[:max_len].rstrip("-")


def make_poc_id(ptype: str, vendor: str, feature: str, hash8: str) -> str:
    """id 命名（计划）：poc-{type}-{vendor}-{feature}-{hash8}。

    所有段统一清洗并保证非空（空段兜底 'probe'），杜绝连续 '-' 等
    nuclei id 非法形态。
    """
    v = sanitize_segment(vendor) or "generic"
    f = sanitize_segment(feature) or "probe"
    return f"poc-{sanitize_segment(ptype) or 'generic'}-{v}-{f}-{hash8}"


class EmitError(Exception):
    pass


class ValidateError(EmitError):
    pass


# ---------- YAML 序列化 ----------

def _needs_quote(s: str) -> bool:
    if not s:
        return False
    if s[0] in '{[&*!|>%@`"\'#':
        return True
    if s in ("true", "false", "True", "False", "null", "Null", "NULL", "~", "yes", "no", "on", "off"):
        return True
    if s[0].isdigit() or (s[0] in "+-." and len(s) > 1 and s[1].isdigit()):
        return True
    if "{{" in s or "\n" in s or "\t" in s or ": " in s or " #" in s:
        return True
    if s != s.strip():
        return True
    return False


def _yaml_str(s: str, indent: int, as_value: bool) -> str:
    """极简 YAML 字符串渲染（含引号规则）。"""
    quote = _needs_quote(s)
    if quote:
        body = (
            s.replace("\\", "\\\\").replace('"', '\\"')
            .replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r")
        )
        return f'"{body}"'
    return s


def _fallback_dump(obj, indent: int = 0) -> str:
    """PyYAML 缺失时的内置序列化器（覆盖本系统模板的全部结构形态）。"""
    pad = " " * indent
    lines: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k)
            if isinstance(v, dict):
                lines.append(f"{pad}{key}:")
                lines.append(_fallback_dump(v, indent + 2))
            elif isinstance(v, list):
                if not v:
                    lines.append(f"{pad}{key}: []")
                elif all(isinstance(x, (str, int, float, bool)) or x is None for x in v):
                    lines.append(f"{pad}{key}:")
                    for item in v:
                        lines.append(f"{pad}- {_yaml_str(str(item), indent, True)}")
                else:
                    lines.append(f"{pad}{key}:")
                    for item in v:
                        lines.append(f"{pad}-")
                        lines.append(_fallback_dump(item, indent + 4))
            elif v is None:
                lines.append(f"{pad}{key}: null")
            elif isinstance(v, bool):
                lines.append(f"{pad}{key}: {'true' if v else 'false'}")
            elif isinstance(v, (int, float)):
                lines.append(f"{pad}{key}: {v}")
            else:
                lines.append(f"{pad}{key}: {_yaml_str(str(v), indent, True)}")
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                lines.append(f"{pad}-")
                lines.append(_fallback_dump(item, indent + 2))
            else:
                lines.append(f"{pad}- {_yaml_str(str(item), indent, True)}")
    else:
        lines.append(f"{pad}{_yaml_str(str(obj), indent, True)}")
    return "\n".join(lines)


def dump_yaml(template: dict) -> str:
    """模板 dict → YAML 文本。优先 PyYAML，确保 {{}} 值被引号包裹。"""
    try:
        import yaml
    except ImportError:
        return _fallback_dump(template)

    class _QuotedDumper(yaml.SafeDumper):
        pass

    def _represent_str(dumper: yaml.Dumper, data: str):
        style = '"' if _needs_quote(data) else None
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)

    yaml.add_representer(str, _represent_str, Dumper=_QuotedDumper)
    return yaml.dump(
        template,
        Dumper=_QuotedDumper,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=4096,
    )


# ---------- 落盘 ----------

def _validate(path: Path, nuclei_bin: Optional[str]) -> None:
    """nuclei -validate 门禁；失败抛 ValidateError。"""
    if not nuclei_bin:
        return
    try:
        proc = subprocess.run(
            [nuclei_bin, "-validate", "-t", str(path)],
            capture_output=True, text=True, timeout=120,
        )
    except FileNotFoundError:
        return  # nuclei 不可用时不阻塞
    except subprocess.TimeoutExpired:
        raise ValidateError(f"nuclei -validate 超时: {path}")
    if proc.returncode != 0:
        raise ValidateError(
            f"nuclei -validate 失败 {path}: {proc.stdout[-500:]}{proc.stderr[-500:]}"
        )


def emit(
    template: dict,
    *,
    src_ip: str,
    source_session_count: int,
    out_dir: Optional[Path] = None,
    validate: bool = False,
    nuclei_bin: Optional[str] = None,
) -> tuple[str, str]:
    """模板原子落盘 → (poc_id, 文件路径)。

    文件头注释含生成时间 + 源 IP（审计线索）；tmp+rename 保证不出现半文件。
    """
    poc_id = str(template.get("id") or "")
    if not _ID_RE.match(poc_id):
        raise EmitError(f"非法模板 id: {poc_id!r}")

    out_dir = Path(out_dir) if out_dir else templates_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    header = (
        "# generated by EatAll pipeline (M2)\n"
        f"# generated_at: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
        f"# src_ip: {src_ip}\n"
        f"# source_sessions: {source_session_count}\n"
    )
    text = header + dump_yaml(template)

    final = out_dir / f"{poc_id}.yaml"
    tmp = out_dir / f".{poc_id}.tmp{os.getpid()}"
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, final)

    if validate:
        _validate(final, nuclei_bin)
    return poc_id, str(final)
