"""webscan.py 探测思路归纳单测。"""
import base64
import json

from webscan import analyze_webscan


def _sess(path, ts=1_000, method="GET", body_b64="", parsed_extra=None):
    parsed = {"method": method, "path": path, "body_b64": body_b64}
    if parsed_extra:
        parsed.update(parsed_extra)
    return {
        "session_id": "s" + str(abs(hash(path)) % 100000),
        "ts_start": ts,
        "parsed_json": json.dumps(parsed),
    }


def test_path_sequence_order():
    s = [
        _sess("/", ts=100),
        _sess("/index.php", ts=200),
        _sess("/admin/", ts=300),
        _sess("/", ts=400),  # 重复
        _sess("/admin/", ts=500),
    ]
    out = analyze_webscan(s)
    seq = out["path_sequence"]
    assert [p["path"] for p in seq] == ["/", "/index.php", "/admin/"]
    assert seq[0]["count"] == 2 and seq[2]["count"] == 2
    assert out["total_requests"] == 5 and out["distinct_paths"] == 3


def test_techniques_detection():
    s = [
        _sess("/index.php?id=1%27%20union%20select%20sleep(3)--%20-"),
        _sess("/search.php?q=<script>alert(1)</script>"),
        _sess("/download.php?f=../../../../etc/passwd"),
        _sess("/cmd.php?x=;id"),
        _sess("/ssti.php?name={{7*7}}"),
        _sess("/ssrf.php?u=file:///etc/passwd"),
    ]
    out = analyze_webscan(s)
    tech = {t["name"]: t["count"] for t in out["techniques"]}
    assert tech.get("sql_injection", 0) >= 1
    assert tech.get("xss", 0) >= 1
    assert tech.get("traversal", 0) >= 1
    assert tech.get("rce", 0) >= 1
    assert tech.get("expression", 0) >= 1
    assert tech.get("ssrf", 0) >= 1


def test_unknown_technique():
    """高熵不可归类 → unknown 计入，不静默归探测。"""
    s = [_sess("/x.php?p=aB3!x9#z1@q5$w8%r2&t7*u4(v6)p0_=e2;f4:c8+d1,g7")]
    out = analyze_webscan(s)
    tech = {t["name"]: t["count"] for t in out["techniques"]}
    assert tech.get("unknown", 0) >= 1


def test_param_matrix():
    s = [
        _sess("/login.php?username=admin&password=123", ts=100),
        _sess("/login.php?username=admin' or 1=1-- &password=x", ts=200),
        _sess("/login.php?username=root", ts=300),
    ]
    out = analyze_webscan(s)
    matrix = out["param_matrix"]
    assert "/login.php" in matrix
    assert matrix["/login.php"]["username"]["variants"] == 3
    assert "or 1=1" in matrix["/login.php"]["username"]["example"]


def test_param_matrix_post_body():
    body = base64.b64encode(b"user=admin&pass=test123").decode()
    s = [_sess("/login.php", method="POST", body_b64=body)]
    out = analyze_webscan(s)
    matrix = out["param_matrix"]
    assert matrix["/login.php"]["user"]["variants"] == 1
    assert matrix["/login.php"]["pass"]["example"] == "test123"


def test_dict_scan_flag():
    # 60s 内 40 个不同路径 → 字典爆破特征
    s = [_sess(f"/dict/path{i}.php", ts=1000 + i * 1000) for i in range(40)]
    assert analyze_webscan(s)["dict_scan"] is True
    # 少量路径 → 非字典
    s2 = [_sess("/a", ts=1000), _sess("/b", ts=2000), _sess("/c", ts=3000)]
    assert analyze_webscan(s2)["dict_scan"] is False


def test_empty_input():
    out = analyze_webscan([])
    assert out["total_requests"] == 0
    assert out["path_sequence"] == []
    assert out["techniques"] == []


def test_patterns_are_substrings():
    """特征词必须是合法子串（无正则元字符依赖）。"""
    from classify import FEATURE_KINDS
    for name, pats in FEATURE_KINDS:
        for p in pats:
            assert len(p) >= 2, (name, p)
