"""chain.py 利用链识别单测。"""
import base64
import json

from chain import analyze_chains


def _sess(method, path, body="", ts=1000, headers=None):
    parsed = {
        "method": method, "path": path,
        "body_b64": base64.b64encode(body.encode()).decode() if body else "",
        "headers": headers or {},
    }
    return {"ts_start": ts, "parsed_json": json.dumps(parsed)}


def test_upload_exec_chain():
    s = [
        _sess("GET", "/upload.php", ts=100),
        _sess("POST", "/upload.php",
              body="------boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.jsp\"\r\n\r\n<% out.println(\"pwned\"); %>",
              headers={"Content-Type": "multipart/form-data; boundary=----boundary"},
              ts=200),
        _sess("GET", "/upload/shell.jsp?cmd=whoami", ts=300),
    ]
    chains = analyze_chains(s)
    assert len(chains) == 1
    assert chains[0]["type"] == "upload_exec"
    assert "cmd" in chains[0]["detail"]


def test_upload_only_no_exec():
    s = [
        _sess("POST", "/upload.php",
              body="filename=shell.php\n<?php system($_GET['c']); ?>",
              ts=100),
        _sess("GET", "/index.php", ts=200),
    ]
    chains = analyze_chains(s)
    assert chains and chains[0]["type"] == "upload_only"


def test_brute_chain():
    s = [
        _sess("POST", f"/login.php?username=admin&password=pass{i}", ts=100 + i)
        for i in range(6)
    ]
    chains = analyze_chains(s)
    assert chains and chains[0]["type"] == "brute"
    # username 1 个值 + password 6 个值 = 7 组凭据变体
    assert "7 组凭据变体" in chains[0]["detail"]


def test_probe_exploit_chain():
    s = [
        _sess("GET", "/index.php", ts=100),
        _sess("GET", "/index.php?id=1' AND sleep(3)-- -", ts=200),
    ]
    chains = analyze_chains(s)
    assert chains and chains[0]["type"] == "probe_exploit"


def test_no_chain_for_single():
    assert analyze_chains([_sess("GET", "/index.php", ts=100)]) == []


def test_no_chain_for_repeated_probe():
    s = [_sess("GET", "/index.php", ts=100 + i) for i in range(5)]
    assert analyze_chains(s) == []


def test_app_cluster_attack():
    """WebLogic 风格：同一应用多个分散路径 + 攻击 payload → 应用级攻击簇。"""
    s = [
        _sess("GET", "/console/", ts=100),
        _sess("POST", "/console/j_security_check?j_username=a&j_password=b", ts=200),
        _sess("GET", "/console/css/%252e%252e%252fconsole.portal", ts=300),
        _sess("POST", "/wls-wsat/CoordinatorPortType", ts=400),
        _sess("GET", "/ws_utc/resources/setting/options", ts=500),
        _sess("GET", "/uddiexplorer/SearchPublicRegistries.jsp", ts=600),
    ]
    chains = analyze_chains(s)
    types = [c["type"] for c in chains]
    assert "app_cluster_attack" in types


def test_repeated_attack_chain():
    # 同路径 ≥10 次且含攻击 payload → 重复确认攻击链
    s = [_sess("GET", "/jmx-console/", ts=100 + i) for i in range(10)]
    s.append(_sess("GET", "/jmx-console/;jsessionid=x", ts=200))
    # 让其中一个含攻击特征
    s[3] = _sess("GET", "/jmx-console/?cmd=whoami", ts=103)
    chains = analyze_chains(s)
    types = [c["type"] for c in chains]
    assert "repeated_attack" in types or "probe_exploit" in types
