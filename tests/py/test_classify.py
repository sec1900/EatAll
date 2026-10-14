"""classify.py 分层分类引擎单测。"""
from classify import classify, is_exploit, shannon_entropy


def test_feature_layer():
    assert classify("/index.php?id=1' AND sleep(3)-- -")["kind"] == "sql_injection"
    assert classify("GET /wls-wsat/CoordinatorPortType")["kind"] == "rce"
    assert classify("../../../../etc/passwd")["kind"] == "traversal"
    assert classify("<script>alert(1)</script>")["kind"] == "xss"
    assert classify("?cmd=whoami")["kind"] == "rce"
    assert classify("jndi:ldap://evil.com")["kind"] == "rce"


def test_structure_layer():
    # 结构检测不依赖具体关键词
    assert classify("?q=1' OR 1=1-- -")["kind"] == "sql_injection"  # 引号+or
    assert classify("?x=1' AND '1'='1")["kind"] == "sql_injection"
    assert classify("?y=abc'; SELECT * FROM users-- ")["kind"] == "sql_injection"
    assert classify(";whoami")["kind"] == "rce"  # 命令分隔符
    assert classify("|cat /etc/hosts")["kind"] == "rce"
    assert classify("%252e%252e%252f")["kind"] in ("obfuscation", "traversal")
    assert classify("%{new java.lang.ProcessBuilder('id')}")["kind"] == "expression"
    assert classify("${7*7}")["kind"] == "expression"
    assert classify("{{7*'7'}}")["kind"] == "expression"


def test_unknown_fallback():
    # 高熵/混淆但无法归类 → unknown，绝不 probe（混合字符集使熵 > 4.5）
    r = classify("aB3!x9#z1@q5$w8%r2&t7*u4(v6)p0_=e2;f4:c8+d1,g7")
    assert r["kind"] == "unknown"
    assert is_exploit(r["kind"])
    # 密集编码
    r2 = classify("%c0%ae%c0%ae%c0%af" * 3)
    assert r2["kind"] in ("unknown", "obfuscation")
    # 纯 hex 长串 = token，不误标
    assert classify("9f8e7d6c5b4a3e2f1d0c9b8a7f6e5d4c" * 2)["kind"] == "probe"


def test_probe_clean():
    assert classify("GET /index.php")["kind"] == "probe"
    assert classify("GET /favicon.ico")["kind"] == "probe"
    assert not is_exploit("probe")


def test_entropy():
    assert shannon_entropy("aaaaaaa") < 1.0
    assert shannon_entropy("aB3!x9#z1@q5$w8%r2&t7*u4(v6)p0_") > 4.0
