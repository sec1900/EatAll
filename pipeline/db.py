"""SQLite 持久层：sessions / flows / pocs 三表（按计划 §2.5 严格定义）。

- sessions：原始会话（含 client/server 原始字节 BLOB 与归一化 parsed JSON）
- flows：同 src_ip 60s 滑动窗口聚合（端口扫描行为检测输入）
- pocs：生成的 nuclei 模板；normalized_req_hash UNIQUE 为去重键，
  status 默认 'unverified'，confidence 按规则演进

时间统一 UTC unix 毫秒。
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    ts_start     INTEGER NOT NULL,
    ts_end       INTEGER,
    src_ip       TEXT NOT NULL,
    src_port     INTEGER,
    dst_ip       TEXT,
    dst_port     INTEGER,
    transport    TEXT,
    proto        TEXT,
    banner       TEXT,
    client_bytes BLOB,
    server_bytes BLOB,
    parse_status TEXT,
    parsed_json  TEXT,
    close_reason TEXT,
    flow_id      TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_src ON sessions(src_ip, ts_start);
CREATE INDEX IF NOT EXISTS idx_sessions_proto ON sessions(proto, ts_start);

CREATE TABLE IF NOT EXISTS flows (
    flow_id    TEXT PRIMARY KEY,
    src_ip     TEXT NOT NULL,
    ts_start   INTEGER NOT NULL,
    ts_end     INTEGER,
    ports_hit  TEXT,
    conn_count INTEGER,
    tool_guess TEXT,
    tool_conf  REAL,
    behaviors  TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src_ip, ts_start);

CREATE TABLE IF NOT EXISTS pocs (
    poc_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    template_path       TEXT,
    template_yaml       TEXT,
    normalized_req_hash TEXT NOT NULL UNIQUE,
    proto               TEXT,
    type                TEXT,
    src_ips             TEXT,
    hit_count           INTEGER DEFAULT 1,
    status              TEXT DEFAULT 'unverified',
    confidence          REAL,
    first_seen          INTEGER,
    last_seen           INTEGER,
    source_session_ids  TEXT
);

-- 扫描事件（版本控制）：同一 (src_ip, tool_guess) 的空闲间隔分割事件，
-- 相邻事件 diff 出新增/移除的 POC（对方扫描器升级检测）
CREATE TABLE IF NOT EXISTS scans (
    scan_id      TEXT PRIMARY KEY,
    src_ip       TEXT NOT NULL,
    tool_guess   TEXT,
    ts_start     INTEGER NOT NULL,
    ts_end       INTEGER,
    conn_count   INTEGER,
    session_ids  TEXT,                 -- JSON
    poc_ids      TEXT,                 -- JSON（本次捕获的模板文件名）
    new_pocs     TEXT,                 -- JSON（相对上一事件新增）
    removed_pocs TEXT,                 -- JSON（相对上一事件移除）
    poc_count    INTEGER,
    new_count    INTEGER,
    removed_count INTEGER,
    ports_hit    TEXT,                 -- JSON（本次事件扫过的端口列表）
    web_probe_json TEXT,               -- JSON（扫描闭合时预计算的网站探测思路，请求时不重算）
    chains_json    TEXT                -- JSON（扫描闭合时预计算的利用链）
);
CREATE INDEX IF NOT EXISTS idx_scans_src ON scans(src_ip, ts_start);

-- 事件 × 端口明细：该事件对每个端口探测了什么（服务/会话数/攻击标记/探测样例）
CREATE TABLE IF NOT EXISTS scan_ports (
    scan_id     TEXT NOT NULL,
    dst_port    INTEGER NOT NULL,
    proto       TEXT,
    banner      TEXT,
    conn_count  INTEGER,
    attacks     TEXT,                  -- JSON：攻击意图标记列表
    sample      TEXT,                  -- JSON：探测内容样例
    PRIMARY KEY (scan_id, dst_port)
);

-- 版本快照（每次扫描事件闭合记一条：扫一次记一个版本）
CREATE TABLE IF NOT EXISTS lib_snapshots (
    snap_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,
    poc_count INTEGER NOT NULL,
    lib_hash  TEXT NOT NULL,
    scan_id   TEXT,                  -- 触发快照的扫描事件（与 scans.scan_id 对应）
    src_ip    TEXT,
    tool      TEXT
);
"""


def data_root() -> Path:
    """仓库根目录（可被 EATALL_HOME 环境变量覆盖，测试用）。"""
    env = os.environ.get("EATALL_HOME")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent


def sessions_dir() -> Path:
    return data_root() / "data" / "sessions"


def logs_dir() -> Path:
    return data_root() / "data" / "logs"


def state_path() -> Path:
    return data_root() / "data" / ".ingest_state.json"


def db_path() -> Path:
    return data_root() / "data" / "eatall.db"


def templates_dir() -> Path:
    return data_root() / "out" / "templates"


class DB:
    """SQLite 连接封装。单进程内使用（ingest 单线程）。"""

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        with self.conn:
            self.conn.executescript(_SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """存量库列迁移（CREATE IF NOT EXISTS 不会给已有表加列）。"""
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(scans)")}
        if "ports_hit" not in cols:
            self.conn.execute("ALTER TABLE scans ADD COLUMN ports_hit TEXT")
        for col in ("web_probe_json", "chains_json"):
            if col not in cols:
                self.conn.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT")
        snap_cols = {r[1] for r in self.conn.execute("PRAGMA table_info(lib_snapshots)")}
        for col in ("scan_id", "src_ip", "tool"):
            if col not in snap_cols:
                self.conn.execute(f"ALTER TABLE lib_snapshots ADD COLUMN {col} TEXT")

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass

    # ---------- sessions ----------

    def insert_session(
        self,
        *,
        session_id: str,
        ts_start: int,
        ts_end: Optional[int],
        src_ip: str,
        src_port: Optional[int],
        dst_ip: Optional[str],
        dst_port: Optional[int],
        transport: str,
        proto: str,
        banner: str,
        client_bytes: bytes,
        server_bytes: bytes,
        parse_status: str,
        parsed_json: str,
        close_reason: str,
        flow_id: str,
    ) -> bool:
        """插入会话；session_id 冲突（重复 ingest）时忽略，返回是否新插入。

        显式 commit：Python sqlite3 默认延迟事务，不 commit 的话连接关闭即
        回滚——断点续传的崩溃安全前提是已入库数据真正落盘。
        """
        with self.conn:
            cur = self.conn.execute(
                """INSERT OR IGNORE INTO sessions
                   (session_id, ts_start, ts_end, src_ip, src_port, dst_ip, dst_port,
                    transport, proto, banner, client_bytes, server_bytes, parse_status,
                    parsed_json, close_reason, flow_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (session_id, ts_start, ts_end, src_ip, src_port, dst_ip, dst_port,
                 transport, proto, banner, client_bytes, server_bytes, parse_status,
                 parsed_json, close_reason, flow_id),
            )
            return cur.rowcount > 0

    def get_sessions(
        self,
        proto: Optional[str] = None,
        since_rowid: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> list[sqlite3.Row]:
        """查询会话。since_rowid 为增量构建水位（入库顺序，非 ts_start——
        代理按完成序落盘，ts_start 可能乱序，时间水位会漏处理迟完成的会话）。
        rowid 是 SQLite 隐式自增列（session_id 为 TEXT 主键，rowid 仍然存在）。"""
        sql = "SELECT sessions.*, sessions.rowid AS rowid FROM sessions"
        conds, args = [], []
        if proto:
            conds.append("proto = ?")
            args.append(proto)
        if since_rowid is not None:
            conds.append("rowid > ?")
            args.append(since_rowid)
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += " ORDER BY rowid"
        if limit:
            sql += f" LIMIT {int(limit)}"
        return self.conn.execute(sql, args).fetchall()

    def session_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

    # ---------- flows ----------

    def insert_flow(
        self,
        *,
        flow_id: str,
        src_ip: str,
        ts_start: int,
        ts_end: int,
        ports_hit: list,
        conn_count: int,
        tool_guess: Optional[str],
        tool_conf: Optional[float],
        behaviors: list,
    ) -> bool:
        with self.conn:
            cur = self.conn.execute(
                """INSERT OR IGNORE INTO flows
                   (flow_id, src_ip, ts_start, ts_end, ports_hit, conn_count,
                    tool_guess, tool_conf, behaviors)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (flow_id, src_ip, ts_start, ts_end, json.dumps(ports_hit),
                 conn_count, tool_guess, tool_conf, json.dumps(behaviors)),
            )
            return cur.rowcount > 0

    def flow_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]

    # ---------- pocs ----------

    def upsert_poc(
        self,
        *,
        normalized_req_hash: str,
        proto: str,
        ptype: str,
        src_ip: str,
        first_seen: int,
        last_seen: int,
        source_session_id: str,
        template_path: Optional[str] = None,
        template_yaml: Optional[str] = None,
        confidence: float = 0.4,
        src_ips: Optional[list] = None,
        source_session_ids: Optional[list] = None,
    ) -> tuple[str, sqlite3.Row]:
        """pocs 去重键 upsert。

        新键 → 插入（'inserted'）；已存在 → hit_count+1、追加 src_ip、
        confidence+0.1（封顶 1.0），不重建模板文件（'updated'）。
        """
        row = self.conn.execute(
            "SELECT * FROM pocs WHERE normalized_req_hash = ?", (normalized_req_hash,)
        ).fetchone()
        if row is None:
            ips = list(dict.fromkeys((src_ips or []) + [src_ip]))
            sids = list(dict.fromkeys((source_session_ids or []) + [source_session_id]))[:256]
            with self.conn:
                self.conn.execute(
                    """INSERT INTO pocs (template_path, template_yaml, normalized_req_hash,
                       proto, type, src_ips, hit_count, status, confidence,
                       first_seen, last_seen, source_session_ids)
                       VALUES (?,?,?,?,?,?,1,'unverified',?,?,?,?)""",
                    (template_path, template_yaml, normalized_req_hash, proto, ptype,
                     json.dumps(ips), confidence, first_seen, last_seen, json.dumps(sids)),
                )
            row = self.conn.execute(
                "SELECT * FROM pocs WHERE normalized_req_hash = ?", (normalized_req_hash,)
            ).fetchone()
            return "inserted", row

        # 已存在：命中次数 +1，confidence +0.1（封顶 1.0），追加 src_ip / session
        new_conf = min(1.0, round((row["confidence"] or 0.4) + 0.1, 3))
        ips = list(dict.fromkeys((json.loads(row["src_ips"] or "[]")) + [src_ip]))
        sids = list(
            dict.fromkeys((json.loads(row["source_session_ids"] or "[]")) + [source_session_id])
        )[:256]
        path = row["template_path"]
        yaml_text = row["template_yaml"]
        # 模板文件丢失 → 允许重建（由调用方在返回 'updated' 后重发文件）
        with self.conn:
            self.conn.execute(
                """UPDATE pocs SET hit_count = hit_count + 1, confidence = ?,
                   src_ips = ?, last_seen = ?, source_session_ids = ?,
                   template_path = ?, template_yaml = ?
                   WHERE normalized_req_hash = ?""",
                (new_conf, json.dumps(ips), last_seen, json.dumps(sids),
                 path, yaml_text, normalized_req_hash),
            )
        row = self.conn.execute(
            "SELECT * FROM pocs WHERE normalized_req_hash = ?", (normalized_req_hash,)
        ).fetchone()
        return "updated", row

    def get_poc_by_hash(self, normalized_req_hash: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM pocs WHERE normalized_req_hash = ?", (normalized_req_hash,)
        ).fetchone()

    def get_pocs(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM pocs ORDER BY poc_id").fetchall()

    def poc_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM pocs").fetchone()[0]

    def list_pocs_full(
        self,
        *,
        search: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        ptype: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[sqlite3.Row]:
        """POC 库查询（dashboard 用）。severity/status 从 template_yaml 的 info 段解析，
        由调用方（scans 模块）建立索引；此处仅做 SQL 层过滤。"""
        sql = "SELECT * FROM pocs"
        conds, args = [], []
        if ptype:
            conds.append("type = ?")
            args.append(ptype)
        if search:
            conds.append("(template_path LIKE ? OR template_yaml LIKE ?)")
            args += [f"%{search}%", f"%{search}%"]
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        args += [int(limit), int(offset)]
        return self.conn.execute(sql, args).fetchall()

    # ---------- dashboard 只读查询 ----------

    def list_sessions(
        self,
        *,
        src: Optional[str] = None,
        proto: Optional[str] = None,
        kw: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        after_ts: Optional[int] = None,
    ) -> list[sqlite3.Row]:
        sql = "SELECT session_id, ts_start, ts_end, src_ip, src_port, dst_ip, dst_port," \
              " transport, proto, banner, client_len, server_len, parse_status, close_reason" \
              " FROM (SELECT *, length(client_bytes) AS client_len, length(server_bytes) AS server_len FROM sessions)"
        conds, args = [], []
        if src:
            conds.append("src_ip = ?")
            args.append(src)
        if proto:
            conds.append("proto = ?")
            args.append(proto)
        if kw:
            like = f"%{kw}%"
            conds.append("(banner LIKE ? OR parsed_json LIKE ?)")
            args += [like, like]
        if after_ts is not None:
            conds.append("ts_start >= ?")
            args.append(after_ts)
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += " ORDER BY ts_start DESC LIMIT ? OFFSET ?"
        args += [int(limit), int(offset)]
        return self.conn.execute(sql, args).fetchall()

    def session_count_filtered(
        self, src: Optional[str] = None, proto: Optional[str] = None, kw: Optional[str] = None
    ) -> int:
        sql = "SELECT COUNT(*) FROM sessions"
        conds, args = [], []
        if src:
            conds.append("src_ip = ?")
            args.append(src)
        if proto:
            conds.append("proto = ?")
            args.append(proto)
        if kw:
            like = f"%{kw}%"
            conds.append("(banner LIKE ? OR parsed_json LIKE ?)")
            args += [like, like]
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        return self.conn.execute(sql, args).fetchone()[0]

    def get_session_by_id(self, session_id: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()

    def list_flows(self, limit: int = 200) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM flows ORDER BY ts_start DESC LIMIT ?", (int(limit),)
        ).fetchall()

    def protocol_distribution(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT proto, COUNT(*) AS n FROM sessions GROUP BY proto ORDER BY n DESC"
        ).fetchall()

    def top_srcs(self, limit: int = 10) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT src_ip, COUNT(*) AS n FROM sessions GROUP BY src_ip ORDER BY n DESC LIMIT ?",
            (int(limit),),
        ).fetchall()

    def sessions_since(self, ts: int) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE ts_start >= ?", (ts,)
        ).fetchone()[0]

    # ---------- scans（版本控制） ----------

    def upsert_scan(self, *, scan: dict) -> None:
        """按 scan_id 幂等 upsert 扫描事件。"""
        with self.conn:
            self.conn.execute(
                """INSERT INTO scans (scan_id, src_ip, tool_guess, ts_start, ts_end,
                   conn_count, session_ids, poc_ids, new_pocs, removed_pocs,
                   poc_count, new_count, removed_count, ports_hit)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(scan_id) DO UPDATE SET
                     ts_end = excluded.ts_end,
                     conn_count = excluded.conn_count,
                     session_ids = excluded.session_ids,
                     poc_ids = excluded.poc_ids,
                     new_pocs = excluded.new_pocs,
                     removed_pocs = excluded.removed_pocs,
                     poc_count = excluded.poc_count,
                     new_count = excluded.new_count,
                     removed_count = excluded.removed_count,
                     ports_hit = excluded.ports_hit""",
                (scan["scan_id"], scan["src_ip"], scan.get("tool_guess"),
                 scan["ts_start"], scan.get("ts_end"),
                 scan.get("conn_count", 0), json.dumps(scan.get("session_ids", [])),
                 json.dumps(scan.get("poc_ids", [])),
                 json.dumps(scan.get("new_pocs", [])),
                 json.dumps(scan.get("removed_pocs", [])),
                 scan.get("poc_count", 0), scan.get("new_count", 0),
                 scan.get("removed_count", 0), json.dumps(scan.get("ports_hit", []))),
            )

    def update_scan_analysis(self, *, scan_id: str, web_probe_json: Optional[str],
                             chains_json: Optional[str]) -> None:
        """写入扫描闭合时预计算的网站探测思路/利用链（详情请求不再重算）。"""
        with self.conn:
            self.conn.execute(
                "UPDATE scans SET web_probe_json = ?, chains_json = ? WHERE scan_id = ?",
                (web_probe_json, chains_json, scan_id),
            )

    def upsert_scan_port(self, *, scan_id: str, dst_port: int, proto: str,
                         banner: str, conn_count: int, attacks: list,
                         sample: dict) -> None:
        """事件 × 端口明细，幂等 upsert。"""
        with self.conn:
            self.conn.execute(
                """INSERT INTO scan_ports (scan_id, dst_port, proto, banner,
                   conn_count, attacks, sample)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(scan_id, dst_port) DO UPDATE SET
                     proto = excluded.proto,
                     banner = excluded.banner,
                     conn_count = excluded.conn_count,
                     attacks = excluded.attacks,
                     sample = excluded.sample""",
                (scan_id, dst_port, proto, banner, conn_count,
                 json.dumps(attacks), json.dumps(sample)),
            )

    def get_scan_ports(self, scan_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM scan_ports WHERE scan_id = ? ORDER BY dst_port",
            (scan_id,),
        ).fetchall()

    def list_scans(self, limit: int = 100) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM scans ORDER BY ts_start DESC LIMIT ?", (int(limit),)
        ).fetchall()

    def get_scan(self, scan_id: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()

    def list_scans_for_src(self, src_ip: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM scans WHERE src_ip = ? ORDER BY ts_start", (src_ip,)
        ).fetchall()

    # ---------- lib 快照 ----------

    def upsert_lib_snapshot(
        self, *, ts: int, poc_count: int, lib_hash: str,
        scan_id: Optional[str] = None, src_ip: Optional[str] = None,
        tool: Optional[str] = None,
    ) -> int:
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO lib_snapshots (ts, poc_count, lib_hash, scan_id, src_ip, tool)"
                " VALUES (?,?,?,?,?,?)",
                (ts, poc_count, lib_hash, scan_id, src_ip, tool),
            )
            return int(cur.lastrowid)

    def list_lib_snapshots(self, limit: int = 100) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM lib_snapshots ORDER BY ts DESC LIMIT ?", (int(limit),)
        ).fetchall()

    def latest_lib_snapshot(self) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM lib_snapshots ORDER BY ts DESC LIMIT 1"
        ).fetchone()
