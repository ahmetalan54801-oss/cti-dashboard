#!/usr/bin/env python3
"""
CTI Dashboard - API + statik dosya servisi (stdlib, bağımlılık yok)
"""
import json
import os
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.environ.get("CTI_DB_PATH", str(BASE_DIR / "cti.db"))
STATIC_DIR = Path(os.environ.get("CTI_STATIC_DIR", str(BASE_DIR / "static")))
PORT = int(os.environ.get("PORT", "8787"))


def q(conn, sql, params=()):
    cur = conn.execute(sql, params)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # sessiz log

    def _send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, content_type):
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            return self._send_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
        if path == "/app.js":
            return self._send_file(STATIC_DIR / "app.js", "application/javascript; charset=utf-8")

        if path == "/api/summary":
            conn = sqlite3.connect(DB_PATH)
            meta = dict(q(conn, "SELECT key,value FROM meta") and
                        [(r["key"], r["value"]) for r in q(conn, "SELECT key,value FROM meta")])
            counts = {
                "kev": q(conn, "SELECT COUNT(*) c FROM kev")[0]["c"],
                "urlhaus": q(conn, "SELECT COUNT(*) c FROM urlhaus")[0]["c"],
                "threatfox": q(conn, "SELECT COUNT(*) c FROM threatfox")[0]["c"],
            }
            ransomware_count = q(
                conn, "SELECT COUNT(*) c FROM kev WHERE ransomware='Known'"
            )[0]["c"]
            conn.close()
            return self._send_json(
                {
                    "last_update": meta.get("last_update"),
                    "last_errors": json.loads(meta.get("last_errors", "null") or "null"),
                    "counts": counts,
                    "ransomware_kev_count": ransomware_count,
                }
            )

        if path == "/api/kev":
            limit = int((params.get("limit") or ["50"])[0])
            search = (params.get("q") or [""])[0].strip()
            ransomware_only = (params.get("ransomware") or ["0"])[0] == "1"
            conn = sqlite3.connect(DB_PATH)
            sql = "SELECT * FROM kev WHERE 1=1"
            args = []
            if search:
                sql += " AND (vendor LIKE ? OR product LIKE ? OR vuln_name LIKE ? OR cve_id LIKE ?)"
                like = f"%{search}%"
                args += [like, like, like, like]
            if ransomware_only:
                sql += " AND ransomware='Known'"
            sql += " ORDER BY date_added DESC LIMIT ?"
            args.append(limit)
            rows = q(conn, sql, args)
            conn.close()
            return self._send_json({"rows": rows})

        if path == "/api/urlhaus":
            limit = int((params.get("limit") or ["50"])[0])
            search = (params.get("q") or [""])[0].strip()
            conn = sqlite3.connect(DB_PATH)
            sql = "SELECT * FROM urlhaus WHERE 1=1"
            args = []
            if search:
                sql += " AND (url LIKE ? OR threat LIKE ? OR tags LIKE ?)"
                like = f"%{search}%"
                args += [like, like, like]
            sql += " ORDER BY date_added DESC LIMIT ?"
            args.append(limit)
            rows = q(conn, sql, args)
            conn.close()
            return self._send_json({"rows": rows})

        if path == "/api/threatfox":
            limit = int((params.get("limit") or ["50"])[0])
            search = (params.get("q") or [""])[0].strip()
            conn = sqlite3.connect(DB_PATH)
            sql = "SELECT * FROM threatfox WHERE 1=1"
            args = []
            if search:
                sql += " AND (ioc_value LIKE ? OR malware LIKE ? OR threat_type LIKE ? OR tags LIKE ?)"
                like = f"%{search}%"
                args += [like, like, like, like]
            sql += " ORDER BY first_seen DESC LIMIT ?"
            args.append(limit)
            rows = q(conn, sql, args)
            conn.close()
            return self._send_json({"rows": rows})

        if path == "/api/malware_stats":
            conn = sqlite3.connect(DB_PATH)
            rows = q(
                conn,
                """SELECT malware, COUNT(*) c FROM threatfox
                   WHERE malware IS NOT NULL
                   GROUP BY malware ORDER BY c DESC LIMIT 10""",
            )
            conn.close()
            return self._send_json({"rows": rows})

        self.send_response(404)
        self.end_headers()


def main():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"CTI dashboard http://0.0.0.0:{PORT} adresinde çalışıyor")
    server.serve_forever()


if __name__ == "__main__":
    main()
