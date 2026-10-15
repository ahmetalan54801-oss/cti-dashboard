#!/usr/bin/env python3
"""
CTI Dashboard - Otonom Siber Tehdit İstihbaratı Toplayıcısı
Kaynaklar: CISA KEV, abuse.ch URLhaus, abuse.ch ThreatFox
Veriyi çeker, normalize eder, SQLite'a yazar.
"""
import json
import sqlite3
import urllib.request
import ssl
import sys
from datetime import datetime, timezone

import os
from pathlib import Path as _Path
DB_PATH = os.environ.get("CTI_DB_PATH", str(_Path(__file__).resolve().parent / "cti.db"))

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/json_recent/"
THREATFOX_URL = "https://threatfox.abuse.ch/export/json/recent/"

HEADERS = {"User-Agent": "Mozilla/5.0 (CTI-Dashboard/1.0; +local)"}


def fetch_json(url, timeout=60):
    req = urllib.request.Request(url, headers=HEADERS)
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def init_db(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS kev (
            cve_id TEXT PRIMARY KEY,
            vendor TEXT,
            product TEXT,
            vuln_name TEXT,
            date_added TEXT,
            due_date TEXT,
            ransomware TEXT,
            short_desc TEXT
        );
        CREATE TABLE IF NOT EXISTS urlhaus (
            id TEXT PRIMARY KEY,
            date_added TEXT,
            url TEXT,
            url_status TEXT,
            threat TEXT,
            tags TEXT,
            reporter TEXT
        );
        CREATE TABLE IF NOT EXISTS threatfox (
            id TEXT PRIMARY KEY,
            ioc_value TEXT,
            ioc_type TEXT,
            threat_type TEXT,
            malware TEXT,
            first_seen TEXT,
            last_seen TEXT,
            confidence INTEGER,
            tags TEXT,
            reporter TEXT
        );
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        """
    )
    conn.commit()


def ingest_kev(conn):
    data = fetch_json(KEV_URL)
    vulns = data.get("vulnerabilities", [])
    rows = [
        (
            v.get("cveID"),
            v.get("vendorProject"),
            v.get("product"),
            v.get("vulnerabilityName"),
            v.get("dateAdded"),
            v.get("dueDate"),
            v.get("knownRansomwareCampaignUse"),
            v.get("shortDescription"),
        )
        for v in vulns
    ]
    conn.executemany(
        "INSERT OR REPLACE INTO kev VALUES (?,?,?,?,?,?,?,?)", rows
    )
    conn.commit()
    return len(rows)


def ingest_urlhaus(conn):
    data = fetch_json(URLHAUS_URL)
    rows = []
    for _id, entries in data.items():
        for e in entries:
            rows.append(
                (
                    str(_id),
                    e.get("dateadded"),
                    e.get("url"),
                    e.get("url_status"),
                    e.get("threat"),
                    ",".join(e.get("tags") or []),
                    e.get("reporter"),
                )
            )
    conn.executemany(
        "INSERT OR REPLACE INTO urlhaus VALUES (?,?,?,?,?,?,?)", rows
    )
    conn.commit()
    return len(rows)


def ingest_threatfox(conn):
    data = fetch_json(THREATFOX_URL)
    rows = []
    for _id, entries in data.items():
        for e in entries:
            rows.append(
                (
                    str(_id),
                    e.get("ioc_value"),
                    e.get("ioc_type"),
                    e.get("threat_type"),
                    e.get("malware_printable") or e.get("malware"),
                    e.get("first_seen_utc"),
                    e.get("last_seen_utc"),
                    e.get("confidence_level"),
                    e.get("tags") if isinstance(e.get("tags"), str) else ",".join(e.get("tags") or []),
                    e.get("reporter"),
                )
            )
    conn.executemany(
        "INSERT OR REPLACE INTO threatfox VALUES (?,?,?,?,?,?,?,?,?,?)", rows
    )
    conn.commit()
    return len(rows)


def prune(conn):
    # DB şişmesin diye: urlhaus/threatfox'ta 30 günden eski kayıtları temizle
    conn.execute(
        "DELETE FROM urlhaus WHERE date_added < datetime('now', '-30 days')"
    )
    conn.execute(
        "DELETE FROM threatfox WHERE first_seen < datetime('now', '-30 days')"
    )
    conn.commit()


def main():
    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    summary = {}
    errors = []
    now = datetime.now(timezone.utc).isoformat()

    for name, fn in (
        ("kev", ingest_kev),
        ("urlhaus", ingest_urlhaus),
        ("threatfox", ingest_threatfox),
    ):
        try:
            n = fn(conn)
            summary[name] = n
            print(f"{name}: {n} kayıt işlendi", file=sys.stderr)
        except Exception as e:
            errors.append(f"{name}: {e}")
            print(f"{name} HATA: {e}", file=sys.stderr)

    prune(conn)

    conn.execute(
        "INSERT OR REPLACE INTO meta VALUES ('last_update', ?)", (now,)
    )
    conn.execute(
        "INSERT OR REPLACE INTO meta VALUES ('last_summary', ?)",
        (json.dumps(summary, ensure_ascii=False),),
    )
    if errors:
        conn.execute(
            "INSERT OR REPLACE INTO meta VALUES ('last_errors', ?)",
            (json.dumps(errors, ensure_ascii=False),),
        )
    else:
        conn.execute("DELETE FROM meta WHERE key='last_errors'")
    conn.commit()
    conn.close()
    print(f"Güncelleme tamamlandı: {summary}", file=sys.stderr)


if __name__ == "__main__":
    main()
