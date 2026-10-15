#!/usr/bin/env python3
"""
Render.com gibi tek işlem/tek port izin veren ücretsiz platformlar için:
collector'ı arka plan thread'inde saatlik çalıştırır, server'ı ana thread'de ayağa kaldırır.
"""
import subprocess
import sys
import threading
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
COLLECTOR = str(BASE_DIR / "collector.py")

INTERVAL_SECONDS = 60 * 60  # saatlik


def run_collector_loop():
    while True:
        try:
            print("[worker] collector çalıştırılıyor...", flush=True)
            subprocess.run([sys.executable, COLLECTOR], check=False)
        except Exception as e:
            print(f"[worker] collector hata: {e}", flush=True)
        time.sleep(INTERVAL_SECONDS)


def main():
    # İlk çalıştırmada veritabanı boşsa hemen bir kez doldur (bloklayıcı)
    subprocess.run([sys.executable, COLLECTOR], check=False)

    t = threading.Thread(target=run_collector_loop, daemon=True)
    t.start()

    import server
    server.main()


if __name__ == "__main__":
    main()
