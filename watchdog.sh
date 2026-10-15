#!/usr/bin/env bash
# CTI Dashboard watchdog: server.py ve cloudflared tünelini ayakta tutar.
# cron ile her dakika çalıştırılır; süreç yoksa başlatır.
set -euo pipefail

DIR="/home/ahmet/cti-dashboard"
SERVER_LOG="$DIR/server.log"
TUNNEL_LOG="$DIR/tunnel.log"
URL_FILE="$DIR/live_url.txt"

cd "$DIR"

# server.py ayakta mı?
if ! pgrep -f "python3 $DIR/server.py" >/dev/null 2>&1; then
    nohup python3 "$DIR/server.py" >> "$SERVER_LOG" 2>&1 &
    disown
    echo "$(date -Iseconds) server.py başlatıldı" >> "$DIR/watchdog.log"
fi

# cloudflared ayakta mı?
if ! pgrep -f "cloudflared tunnel --url http://localhost:8787" >/dev/null 2>&1; then
    : > "$TUNNEL_LOG"
    nohup /home/ahmet/bin/cloudflared tunnel --url http://localhost:8787 --logfile "$TUNNEL_LOG" >> "$DIR/cloudflared_stdout.log" 2>&1 &
    disown
    echo "$(date -Iseconds) cloudflared başlatıldı" >> "$DIR/watchdog.log"
    sleep 8
fi

# Güncel URL'yi dosyaya yaz (tünel yeniden başladıysa değişebilir)
NEW_URL=$(grep -o 'https://[a-zA-Z0-9.-]*\.trycloudflare\.com' "$TUNNEL_LOG" | tail -1 || true)
if [ -n "$NEW_URL" ]; then
    echo "$NEW_URL" > "$URL_FILE"
fi
