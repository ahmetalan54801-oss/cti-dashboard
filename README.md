# CTI Dashboard — Otonom Siber Tehdit İstihbaratı

Ücretsiz açık kaynak feed'lerden (CISA KEV, abuse.ch URLhaus, abuse.ch ThreatFox)
tehdit istihbaratı toplayıp SQLite'a yazan ve basit bir web dashboard'u üzerinden
sunan bağımsız bir uygulama. Bağımlılık yok (sadece Python stdlib).

## Bileşenler
- `collector.py` — feed'leri çekip `cti.db` SQLite veritabanına yazar.
- `server.py` — JSON API + statik dashboard'u `PORT` ortam değişkenindeki portta sunar (varsayılan 8787).
- `static/` — tek sayfalık HTML/JS dashboard.
- `worker.py` — Render gibi tek işlemli ücretsiz platformlarda server + saatlik collector döngüsünü aynı process içinde birlikte çalıştırır.

## Yerel çalıştırma
```
python3 collector.py   # ilk veri çekimi
python3 server.py      # http://localhost:8787
```

## Render.com deploy
`render.yaml` kullanılarak "Blueprint" olarak deploy edilebilir; `worker.py` başlatılır,
hem API/dashboard'u sunar hem de arka planda saatte bir collector'ı tetikler.
