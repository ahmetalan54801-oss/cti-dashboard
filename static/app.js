const API = "";

function esc(s) {
  if (s === null || s === undefined) return "";
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

async function fetchJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url} -> ${r.status}`);
  return r.json();
}

function setStatus(text, isErr) {
  const el = document.getElementById("status");
  el.textContent = text;
  el.className = isErr ? "err" : "";
}

async function loadSummary() {
  try {
    const s = await fetchJSON("/api/summary");
    const cards = document.getElementById("cards");
    cards.innerHTML = `
      <div class="card info"><div class="label">CISA KEV Kayıtları</div><div class="value">${s.counts.kev.toLocaleString("tr-TR")}</div></div>
      <div class="card danger"><div class="label">Ransomware İlişkili CVE</div><div class="value">${s.ransomware_kev_count.toLocaleString("tr-TR")}</div></div>
      <div class="card warn"><div class="label">ThreatFox IOC (30 gün)</div><div class="value">${s.counts.threatfox.toLocaleString("tr-TR")}</div></div>
      <div class="card ok"><div class="label">URLhaus URL (30 gün)</div><div class="value">${s.counts.urlhaus.toLocaleString("tr-TR")}</div></div>
    `;
    const t = s.last_update ? new Date(s.last_update).toLocaleString("tr-TR") : "bilinmiyor";
    if (s.last_errors) {
      setStatus(`Son güncelleme: ${t} — HATA: ${JSON.stringify(s.last_errors)}`, true);
    } else {
      setStatus(`Son güncelleme: ${t} — canlı`, false);
    }
  } catch (e) {
    setStatus("Özet verisi alınamadı: " + e.message, true);
  }
}

function ransomwareBadge(v) {
  if (v === "Known") return `<span class="badge red">Bilinen</span>`;
  return `<span class="badge gray">Bilinmiyor</span>`;
}

async function loadKev() {
  const q = document.getElementById("kev-search").value;
  const ransomware = document.getElementById("kev-ransomware").checked ? "1" : "0";
  const params = new URLSearchParams({ limit: "100", q, ransomware });
  const data = await fetchJSON(`/api/kev?${params}`);
  const body = document.getElementById("kev-body");
  body.innerHTML = data.rows.map(r => `
    <tr>
      <td class="mono"><a href="https://nvd.nist.gov/vuln/detail/${esc(r.cve_id)}" target="_blank">${esc(r.cve_id)}</a></td>
      <td>${esc(r.vendor)} / ${esc(r.product)}</td>
      <td>${esc(r.vuln_name)}</td>
      <td>${esc(r.date_added)}</td>
      <td>${esc(r.due_date)}</td>
      <td>${ransomwareBadge(r.ransomware)}</td>
    </tr>
  `).join("") || `<tr><td colspan="6">Kayıt yok</td></tr>`;
}

async function loadThreatfox() {
  const q = document.getElementById("tf-search").value;
  const params = new URLSearchParams({ limit: "100", q });
  const data = await fetchJSON(`/api/threatfox?${params}`);
  const body = document.getElementById("tf-body");
  body.innerHTML = data.rows.map(r => `
    <tr>
      <td class="mono">${esc(r.ioc_value)}</td>
      <td>${esc(r.ioc_type)}</td>
      <td>${esc(r.threat_type)}</td>
      <td>${esc(r.malware)}</td>
      <td>${esc(r.first_seen)}</td>
      <td><span class="badge green">${esc(r.confidence)}%</span></td>
    </tr>
  `).join("") || `<tr><td colspan="6">Kayıt yok</td></tr>`;
}

async function loadUrlhaus() {
  const q = document.getElementById("uh-search").value;
  const params = new URLSearchParams({ limit: "100", q });
  const data = await fetchJSON(`/api/urlhaus?${params}`);
  const body = document.getElementById("uh-body");
  body.innerHTML = data.rows.map(r => `
    <tr>
      <td class="mono">${esc(r.url)}</td>
      <td>${r.url_status === "online" ? '<span class="badge red">online</span>' : '<span class="badge gray">offline</span>'}</td>
      <td>${esc(r.threat)}</td>
      <td>${esc(r.tags)}</td>
      <td>${esc(r.date_added)}</td>
    </tr>
  `).join("") || `<tr><td colspan="5">Kayıt yok</td></tr>`;
}

function initTabs() {
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById(`panel-${tab.dataset.tab}`).classList.add("active");
    });
  });
}

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

function init() {
  initTabs();
  loadSummary();
  loadKev();
  loadThreatfox();
  loadUrlhaus();

  document.getElementById("kev-search").addEventListener("input", debounce(loadKev, 300));
  document.getElementById("kev-ransomware").addEventListener("change", loadKev);
  document.getElementById("tf-search").addEventListener("input", debounce(loadThreatfox, 300));
  document.getElementById("uh-search").addEventListener("input", debounce(loadUrlhaus, 300));

  setInterval(loadSummary, 60000);
}

init();
