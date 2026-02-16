# 🛡️ IP Security Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0-blue?style=for-the-badge&color=6366f1">
  <img src="https://img.shields.io/badge/platform-Cloudflare%20Workers-orange?style=for-the-badge">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge">
</p>

<p align="center">
  <b>IP Security Analyzer: A pro-grade Cloudflare Worker for forensic intelligence.</b><br>
  Detects VPNs, Proxies & Hosting IPs via heuristic ASN auditing.<br>
  Includes Security Scoring, WebRTC Leak Test, ISP classification, and Geo-location.<br>
  Built with a modern Bento UI and live terminal logs.<br>
  Powerful, open-source and real-time network forensic tool.
</p>

<p align="center">
  <a href="https://myip.theazizi.ir"><b>🚀 Live Demo</b></a> 
</p>

---

## ✨ Features

- 🔍 **Heuristic ASN Auditing** — Detects VPNs, Proxies, Hosting providers via ISP pattern analysis
- 🛡️ **Security Scoring** — Dynamic 0-100 trust score based on infrastructure risk
- 🔌 **WebRTC Leak Test** — Real-time detection of IP leaks via browser STUN probing
- 🏷️ **ISP Classification** — Categorizes connections (Mobile, Hosting, Educational, Corporate, Residential)
- 🌍 **Geo-Location** — Country, city, region, coordinates from Cloudflare edge data
- 🖥️ **Modern Bento UI** — Glass-morphism dashboard with responsive grid layout
- 📜 **Live Terminal Logs** — Real-time forensic logging with animated timestamps
- ⚡ **Edge Performance** — Sub-100ms response via Cloudflare's global network
- 🔌 **JSON API** — RESTful `/json` endpoint for programmatic access
- 📋 **One-Click Copy** — Copy IP address to clipboard instantly

---

## 🚀 Deployment

### Prerequisites
- Cloudflare account (Free tier works)
- Wrangler CLI: `npm install -g wrangler`

### Method 1: Wrangler CLI (Recommended)

```bash
# 1. Login
npx wrangler login

# 2. Create worker
npx wrangler init ip-security-analyzer

# 3. Paste code into src/index.js

# 4. Deploy
npx wrangler deploy
```

Your URL: `https://ip-security-analyzer.YOUR_SUBDOMAIN.workers.dev`

### Method 2: Cloudflare Dashboard

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/) → Workers & Pages
2. Click "Create Application" → "Create Worker"
3. Name it `ip-security-analyzer`
4. Click "Edit Code", paste the code, "Save and Deploy"

---

## 🌐 Custom Domain Setup

### Step 1: Add Domain to Cloudflare
- Add your domain to Cloudflare
- Update nameservers

### Step 2: Create DNS Record
```
Type: CNAME
Name: myip
Target: your-worker.YOUR_SUBDOMAIN.workers.dev
Proxy: Orange cloud (Proxied)
```

### Step 3: Add Route
**Via Wrangler:**
```bash
npx wrangler route add "myip.yourdomain.com/*" ip-security-analyzer
```

**Via Dashboard:**
1. Workers & Pages → Your Worker → Settings → Triggers
2. Click "Add Custom Domain"
3. Enter: `myip.yourdomain.com`

### Step 4: Verify
Visit: `https://myip.yourdomain.com`

---

## 📡 API

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | HTML Dashboard |
| `/json` | JSON Metadata |

### JSON Response

```json
{
  "status": "success",
  "metadata": {
    "ip": "203.0.113.42",
    "type": "IPv4",
    "asn": "15169",
    "isp": "Google LLC",
    "connectionType": "Hosting / Proxy",
    "country": "US",
    "city": "Mountain View",
    "region": "California",
    "lat": "37.3860",
    "lon": "-122.0838",
    "colo": "SJC",
    "timezone": "America/Los_Angeles",
    "tlsVersion": "TLSv1.3",
    "httpProtocol": "HTTP/2",
    "rayId": "8f7e6d5c4b3a2190"
  }
}
```

### Usage Examples

**cURL:**
```bash
curl https://myip.theazizi.ir/json
```

**JavaScript:**
```javascript
const res = await fetch('https://myip.theazizi.ir/json');
const data = await res.json();
console.log(data.metadata.ip);
```

**Python:**
```python
import requests
print(requests.get('https://myip.theazizi.ir/json').json())
```

---

## 🔐 Security Analysis

### Detection Categories

| Type | Patterns |
|------|----------|
| 📱 Mobile | Vodafone, Verizon, T-Mobile, LTE, 5G |
| ☁️ Hosting/Proxy | AWS, GCP, Azure, DigitalOcean, Hetzner, VPN |
| 🎓 Educational | University, .edu, Research networks |
| 🏢 Corporate | Enterprise, Business ASN ranges |
| 🏠 Residential | Standard consumer ISPs (default) |

### Scoring Algorithm

| Risk Factor | Deduction |
|-------------|-----------|
| Hosting/VPN detected | -45 pts |
| Mobile network | -10 pts |
| Bot signature | -30 pts |
| Timezone mismatch | -20 pts |
| WebRTC leak | -15 pts |

**Score Ranges:**
- 🟢 80-100: Trusted
- 🟡 50-79: Limited Trust
- 🔴 0-49: High Risk

---

## ⚙️ Configuration

### Environment Variables

```bash
npx wrangler secret put API_KEY
```

Access in code:
```javascript
const apiKey = env.API_KEY;
```

### wrangler.toml

```toml
name = "ip-security-analyzer"
main = "src/index.js"
compatibility_date = "2026-02-14"

[[routes]]
pattern = "myip.yourdomain.com"
custom_domain = true
```

---

## 🛠️ Development

```bash
# Local dev server
npx wrangler dev

# View logs
npx wrangler tail
```

---

## 📊 Performance

- **Latency:** Sub-100ms globally
- **Cold Start:** Near-zero (Cloudflare 2025 optimization)
- **Requests:** 100K/day (Free tier)

---

## 📝 License

MIT License — Free to use, modify, and deploy.

---

## 👤 Author

**TheGreatAzizi**

- X: [@the_azzi](https://x.com/the_azzi)
- GitHub: [@TheGreatAzizi](https://github.com/TheGreatAzizi)
- Demo: [myip.theazizi.ir](https://myip.theazizi.ir)

---

<p align="center">
  <sub>Built with ❤️</sub>
</p>
