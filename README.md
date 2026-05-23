# 🛡️ IP Security Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/platform-Cloudflare%20Workers-f38020?style=for-the-badge">
  <img src="https://img.shields.io/badge/IPinfo-Lite-2563eb?style=for-the-badge">
  <img src="https://img.shields.io/badge/AbuseIPDB-Reputation-ef4444?style=for-the-badge">
  <img src="https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge">
</p>

<p align="center">
  <b>A lightweight Cloudflare Worker dashboard for IP intelligence, reputation analysis, and browser-side WebRTC exposure testing.</b>
</p>

<p align="center">
  <a href="#فارسی"><b> نسخه فارسی پایین همین فایل قرار دارد</b></a>
</p>

<p align="center">
  <a href="https://myip.theazizi.ir"><b>🚀 Live Demo</b></a>
  ·
  <a href="https://github.com/TheGreatAzizi/IP-Security-Analyzer-Cloudflare-Worker"><b>GitHub Repository</b></a>
  ·
  <a href="https://x.com/the_azzi"><b>X / Twitter</b></a>
  ·
  <a href="https://t.me/luluch_code"><b>Telegram</b></a>
</p>

---

## Overview

**IP Security Analyzer** is a single-file Cloudflare Worker that analyzes the public network identity of a visitor. It combines Cloudflare request metadata, IPinfo Lite ASN enrichment, AbuseIPDB reputation data, request-header consistency checks, and a browser-side WebRTC leak test.

The project is designed to be transparent: it separates **network classification** from **risk scoring**. For example, a datacenter, CDN, cloud, or transit IP is shown as infrastructure, but it is **not penalized by default** unless stronger risk indicators exist, such as abuse reports, Tor status, suspicious automation headers, VPN/proxy naming signals, or WebRTC public IP mismatch.

This makes the project useful for:

- Personal IP/security dashboards
- VPN/proxy visibility testing
- Network identity inspection
- Abuse/reputation checks
- Browser WebRTC exposure testing
- Edge-based IP intelligence demos
- Lightweight forensic-style network analysis

---

## Key Features

### 🌐 Public IP and Network Identity

The Worker detects the public IP address visible to Cloudflare and displays:

- IP address
- IP version, IPv4 or IPv6
- ASN
- ISP / organization
- Country, region, city
- Cloudflare edge colo
- HTTP protocol
- TLS version
- Cloudflare Ray ID

### 🧠 ASN and Network Classification

The project classifies the visible network into categories such as:

- Hosting / Datacenter
- Mobile / Cellular
- Corporate / Business
- Education / Campus
- Likely Residential
- VPN / Proxy / Privacy name match
- Unknown

This classification is contextual. A hosting/datacenter classification alone does not reduce the security score.

### 🧩 IPinfo Lite Enrichment

IPinfo Lite is used to enrich the IP address with:

- ASN
- AS name
- AS domain
- Country
- Continent

IPinfo Lite does not provide direct `is_vpn`, `is_proxy`, `is_tor`, or `is_hosting` fields. Because of that, this project does not claim definitive VPN detection from IPinfo Lite alone. It uses Lite data as attribution and context.

### 🧯 AbuseIPDB Reputation Layer

AbuseIPDB adds reputation and abuse context, including:

- Abuse confidence score
- Total abuse reports
- Number of distinct reporting users
- Tor status
- Usage type
- ISP
- Domain
- Hostnames
- Last reported time

The score is affected by abuse history and Tor status. A usage type like `Data Center/Web Hosting/Transit` is displayed as network context only and does not reduce the score by itself.

### 🕵️ Request Consistency Checks

The Worker checks request headers and Cloudflare signals for suspicious or inconsistent patterns:

- Missing User-Agent
- Automation clients such as `curl`, `wget`, `python`, `requests`, Selenium, Playwright, Puppeteer
- Browser-like User-Agent without modern browser headers
- Missing `Accept-Language`
- Non-TLS 1.3 connection
- Optional Cloudflare Bot Management score, if available

### 🔌 WebRTC Exposure Test

The dashboard includes a browser-side WebRTC test. It creates a temporary `RTCPeerConnection`, gathers ICE candidates, and sends them to the Worker through `/report`.

The WebRTC test can detect:

- Public IP candidates exposed by the browser
- Public IP mismatch between WebRTC and HTTP
- Private/local candidate exposure
- mDNS-masked local candidates
- Cases where WebRTC is blocked or protected

If WebRTC exposes a public IP that differs from the HTTP IP seen by Cloudflare, the dashboard marks it as a possible browser-side exposure or VPN/proxy bypass signal.

### 📊 Transparent Risk Score

The score starts at `100`.

The score decreases only for stronger signals such as:

| Signal | Effect |
|---|---:|
| Tor flag from AbuseIPDB | High penalty |
| High AbuseIPDB confidence score | High penalty |
| Abuse reports | Low to high penalty depending on report count |
| VPN/proxy/privacy keyword match | Penalty |
| Suspicious automation User-Agent | Penalty |
| Low Cloudflare Bot Management score | Penalty |
| WebRTC public IP mismatch | Penalty |
| WebRTC local/private exposure | Small penalty |

The score does **not** decrease simply because the IP belongs to hosting, datacenter, cloud, CDN, or transit infrastructure.

---

## Scoring Philosophy

This project intentionally avoids treating infrastructure as automatically malicious.

A clean datacenter IP with:

- Abuse score `0`
- No abuse reports
- Not Tor
- No WebRTC mismatch
- No suspicious headers

should remain low risk.

A residential-looking IP can still become risky if it has:

- Abuse history
- Tor status
- Automation indicators
- VPN/proxy naming patterns
- WebRTC mismatch
- Suspicious request consistency signals

The goal is not to guess hidden private data. The goal is to evaluate observable evidence.

---

## Endpoints

| Endpoint | Method | Description |
|---|---:|---|
| `/` | `GET` | HTML dashboard |
| `/json` | `GET` | Full server-side analysis as JSON |
| `/api` | `GET` | Alias for `/json` |
| `/report` | `POST` | Receives browser WebRTC candidate report and returns combined risk |
| `/health` | `GET` | Basic status and version endpoint |

---

## Example JSON Structure

```json
{
  "status": "success",
  "ip": {
    "address": "203.0.113.42",
    "version": "IPv4"
  },
  "network": {
    "asn": 15169,
    "isp": "Google LLC",
    "localClassification": {
      "type": "Hosting / Datacenter",
      "flags": {
        "hostingName": true,
        "vpnProxyName": false,
        "abuseDatacenterUsage": true
      }
    }
  },
  "externalIntel": {
    "ipinfoLite": {
      "enabled": true,
      "ok": true
    },
    "abuseipdb": {
      "enabled": true,
      "ok": true
    }
  },
  "risk": {
    "score": 100,
    "verdict": "Low Risk",
    "tags": ["Hosting/Datacenter"],
    "findings": []
  }
}
```

---

## Deployment

### Option 1: Cloudflare Dashboard

1. Open Cloudflare Dashboard.
2. Go to **Workers & Pages**.
3. Create a new Worker.
4. Open **Edit Code**.
5. Paste the full Worker code.
6. Click **Save and Deploy**.

### Option 2: Wrangler CLI

```bash
npx wrangler init ip-security-analyzer
cd ip-security-analyzer
```

Paste the Worker code into:

```text
src/index.js
```

Deploy:

```bash
npx wrangler deploy
```

---

## Configuration

The Worker can run without external keys, but external intelligence is recommended.

### IPinfo Lite

Create a free IPinfo token and add it as:

```text
IPINFO_TOKEN
```

### AbuseIPDB

Create an AbuseIPDB API key and add it as:

```text
ABUSEIPDB_KEY
```

### Cloudflare Dashboard Secrets

In Cloudflare Dashboard:

```text
Worker → Settings → Variables and Secrets → Add
```

Add:

```text
IPINFO_TOKEN = your_ipinfo_token
ABUSEIPDB_KEY = your_abuseipdb_key
```

### Manual Fallback

If secrets are not available, fill these values at the top of the Worker file:

```javascript
const MANUAL_IPINFO_TOKEN = "";
const MANUAL_ABUSEIPDB_KEY = "";
```

Using Cloudflare secrets is safer for production.

---

## Custom Domain

You can attach a custom domain from the Cloudflare dashboard:

```text
Workers & Pages → Your Worker → Settings → Triggers → Add Custom Domain
```

Example:

```text
myip.example.com
```

---

## Technical Methodology

### 1. Server-Side IP Detection

The Worker reads the IP address visible to Cloudflare using headers such as:

- `CF-Connecting-IP`
- `True-Client-IP`
- `X-Real-IP`
- `X-Forwarded-For`

The primary source is Cloudflare's connecting IP header. This identifies the public IP that reached the Worker.

### 2. Cloudflare Metadata

Cloudflare Workers expose metadata through `request.cf`, including ASN, organization, country, city, region, colo, timezone, TLS version, and protocol data.

This data provides the base network identity.

### 3. External Enrichment

The Worker queries external APIs:

- **IPinfo Lite** for ASN and country enrichment
- **AbuseIPDB** for reputation, report count, Tor flag, usage type, and related abuse context

These sources are combined with Cloudflare metadata for better attribution.

### 4. Heuristic Classification

The Worker uses conservative keyword matching to classify network names and domains. For example:

- `cloud`, `hosting`, `datacenter`, `transit` → infrastructure context
- `vpn`, `proxy`, `tor`, `privacy`, `tunnel` → higher-risk naming context
- `mobile`, `lte`, `5g`, carrier names → mobile context
- known consumer ISPs → residential-like context

Infrastructure context does not automatically lower the score.

### 5. Risk Model

Risk is calculated from evidence, not assumptions. The Worker applies penalties for:

- Tor
- Abuse score
- Abuse reports
- VPN/proxy/privacy naming
- Automation signatures
- Header inconsistency
- Low bot score
- WebRTC mismatch

Informational findings are still shown, but have `points: 0`.

### 6. WebRTC Candidate Analysis

The browser creates a temporary `RTCPeerConnection` and collects ICE candidates.

The Worker compares:

- HTTP IP seen by Cloudflare
- Public IPs exposed by WebRTC
- Local/private candidates
- mDNS candidates

A different public WebRTC IP can indicate a browser-side leak or proxy/VPN bypass.

### 7. Known Limitations

This project cannot reliably reveal the original ISP IP behind a correctly configured VPN or proxy.

It also cannot perform real DNS leak detection by itself, because a normal Worker cannot observe the visitor's DNS resolver. Real DNS leak testing requires unique subdomains and authoritative DNS query logs.

---

## Security Notes

- Do not expose private API keys in public repositories.
- Prefer Cloudflare secrets over manual constants.
- Do not interpret hosting/datacenter as malicious by itself.
- Use findings and score together, not score alone.
- WebRTC results depend on browser settings and privacy protections.
- DNS leak detection requires a separate authoritative DNS logging system.

---

## Use Cases

- Checking whether a VPN or proxy exposes browser-side WebRTC candidates
- Inspecting ASN and network ownership
- Viewing public IP reputation
- Building a simple edge-based IP intelligence dashboard
- Demonstrating Cloudflare Worker request metadata
- Comparing HTTP-visible IP with WebRTC-visible IP
- Learning how infrastructure classification differs from abuse scoring

---

## Project Links

- Live Demo: [myip.theazizi.ir](https://myip.theazizi.ir)
- GitHub: [TheGreatAzizi/IP-Security-Analyzer-Cloudflare-Worker](https://github.com/TheGreatAzizi/IP-Security-Analyzer-Cloudflare-Worker)
- X / Twitter: [@the_azzi](https://x.com/the_azzi)
- Telegram: [luluch_code](https://t.me/luluch_code)

---

## License

MIT License — free to use, modify, and deploy.

---

## فارسی

<p align="center">
  <b>تحلیل‌گر امنیت IP</b><br>
  داشبوردی سبک بر پایه Cloudflare Worker برای تحلیل هویت شبکه، اعتبار IP، بررسی WebRTC و نمایش شفاف سیگنال‌های امنیتی.
</p>

---

## معرفی

**IP Security Analyzer** یک پروژه تک‌فایلی برای Cloudflare Worker است که IP عمومی و مسیر شبکه‌ای قابل مشاهده توسط سایت را تحلیل می‌کند.

این پروژه تلاش نمی‌کند اطلاعات مخفی یا غیرقابل مشاهده را حدس بزند. در عوض، داده‌های قابل مشاهده را بررسی و با هم ترکیب می‌کند:

- متادیتای Cloudflare
- اطلاعات ASN و کشور از IPinfo Lite
- اعتبار و سابقه سوءاستفاده از AbuseIPDB
- بررسی سازگاری هدرهای درخواست
- تست WebRTC در مرورگر

هدف پروژه این است که نشان دهد یک اتصال از نظر شواهد قابل مشاهده چقدر قابل اعتماد یا مشکوک است.

---

## ویژگی‌ها

### تشخیص IP و هویت شبکه

پروژه اطلاعات زیر را نمایش می‌دهد:

- IP عمومی
- IPv4 یا IPv6
- ASN
- نام ISP یا سازمان شبکه
- کشور، شهر و منطقه
- Cloudflare colo
- نسخه TLS
- پروتکل HTTP
- Ray ID

### دسته‌بندی شبکه

اتصال می‌تواند در دسته‌هایی مثل موارد زیر قرار بگیرد:

- دیتاسنتر / هاستینگ
- موبایل / سلولار
- سازمانی / شرکتی
- آموزشی
- شبیه Residential
- VPN / Proxy / Privacy name match
- ناشناخته

نکته مهم: **صرفاً دیتاسنتر یا هاستینگ بودن باعث کم شدن نمره نمی‌شود.**

---

## IPinfo Lite

IPinfo Lite اطلاعات پایه‌ای مثل موارد زیر را اضافه می‌کند:

- ASN
- نام AS
- دامنه AS
- کشور
- قاره

نسخه Lite فیلدهای مستقیم مثل `is_vpn`، `is_proxy`، `is_tor` یا `is_hosting` ندارد. بنابراین پروژه از IPinfo Lite فقط برای زمینه‌سازی و شناسایی بهتر شبکه استفاده می‌کند، نه برای ادعای قطعی VPN بودن.

---

## AbuseIPDB

AbuseIPDB اطلاعات اعتبار و سوءاستفاده IP را فراهم می‌کند:

- Abuse confidence score
- تعداد گزارش‌ها
- تعداد کاربران گزارش‌دهنده
- وضعیت Tor
- نوع استفاده شبکه
- ISP
- دامنه
- Hostnameها
- آخرین زمان گزارش

نمره ریسک فقط وقتی کم می‌شود که شواهد قوی‌تری وجود داشته باشد، مثل گزارش سوءاستفاده، امتیاز Abuse بالا یا Tor بودن.

اگر AbuseIPDB فقط بگوید IP از نوع `Data Center/Web Hosting/Transit` است، این مورد فقط به عنوان اطلاعات شبکه نمایش داده می‌شود و به تنهایی نمره کم نمی‌کند.

---

## مدل امتیازدهی

امتیاز از ۱۰۰ شروع می‌شود.

امتیاز فقط برای موارد معنادار کم می‌شود:

| سیگنال | اثر |
|---|---:|
| Tor بودن IP | جریمه زیاد |
| Abuse score بالا | جریمه زیاد |
| گزارش‌های AbuseIPDB | جریمه بسته به تعداد گزارش |
| کلمات مرتبط با VPN / Proxy / Privacy | جریمه |
| User-Agent مشکوک یا خودکار | جریمه |
| Bot score پایین در Cloudflare | جریمه |
| WebRTC public IP mismatch | جریمه |
| افشای IP محلی در WebRTC | جریمه کم |

موارد زیر به تنهایی جریمه ندارند:

- دیتاسنتر
- هاستینگ
- CDN
- Cloud
- Transit
- Mobile carrier

---

## WebRTC Leak Test

تست WebRTC در مرورگر اجرا می‌شود. مرورگر یک اتصال موقت `RTCPeerConnection` می‌سازد و ICE candidateها را جمع‌آوری می‌کند.

سپس Worker بررسی می‌کند:

- IP دیده‌شده توسط HTTP / Cloudflare چیست
- WebRTC چه IPهایی را نشان داده است
- آیا IP عمومی متفاوتی لو رفته است
- آیا IP خصوصی یا local دیده شده است
- آیا مرورگر از mDNS masking استفاده کرده است

اگر WebRTC یک IP عمومی متفاوت از IP دیده‌شده توسط Cloudflare نشان دهد، پروژه آن را به عنوان احتمال leak یا bypass تشخیص می‌دهد.

---

## محدودیت‌ها

این پروژه نمی‌تواند به طور قطعی IP اصلی پشت یک VPN یا Proxy درست پیکربندی‌شده را پیدا کند.

همچنین یک Cloudflare Worker معمولی نمی‌تواند DNS resolver کاربر را ببیند. برای DNS leak واقعی باید دامنه‌های تصادفی و لاگ authoritative DNS داشته باشید.

---

## Endpointها

| مسیر | متد | توضیح |
|---|---:|---|
| `/` | `GET` | داشبورد HTML |
| `/json` | `GET` | خروجی کامل JSON |
| `/api` | `GET` | معادل `/json` |
| `/report` | `POST` | دریافت گزارش WebRTC از مرورگر |
| `/health` | `GET` | وضعیت پایه سرویس |

---

## نصب و راه‌اندازی

### از طریق Cloudflare Dashboard

1. وارد Cloudflare Dashboard شوید.
2. به بخش **Workers & Pages** بروید.
3. یک Worker جدید بسازید.
4. وارد **Edit Code** شوید.
5. کد Worker را جایگذاری کنید.
6. روی **Save and Deploy** کلیک کنید.

### از طریق Wrangler

```bash
npx wrangler init ip-security-analyzer
cd ip-security-analyzer
```

کد را در فایل زیر قرار دهید:

```text
src/index.js
```

سپس Deploy کنید:

```bash
npx wrangler deploy
```

---

## تنظیم کلیدها

برای نتیجه بهتر، این دو کلید را در Cloudflare Worker Secrets قرار دهید:

```text
IPINFO_TOKEN
ABUSEIPDB_KEY
```

اگر به Secrets دسترسی ندارید، می‌توانید مقدارها را در ابتدای فایل Worker وارد کنید:

```javascript
const MANUAL_IPINFO_TOKEN = "";
const MANUAL_ABUSEIPDB_KEY = "";
```

برای محیط عمومی، استفاده از Secret امن‌تر است.

---

## کاربردها

- بررسی WebRTC leak هنگام استفاده از VPN
- مشاهده مالکیت ASN و شبکه
- بررسی reputation و گزارش‌های AbuseIPDB
- ساخت داشبورد IP intelligence روی Cloudflare Worker
- مقایسه IP قابل مشاهده از HTTP با IP قابل مشاهده از WebRTC
- آموزش تفاوت classification و risk scoring

---

## لینک‌ها

- دمو: [myip.theazizi.ir](https://myip.theazizi.ir)
- گیت‌هاب: [TheGreatAzizi/IP-Security-Analyzer-Cloudflare-Worker](https://github.com/TheGreatAzizi/IP-Security-Analyzer-Cloudflare-Worker)
- ایکس / توییتر: [@the_azzi](https://x.com/the_azzi)
- تلگرام: [luluch_code](https://t.me/luluch_code)

---

## لایسنس

MIT License — استفاده، تغییر و انتشار آزاد است.
